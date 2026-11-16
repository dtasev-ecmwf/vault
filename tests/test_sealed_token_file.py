# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The token file's sealed format, and the passphrase it is sealed with.

The passphrase is derived from the account, so the tests that matter most are the ones about
*which* facts it is derived from — the user database rather than the environment, and the
account's own uid and gid — because getting those wrong makes a file unreadable rather than
insecure, which is the sort of thing that only shows up on someone else's machine.

The format tests run gpg for real. It is on every host this package targets and a stub would
test the stub; what is checked is a round trip, that a sealed file is not mistakable for a
token, and that a file sealed by *another account* cannot be opened here.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import VaultError, VaultTokenFileError
from ecmwf_vault import _passphrase, _sealed_token_file as sealed

TOKEN = "hvs.synthetic-round-trip-token"


class DerivationTests(unittest.TestCase):
    """What the passphrase is built from."""

    def test_it_is_the_documented_shape(self):
        name = _passphrase.account_name()
        expected = "%s_%d" % ("$".join(name), os.getuid() * os.getgid())
        self.assertEqual(_passphrase.for_this_account(), expected)

    def test_a_dollar_between_every_character(self):
        # The one piece of the derivation that is a *look* rather than a fact, and the part a
        # reader of the README will check by hand.
        self.assertEqual(_passphrase.SEPARATOR, "$")
        with mock.patch.object(_passphrase, "account_name", return_value="madt"):
            with mock.patch.object(os, "getuid", return_value=4509):
                with mock.patch.object(os, "getgid", return_value=5000):
                    self.assertEqual(_passphrase.for_this_account(), "m$a$d$t_22545000")

    def test_the_name_comes_from_the_user_database_not_the_environment(self):
        # The whole reason this does not call getpass.getuser first: a passphrase that changed
        # with an exported variable would make the token file unreadable for no reason.
        with mock.patch.dict(os.environ, {"LOGNAME": "someone-else", "USER": "someone-else"}):
            self.assertEqual(_passphrase.account_name(), _passphrase.pwd.getpwuid(
                os.getuid()).pw_name)

    def test_a_uid_with_no_entry_falls_back_to_the_environment(self):
        # A container running as a random uid: the user database has nothing to say, and a
        # passphrase from the environment still works within one process tree.
        with mock.patch.object(_passphrase.pwd, "getpwuid", side_effect=KeyError):
            with mock.patch.object(_passphrase.getpass, "getuser", return_value="container"):
                self.assertEqual(_passphrase.account_name(), "container")

    def test_nothing_at_all_saying_who_we_are_is_an_error(self):
        with mock.patch.object(_passphrase.pwd, "getpwuid", side_effect=KeyError):
            with mock.patch.object(_passphrase.getpass, "getuser", side_effect=KeyError):
                with self.assertRaises(VaultError) as caught:
                    _passphrase.account_name()
        self.assertIn("could not be determined", str(caught.exception))

    def test_the_label_says_what_the_passphrase_was_derived_from(self):
        label = _passphrase.account_label()
        self.assertIn(_passphrase.account_name(), label)
        self.assertIn("uid %d" % os.getuid(), label)
        self.assertIn("gid %d" % os.getgid(), label)


class FormatTests(unittest.TestCase):
    """The sealed form itself, against the real gpg."""

    def setUp(self):
        environment = _fakes.vault_environment(ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-sealed-")
        self.addCleanup(__import__("shutil").rmtree, self.home, True)
        self.path = os.path.join(self.home, "token")

    def mode_of(self, path):
        return oct(stat.S_IMODE(os.stat(path).st_mode))

    def leftovers(self):
        return [name for name in os.listdir(self.home) if name.startswith(".token-")]

    # -- the round trip ---------------------------------------------------

    def test_a_token_round_trips(self):
        self.assertEqual(sealed.unseal(sealed.seal(TOKEN)), TOKEN)

    def test_what_comes_back_is_not_the_token_in_the_clear(self):
        # The whole point: a scan for tokens, a backup or an eyeball finds nothing.
        content = sealed.seal(TOKEN)
        self.assertNotIn(TOKEN.encode(), content)
        self.assertFalse(sealed.plaintext(content))

    def test_a_token_in_the_clear_is_recognised_as_one(self):
        for content in (TOKEN.encode(), TOKEN.encode() + b"\n", b"  " + TOKEN.encode() + b"  "):
            with self.subTest(content=content[:20]):
                self.assertTrue(sealed.plaintext(content))

    def test_sealed_content_is_not_mistaken_for_a_token(self):
        self.assertFalse(sealed.plaintext(sealed.seal(TOKEN)))
        self.assertFalse(sealed.plaintext(b"not a token at all"))
        self.assertFalse(sealed.plaintext(b""))

    def test_the_cipher_is_an_ordinary_gpg_message(self):
        # The format is gpg's, not something hand-rolled: a plain `gpg -d` with the same
        # passphrase reads it. Asserted by running gpg directly rather than by trusting the
        # library's own unseal, which could be wrong in the same direction as the seal.
        read_fd, write_fd = os.pipe()
        os.write(write_fd, _passphrase.for_this_account().encode("utf-8"))
        os.close(write_fd)
        try:
            back = subprocess.run(
                ["gpg", "-d", "--batch", "--pinentry-mode", "loopback",
                 "--passphrase-fd", str(read_fd), "--output", "-"],
                input=sealed.seal(TOKEN), capture_output=True, pass_fds=(read_fd,))
        finally:
            os.close(read_fd)
        self.assertEqual(back.stdout.decode("utf-8").strip(), TOKEN)

    def test_sealing_and_unsealing_ask_gpg_to_be_quiet(self):
        # gpg narrates a *successful* decrypt ("AES256.CFB encrypted data", "encrypted with 1
        # passphrase") on stderr, and every command that reads the token file decrypts it — so
        # without this those two lines appear on every invocation.
        for sealing in (True, False):
            with self.subTest(sealing=sealing):
                self.assertIn("--quiet", sealed.gpg_arguments(sealing=sealing))

    def test_sealing_and_unsealing_write_nothing_to_stderr(self):
        # The property --quiet exists for, in the form the operator actually notices: reading or
        # writing the token file must not put anything on their terminal. Asserted as emptiness
        # rather than by matching gpg's English, because gpg translates its diagnostics — a
        # localised gpg, reporting a failure correctly, would fail a test looking for the words
        # "decryption failed", and it would also defeat one looking for the chatter.
        cipher = sealed.seal(TOKEN)  # gpg's first-run notes are not what is under test
        self.assertEqual(self.capture_stderr(lambda: sealed.seal(TOKEN)), b"")
        self.assertEqual(self.capture_stderr(lambda: sealed.unseal(cipher)), b"")

    def test_a_refused_passphrase_still_reaches_the_operator(self):
        # Why gpg's stderr is inherited rather than sent to the bit bucket: --quiet drops
        # *informational* messages, and a failure has to stay sayable. Asserted as
        # non-emptiness and not by matching English — gpg translates its diagnostics, and an
        # error is not something a quiet gpg holds back in any language. This is the reason
        # stderr is not DEVNULL, so it has to be tested or that choice is unsupported.
        cipher = sealed.seal(TOKEN)
        refused = []

        def attempt():
            try:
                sealed.unseal(cipher)
            except VaultTokenFileError as error:
                refused.append(error)

        with mock.patch.object(_passphrase, "for_this_account",
                               return_value="not the passphrase"):
            captured = self.capture_stderr(attempt)
        self.assertEqual(len(refused), 1, "a wrong passphrase must still be refused")
        self.assertNotEqual(captured, b"", "--quiet swallowed the reason for a failure")

    def test_the_stderr_capture_hears_a_child(self):
        # The two tests above assert emptiness, which would pass vacuously if pointing
        # descriptor 2 at a file did not really capture what a child writes there. So the
        # mechanism itself is proved on a child whose output is entirely ours. Deliberately
        # *not* gpg: a valid `quiet` line in somebody's ~/.gnupg/gpg.conf would silence gpg and
        # fail this test while the package behaved correctly.
        def write_to_stderr():
            subprocess.run([sys.executable, "-c",
                            "import sys; sys.stderr.write('heard\\n')"], check=True)

        self.assertEqual(self.capture_stderr(write_to_stderr), b"heard\n")

    def capture_stderr(self, action):
        """What ``action`` writes to descriptor 2, as bytes.

        gpg is a child process, so ``sys.stderr`` cannot be redirected from Python: the
        descriptor itself has to be pointed at a file and put back afterwards.
        """
        handle, path = tempfile.mkstemp(prefix="captured-stderr-")
        saved = os.dup(2)
        try:
            os.dup2(handle, 2)
            action()
        finally:
            os.dup2(saved, 2)
            os.close(saved)
            os.close(handle)
        try:
            with open(path, "rb") as captured:
                return captured.read()
        finally:
            os.unlink(path)

    # -- another account --------------------------------------------------

    def test_a_file_sealed_by_another_account_cannot_be_opened(self):
        # The likeliest reason a sealed token file will not open, and the message has to say so
        # rather than suggest a passphrase nobody ever set.
        with mock.patch.object(_passphrase, "for_this_account", return_value="something else"):
            sealed_by_another = sealed.seal(TOKEN)
        with self.assertRaises(VaultTokenFileError) as caught:
            sealed.unseal(sealed_by_another)
        message = str(caught.exception)
        self.assertIn("could not be opened", message)
        self.assertIn(_passphrase.account_label(), message)
        self.assertNotIn(TOKEN, message)

    def test_something_that_is_not_a_cipher_at_all_is_refused_the_same_way(self):
        for content in (b"two words", b"\x00\x01\x02", b"-----BEGIN PGP MESSAGE-----"):
            with self.subTest(content=content[:20]):
                with self.assertRaises(VaultTokenFileError):
                    sealed.unseal(content)

    def test_a_cipher_that_decrypts_to_nothing_is_refused(self):
        # gpg said it worked and produced nothing: not a token, and not silence either.
        with mock.patch.object(sealed, "run", return_value=b""):
            with self.assertRaises(VaultTokenFileError):
                sealed.unseal(b"anything")

    def test_a_cipher_that_decrypts_to_something_not_utf8_is_refused(self):
        with mock.patch.object(sealed, "run", return_value=b"\xff\xfe"):
            with self.assertRaises(VaultTokenFileError):
                sealed.unseal(b"anything")

    # -- the tool ---------------------------------------------------------

    def test_the_tool_is_resolved_to_a_path(self):
        self.assertTrue(os.path.isabs(sealed.tool()))

    def test_gpg2_is_used_where_that_is_the_only_name(self):
        def which(name):
            return "/usr/bin/gpg2" if name == "gpg2" else None

        with mock.patch.object(sealed.shutil, "which", which):
            self.assertEqual(sealed.tool(), "/usr/bin/gpg2")

    def test_no_tool_at_all_is_reported_by_name(self):
        with mock.patch.object(sealed.shutil, "which", return_value=None):
            with self.assertRaises(VaultError) as caught:
                sealed.tool()
        self.assertIn("gpg", str(caught.exception))
        self.assertIn("PATH", str(caught.exception))

    def test_a_tool_that_cannot_be_started_is_reported(self):
        with mock.patch.object(sealed.subprocess, "Popen", side_effect=OSError(13, "denied")):
            with self.assertRaises(VaultError):
                sealed.seal(TOKEN)

    def test_a_tool_that_fails_is_reported(self):
        with mock.patch.object(
                sealed.subprocess, "Popen",
                side_effect=lambda *arguments, **keywords: _failing_process()):
            with self.assertRaises(VaultError):
                sealed.seal(TOKEN)

    def test_a_tool_that_stops_reading_does_not_break_the_writer(self):
        # What gpg does when it cannot get what it asked for: it gives up and exits, leaving
        # this side writing into a pipe nobody is reading and closing it afterwards. Both have
        # to be swallowed so that the tool's own exit status is what gets reported.
        process = _FakeProcess(status=2)
        process.stdin = _ClosedPipe()
        with mock.patch.object(sealed.subprocess, "Popen", return_value=process):
            with self.assertRaises(VaultError) as caught:
                sealed.seal(TOKEN)
        self.assertIn("failed", str(caught.exception))

    def test_the_encryption_tool_is_handed_no_token(self):
        # gpg is a child process too, so it gets the same scrubbed environment the commands'
        # children do. Checked on what Popen was actually given, not on the helper.
        seen = {}
        real = subprocess.Popen

        def recording(*arguments, **keywords):
            seen.update(keywords)
            # Recorded at the moment of the spawn: the patch is undone by the time we can
            # assert, so "there was something to strip" has to be sampled where it is true.
            seen["legacy_in_process_environment"] = "ECMWF_VAULT_TOKEN" in os.environ
            # Sampled here, at the spawn: this test runs gpg for real, so PATH cannot be set
            # to a fiction, and comparing against it later would read the runner's value
            # rather than the one that was in force when the child was built.
            seen["ambient_path"] = os.environ["PATH"]
            return real(*arguments, **keywords)

        # The name has to be present to begin with: an assertion that something is absent from
        # an environment that never held it passes with or without the scrub.
        with _fakes.vault_environment(), \
                mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": "hvs.a-legacy-export"}), \
                mock.patch.object(sealed.subprocess, "Popen", recording):
            sealed.seal(TOKEN)
        self.assertTrue(seen["legacy_in_process_environment"], "nothing was there to strip")
        self.assertIn("env", seen, "gpg was given the environment to inherit")
        self.assertFalse("ECMWF_VAULT_TOKEN" in seen["env"],
                         "the legacy token variable must not reach gpg")
        self.assertEqual(seen["env"]["PATH"], seen["ambient_path"],
                         "gpg still inherits everything else it needs")

    def test_a_tool_that_floods_stdout_is_stopped(self):
        process = _noisy_process(sealed.MAX_OUTPUT + 10)
        with mock.patch.object(sealed.subprocess, "Popen", return_value=process):
            with self.assertRaises(VaultError):
                sealed.seal(TOKEN)
        self.assertTrue(process.killed)

    # -- writing ----------------------------------------------------------

    def test_a_written_file_is_sealed_and_mode_600(self):
        sealed.write(self.path, TOKEN)
        self.assertEqual(self.mode_of(self.path), "0o600")
        with open(self.path, "rb") as handle:
            content = handle.read()
        self.assertFalse(sealed.plaintext(content))
        self.assertEqual(sealed.unseal(content), TOKEN)

    def test_writing_creates_the_directory_at_mode_700(self):
        deeper = os.path.join(self.home, "fresh", "token")
        sealed.write(deeper, TOKEN)
        self.assertEqual(self.mode_of(os.path.dirname(deeper)), "0o700")

    def test_writing_replaces_what_is_there(self):
        sealed.write(self.path, TOKEN)
        other = "hvs.synthetic-second-token"
        sealed.write(self.path, other)
        with open(self.path, "rb") as handle:
            self.assertEqual(sealed.unseal(handle.read()), other)

    def test_a_write_that_fails_leaves_no_temporary_behind(self):
        with mock.patch.object(sealed.os, "replace", side_effect=OSError(28, "no space")):
            with self.assertRaises(OSError):
                sealed.write(self.path, TOKEN)
        self.assertEqual(self.leftovers(), [])

    def test_a_write_that_cannot_clean_up_says_so_with_both_facts(self):
        # Raising the failure on its own would leave a file nobody knows about behind it.
        with mock.patch.object(sealed.os, "replace", side_effect=OSError(28, "no space")), \
                mock.patch.object(sealed.os, "unlink", side_effect=OSError(1, "denied")):
            with self.assertRaises(VaultTokenFileError) as caught:
                sealed.write(self.path, TOKEN)
        message = str(caught.exception)
        self.assertIn("no space", message)
        self.assertIn("could not be removed", message)


class _FakeProcess:
    """Enough of a Popen for the failure paths: a pipe, a status, and a kill to record."""

    def __init__(self, output=b"", status=0):
        self.stdout = _FakePipe(output)
        self.stdin = _FakePipe()
        self.status = status
        self.killed = False

    def wait(self):
        return self.status

    def kill(self):
        self.killed = True


class _ClosedPipe:
    """A pipe the tool has already walked away from: writing or closing it raises."""

    def write(self, content):
        raise BrokenPipeError(32, "Broken pipe")

    def close(self):
        raise BrokenPipeError(32, "Broken pipe")


class _FakePipe:
    def __init__(self, content=b""):
        self.content = content
        self.closed = False

    def read(self, _size):
        return self.content

    def write(self, content):
        self.content = content

    def close(self):
        self.closed = True


def _failing_process():
    return _FakeProcess(status=2)


def _noisy_process(size):
    return _FakeProcess(output=b"x" * size)


if __name__ == "__main__":
    unittest.main()
