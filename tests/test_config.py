# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The token sources: the environment, then a private token file.

The token choice is a security control, so these tests pin precedence, the absence of silent
fall-through, and every refusal the token file can provoke.

The file holds the token and nothing else — the shape HashiCorp's CLI uses for
``~/.vault-token`` — so there is no format here to test. What is left is worth testing hard:
which file is read, what its permissions must be, and what happens when it is missing,
unreadable or holds something that is not a token.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import (
    VaultError,
    VaultTokenFileError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
)
from ecmwf_vault import _config, _sealed_token_file

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TOKEN = "synthetic-env-token"
FILE_TOKEN = _fakes.SEALED_TOKEN
IN_THE_CLEAR = "hvs.synthetic-token-in-the-clear"


class ConfigTestCase(unittest.TestCase):
    """Common environment handling: inherit nothing from whoever runs the suite."""

    def setUp(self):
        # enterContext() is 3.11+, so call the pair explicitly to stay 3.9-clean.
        environment = _fakes.vault_environment()
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)


class TokenSourceTests(ConfigTestCase):
    def setUp(self):
        super().setUp()
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}
        self.vault = _fakes.make_vault(self.fake)
        self.addCleanup(self.vault.close)

    def sent_token(self):
        return self.fake.requests[0].headers["X-Vault-Token"]

    def test_the_token_file_is_used_when_the_environment_is_unset(self):
        os.environ[_config.TOKEN_FILE_ENV] = _fakes.write_file(FILE_TOKEN)
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_surrounding_whitespace_in_the_file_is_not_part_of_the_token(self):
        # A file written by hand almost always ends in a newline; nothing else about the
        # token is whitespace, so stripping the ends is the whole of the parsing.
        for content in (FILE_TOKEN + "\n", FILE_TOKEN + "\r\n", "  " + FILE_TOKEN + "  ",
                        "\n\n" + FILE_TOKEN + "\n\n"):
            with self.subTest(content=content):
                os.environ[_config.TOKEN_FILE_ENV] = _fakes.write_file(content)
                self.vault.value(EXAMPLE, cache=False)
                self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_the_file_is_re_read_on_every_call(self):
        path = _fakes.write_sealed_token_file()
        os.environ[_config.TOKEN_FILE_ENV] = path
        self.vault.value(EXAMPLE, cache=False)
        rotated = "hvs.synthetic-rotated-token"
        sealed = _sealed_token_file.seal(rotated)
        with open(path, "wb") as handle:
            handle.write(sealed)
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.fake.requests[1].headers["X-Vault-Token"], rotated)

    def test_no_token_anywhere_is_an_error_before_any_request(self):
        with self.assertRaises(VaultTokenMissingError):
            self.vault.value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_the_default_path_is_used_when_the_environment_does_not_name_one(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ.pop(_config.TOKEN_FILE_ENV, None)
            with mock.patch.dict(os.environ, {"HOME": home}):
                directory = os.path.join(home, ".ecmwf-vault")
                os.makedirs(directory, 0o700)
                _fakes.write_file(FILE_TOKEN, directory=directory)
                self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_an_explicitly_named_missing_file_is_an_error(self):
        os.environ[_config.TOKEN_FILE_ENV] = _fakes.absent_token_file_path()
        with self.assertRaises(VaultTokenFileError) as caught:
            self.vault.value(EXAMPLE)
        self.assertIn("does not exist", str(caught.exception))

    def test_the_token_never_appears_in_a_raised_message(self):
        # Every way a file can fail to be a token. None of these messages may carry the
        # value: this is a credential, and a message ends up in a log.
        for content in ("", "   \n", "bad%d token" % 1, "tok\u00e9n",
                        "two\nlines", "a" * (_config.MAX_TOKEN_BYTES + 1)):
            with self.subTest(content=content[:20]):
                os.environ[_config.TOKEN_FILE_ENV] = _fakes.write_file(content)
                try:
                    _config.resolve_token()
                except (VaultTokenFileError, VaultTokenInvalidError,
                        VaultTokenMissingError) as error:
                    self.assertNotIn("bad1", str(error))
                    self.assertNotIn("tok\u00e9n", str(error))
                    self.assertNotIn("a" * 40, str(error))
                    if content:
                        # Not for the empty file: every string contains "".
                        self.assertNotIn(content[:20], repr(error))
                else:
                    self.fail("expected a failure for %r" % content[:20])


class TokenFilePathTests(ConfigTestCase):
    def test_a_named_path_is_used_and_reported_as_named(self):
        os.environ[_config.TOKEN_FILE_ENV] = "  /tmp/somewhere/token  "
        self.assertEqual(_config.token_file_path(), ("/tmp/somewhere/token", True))

    def test_the_default_is_expanded_and_not_reported_as_named(self):
        os.environ.pop(_config.TOKEN_FILE_ENV, None)
        with mock.patch.dict(os.environ, {"HOME": "/home/example"}):
            self.assertEqual(_config.token_file_path(),
                             ("/home/example/.ecmwf-vault/token", False))

    def test_a_blank_override_falls_back_to_the_default(self):
        os.environ[_config.TOKEN_FILE_ENV] = "   "
        self.assertEqual(_config.token_file_path()[1], False)

class TokenFileSafetyTests(ConfigTestCase):
    def write(self, text, **kwargs):
        """A file written verbatim: for the tests about content."""
        return _fakes.write_file(text, **kwargs)

    def write_token(self, token=_fakes.SEALED_TOKEN, **kwargs):
        """A token file in the sealed form: for the tests about everything else."""
        return _fakes.write_sealed_token_file(token, **kwargs)

    def read(self, path):
        """The text of a file, with the handle closed."""
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def token_in(self, path):
        os.environ[_config.TOKEN_FILE_ENV] = path
        return _config.resolve_token()

    def test_a_0600_file_owned_by_us_is_read(self):
        path = self.write_token()
        self.assertEqual(oct(stat.S_IMODE(os.stat(path).st_mode)), "0o600")
        self.assertEqual(self.token_in(path), _fakes.SEALED_TOKEN)

    def test_group_or_other_access_is_refused_by_default(self):
        for mode in (0o640, 0o604, 0o660, 0o644, 0o666, 0o607):
            with self.subTest(mode=oct(mode)):
                path = self.write_token(mode=mode)
                with self.assertRaises(VaultTokenFileError) as caught:
                    self.token_in(path)
                self.assertIn("600", str(caught.exception))
                self.assertNotIn(FILE_TOKEN, str(caught.exception))

    def test_a_file_owned_by_another_user_is_refused(self):
        path = self.write_token()
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(VaultTokenFileError) as caught:
                self.token_in(path)
        self.assertIn("owned", str(caught.exception))

    def test_a_symlink_is_refused(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-symlink-")
        real = self.write(FILE_TOKEN, directory=directory, name="real")
        link = os.path.join(directory, "token")
        os.symlink(real, link)
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(link)
        self.assertIn("symlink", str(caught.exception))

    def test_a_directory_is_refused(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-dir-")
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(directory)
        self.assertIn("regular file", str(caught.exception))

    def test_a_fifo_is_refused_without_blocking(self):
        # Opening a FIFO read-only blocks unless O_NONBLOCK is used, so this test
        # would hang rather than fail if that flag were dropped.
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-fifo-")
        path = os.path.join(directory, "token")
        os.mkfifo(path, 0o600)
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(path)
        self.assertIn("regular file", str(caught.exception))

    def test_an_oversized_file_is_refused(self):
        path = self.write("x" * (_config.MAX_TOKEN_BYTES + 1))
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(path)
        self.assertIn("too large", str(caught.exception))

    def test_a_file_that_grows_past_the_limit_during_the_read_is_refused(self):
        # The size check must happen while reading too, not only on the stat: a
        # file can grow between the two.
        path = self.write_token()
        reported = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_size=0,
                             st_uid=os.geteuid())
        with mock.patch("os.fstat", return_value=reported), \
                mock.patch("os.read",
                           side_effect=[b"x" * (_config.MAX_TOKEN_BYTES + 1)]):
            with self.assertRaises(VaultTokenFileError) as caught:
                self.token_in(path)
        self.assertIn("too large", str(caught.exception))

    def test_modes_without_group_or_other_access_are_accepted(self):
        # The rule is "not reachable by group or other", the same one OpenSSH
        # applies to a private key: refusing the strictly safer 0400 in the name of
        # a literal 0600 would push a careful user to loosen their file.
        for mode in (0o600, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                path = self.write_token(mode=mode)
                self.assertEqual(self.token_in(path), FILE_TOKEN)

    # -- and the directory holding it, to the same rule ---------------------

    def directory(self, mode):
        """A token directory with an explicit mode, and the file in it."""
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-dir-mode-")
        self.addCleanup(shutil.rmtree, directory, True)
        # Registered after the rmtree, so it runs first: a directory without write
        # permission cannot have its contents removed.
        self.addCleanup(os.chmod, directory, 0o700)
        path = _fakes.write_sealed_token_file(directory=directory, name="token")
        # Last, so that a mode without owner-write still has the file to hold.
        os.chmod(directory, mode)
        return directory, path

    def test_a_private_directory_is_read(self):
        for mode in (0o700, 0o500, 0o300):
            with self.subTest(mode=oct(mode)):
                _, path = self.directory(mode)
                self.assertEqual(self.token_in(path), FILE_TOKEN)

    def test_a_directory_reachable_by_another_user_is_refused(self):
        # The file is 0600, so only the directory is wrong: another user could list
        # it, replace the file, or add one beside it.
        for mode in (0o755, 0o770, 0o750, 0o705):
            with self.subTest(mode=oct(mode)):
                _, path = self.directory(mode)
                with self.assertRaises(VaultTokenFileError) as caught:
                    self.token_in(path)
                self.assertIn("directory", str(caught.exception))
                self.assertIn("700", str(caught.exception))
                self.assertNotIn(FILE_TOKEN, str(caught.exception))

    def test_a_directory_owned_by_another_user_is_refused(self):
        # Checked directly: mocking geteuid would trip the file's ownership check
        # first, so the directory's own branch is exercised on its own here.
        directory, path = self.directory(0o700)
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(VaultTokenFileError) as caught:
                _config.check_directory_permissions(path)
        self.assertIn("directory", str(caught.exception))
        self.assertIn("owned", str(caught.exception))
        self.assertNotIn(directory, str(caught.exception))

    def test_a_directory_that_disappears_is_not_itself_an_error(self):
        # A race between opening the file and looking at its directory. The file was openable,
        # so the read is judged on the file's own merits. The mock has to let every *other*
        # stat through: resolving the encryption tool walks PATH with stat, and a blanket
        # failure would turn this into a test of a missing gpg.
        _, path = self.directory(0o700)
        directory = os.path.dirname(path)
        real_stat = os.stat

        def vanishing(target, *arguments, **keywords):
            if os.path.abspath(target) == os.path.abspath(directory):
                raise FileNotFoundError(2, "No such file or directory")
            return real_stat(target, *arguments, **keywords)

        with mock.patch.object(os, "stat", vanishing):
            self.assertEqual(self.token_in(path), FILE_TOKEN)

    def test_a_symlinked_directory_is_judged_where_the_file_really_is(self):
        # A permissive-looking path to a directory that is in fact private: the
        # mode that matters is the real one, and it is where an attacker would
        # have to reach.
        private, _ = self.directory(0o700)
        exposed, _ = self.directory(0o700)
        link = os.path.join(exposed, "link")
        os.symlink(private, link)
        os.chmod(exposed, 0o755)
        self.assertEqual(self.token_in(os.path.join(link, "token")), FILE_TOKEN)

    def test_a_private_path_to_an_exposed_directory_is_still_refused(self):
        exposed, _ = self.directory(0o755)
        private, _ = self.directory(0o700)
        link = os.path.join(private, "link")
        os.symlink(exposed, link)
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(os.path.join(link, "token"))
        self.assertIn("directory", str(caught.exception))

    def test_a_file_that_cannot_be_read_is_a_fixed_error(self):
        path = self.write_token()
        with mock.patch("os.open", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(VaultTokenFileError) as caught:
                self.token_in(path)
        self.assertIn("could not be read", str(caught.exception))
        self.assertNotIn(path, str(caught.exception))

    # -- what the file holds ------------------------------------------------

    def test_a_sealed_file_is_read(self):
        self.assertEqual(self.token_in(self.write_token()), _fakes.SEALED_TOKEN)

    def test_a_token_in_the_clear_is_sealed_in_place_and_said_out_loud(self):
        # The case the format exists for: a token dropped in by hand must not stay a string on
        # disk. It is said on stderr, because the file changed underneath a read.
        path = self.write(IN_THE_CLEAR)
        with mock.patch("sys.stderr") as stderr:
            self.assertEqual(self.token_in(path), IN_THE_CLEAR)
        written = "".join(str(call) for call in stderr.write.call_args_list)
        self.assertIn("has been sealed", written)
        with open(path, "rb") as handle:
            on_disk = handle.read()
        self.assertFalse(_sealed_token_file.plaintext(on_disk), "still a token in the clear")
        self.assertEqual(_sealed_token_file.unseal(on_disk), IN_THE_CLEAR)

    def test_a_file_that_cannot_be_sealed_is_refused(self):
        # A token in the clear is only used once it has been sealed. Continuing would leave
        # the credential on disk as text and report success, so the failure is raised, and the
        # reason travels with it.
        path = self.write(IN_THE_CLEAR)
        with mock.patch.object(_sealed_token_file, "write",
                               side_effect=VaultError("no space left")):
            with self.assertRaises(VaultTokenFileError) as caught:
                self.token_in(path)
        self.assertIn("could not be sealed", str(caught.exception))
        self.assertIn("no space left", str(caught.exception))
        self.assertNotIn(IN_THE_CLEAR, str(caught.exception))
        self.assertEqual(self.read(path), IN_THE_CLEAR, "and the file is left as it was")

    def test_a_token_that_is_not_header_safe_is_refused_rather_than_sealed(self):
        for token in ("hvs.two words", "hvs.tok\u00e9n", "hvs.one\ntwo"):
            with self.subTest(token=repr(token)):
                path = self.write(token)
                with self.assertRaises(VaultTokenInvalidError):
                    self.token_in(path)
                self.assertEqual(self.read(path), token, "and left as it was")

    def test_a_file_that_is_neither_a_token_nor_sealed_is_refused(self):
        # No `hvs.` prefix, and nothing gpg can open. The message says what the sealed form is
        # derived from, because another account or machine is the likeliest reason — and
        # "wrong passphrase" would send someone looking for a passphrase to type.
        for content in ("two words", "random bytes\n", "\x00nul", "not a token at all"):
            with self.subTest(content=content[:12]):
                path = self.write(content)
                with self.assertRaises(VaultTokenFileError) as caught:
                    self.token_in(path)
                self.assertIn("could not be opened", str(caught.exception))

    def test_plaintext_that_is_not_utf8_is_refused_as_text(self):
        # It carries the prefix, so it is meant to be a token, and it is not text at all:
        # a refusal about the file rather than an attempt to unseal it.
        path = _fakes.write_bytes(b"hvs.\xff\xfe")
        with self.assertRaises(VaultTokenFileError) as caught:
            self.token_in(path)
        self.assertIn("UTF-8", str(caught.exception))

    def test_whitespace_around_a_token_in_the_clear_is_ignored(self):
        for content in (IN_THE_CLEAR + "\n", IN_THE_CLEAR + "\r\n",
                        "  " + IN_THE_CLEAR + "  "):
            with self.subTest(content=content):
                self.assertEqual(self.token_in(self.write(content)), IN_THE_CLEAR)

    def test_an_empty_file_reports_a_missing_token(self):
        with self.assertRaises(VaultTokenMissingError):
            self.token_in(self.write(""))

    def test_a_file_holding_only_whitespace_reports_a_missing_token(self):
        with self.assertRaises(VaultTokenMissingError):
            self.token_in(self.write("  \n\t\n"))

if __name__ == "__main__":
    unittest.main()
