# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The headline promise: a read never creates a file, and nothing leaks.

Writes are forbidden outright; reads (``/proc/swaps``, the CA bundle) are
expected and allowed. ``repr`` checks cover the library's own objects, since the
``dict`` the caller receives is theirs by design.
"""
from __future__ import annotations

import builtins
import contextlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import VaultError
from ecmwf_vault._errors import SecretFieldMissingError

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TOKEN = "synthetic-vault-token"
SECRET = "synthetic-value"

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

CHILD_FD_SCRIPT = (
    "import os\n"
    "names = []\n"
    "for name in os.listdir('/proc/self/fd'):\n"
    "    try:\n"
    "        names.append(os.readlink('/proc/self/fd/' + name))\n"
    "    except OSError:\n"
    "        pass\n"
    "print(';'.join(sorted(names)))\n")


@contextlib.contextmanager
def forbid_writes():
    """Fail if anything under test opens a path for writing, or wants a temp file."""
    real_os_open = os.open
    real_open = builtins.open

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & WRITE_FLAGS:
            raise AssertionError("the library tried to create %r" % (path,))
        return real_os_open(path, flags, *args, **kwargs)

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(letter in mode for letter in "wax+"):
            raise AssertionError("the library tried to write %r" % (file,))
        return real_open(file, mode, *args, **kwargs)

    with mock.patch("os.open", side_effect=guarded_os_open), \
            mock.patch("builtins.open", side_effect=guarded_open), \
            mock.patch("tempfile.mkstemp",
                       side_effect=AssertionError("mkstemp was called")), \
            mock.patch("tempfile.mkdtemp",
                       side_effect=AssertionError("mkdtemp was called")), \
            mock.patch("tempfile.NamedTemporaryFile",
                       side_effect=AssertionError("NamedTemporaryFile was called")), \
            mock.patch("tempfile.TemporaryFile",
                       side_effect=AssertionError("TemporaryFile was called")):
        yield


class NoDiskTests(unittest.TestCase):
    def setUp(self):
        environment = _fakes.vault_environment(ECMWF_VAULT_TOKEN=TOKEN)
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": SECRET}
        self.vault = _fakes.make_vault(self.fake)
        self.addCleanup(self.vault.close)
        self.tempdir = tempfile.gettempdir()
        self.before = sorted(os.listdir(self.tempdir))

    def test_a_full_read_creates_no_file(self):
        with forbid_writes():
            self.assertEqual(_fakes.revealed(self.vault.value(EXAMPLE)),
                             self.fake.fields)
            self.assertEqual(self.vault.value(EXAMPLE, field="password").reveal(),
                             SECRET)
        self.assertEqual(sorted(os.listdir(self.tempdir)), self.before)

    def test_an_uncached_read_creates_no_file(self):
        with forbid_writes():
            self.assertEqual(_fakes.revealed(self.vault.value(EXAMPLE, cache=False)),
                             self.fake.fields)
        self.assertEqual(sorted(os.listdir(self.tempdir)), self.before)

    def test_a_secret_cannot_be_written_to_a_file(self):
        # The headline restriction. A value read from the Vault is not a str, so the
        # ordinary "dump it to disk" accident raises instead of succeeding. open()
        # creates the file before write() fails, so what matters is that no secret
        # reaches it.
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "out")
            secret = self.vault.value(EXAMPLE, field="password")
            with open(target, "w", encoding="utf-8") as handle:
                with self.assertRaises(TypeError):
                    handle.write(secret)
            with open(target, encoding="utf-8") as handle:
                contents = handle.read()
        self.assertEqual(contents, "")
        self.assertNotIn(SECRET, contents)

    def test_a_token_file_is_only_ever_read(self):
        # The token file is a credential on disk and this package only ever reads
        # it; the guarded open fails the test if anything tries to write.
        path = _fakes.write_config("ECMWF_VAULT_TOKEN=%s\n" % TOKEN)
        os.environ.pop("ECMWF_VAULT_TOKEN", None)
        os.environ["ECMWF_VAULT_CONFIG"] = path
        with forbid_writes():
            self.assertEqual(_fakes.revealed(self.vault.value(EXAMPLE, cache=False)),
                             self.fake.fields)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "ECMWF_VAULT_TOKEN=%s\n" % TOKEN)
        self.assertEqual(self.fake.requests[0].headers["X-Vault-Token"], TOKEN)

    def test_the_secret_lives_only_in_an_anonymous_memory_file(self):
        memory = self.vault.memory_file(EXAMPLE)
        try:
            target = os.readlink("/proc/self/fd/%d" % memory.fd)
            self.assertTrue(target.startswith("/memfd:ecmwf-vault-secret"),
                            target)
            self.assertFalse(os.path.exists(target))
            self.assertIn(SECRET.encode(), memory.read())
        finally:
            memory.close()

    def test_an_exec_child_does_not_inherit_the_secret(self):
        memory = self.vault.memory_file(EXAMPLE)
        try:
            plain = subprocess.run([sys.executable, "-c", CHILD_FD_SCRIPT],
                                   capture_output=True, text=True, check=True)
            self.assertNotIn("memfd:ecmwf-vault-secret", plain.stdout)
            # The documented capability still works when it is asked for.
            shared = subprocess.run(
                [sys.executable, "-c", CHILD_FD_SCRIPT], pass_fds=(memory.fd,),
                capture_output=True, text=True, check=True)
            self.assertIn("memfd:ecmwf-vault-secret", shared.stdout)
        finally:
            memory.close()

    def test_library_objects_do_not_expose_the_secret(self):
        self.vault.value(EXAMPLE)
        memory = self.vault.memory_file(EXAMPLE)
        try:
            self.assertNotIn(SECRET, repr(memory))
        finally:
            memory.close()
        self.assertNotIn(SECRET, repr(self.vault))
        with self.assertRaises(SecretFieldMissingError) as caught:
            self.vault.value(EXAMPLE, field=SECRET)
        self.assertNotIn(SECRET, str(caught.exception))
        with self.assertRaises(VaultError) as caught:
            self.vault.value("../" + SECRET)
        self.assertNotIn(SECRET, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
