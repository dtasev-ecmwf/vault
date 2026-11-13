"""The sealed memory file: sealing, short writes, ownership, no leaks."""
from __future__ import annotations

import fcntl
import gc
import os
import subprocess
import sys
import unittest
import weakref
from unittest import mock

from ecmwf_vault import MAX_SECRET, SecretMemoryFile
from ecmwf_vault import _memory
from ecmwf_vault._errors import VaultError
from ecmwf_vault._memory import missing_support, require_support

PAYLOAD = b'{"password":"synthetic-value"}'


class SupportCheckTests(unittest.TestCase):
    """The runtime capability check, and the message it produces.

    A conda-forge Python built against an old glibc sysroot lacks `memfd_create`
    and every `fcntl` seal constant at once, while the kernel supports both, so
    the check must name all of it and point at the interpreter.
    """

    def test_a_supported_interpreter_reports_nothing_missing(self):
        self.assertEqual(missing_support(), ())
        self.assertIsNone(require_support())

    def test_every_missing_feature_is_named_at_once_not_just_the_first(self):
        with mock.patch.object(os, "memfd_create", None), \
                mock.patch.object(fcntl, "F_ADD_SEALS", None), \
                mock.patch.object(fcntl, "F_SEAL_WRITE", None):
            missing = missing_support()
        self.assertIn("os.memfd_create", missing)
        self.assertIn("fcntl.F_ADD_SEALS", missing)
        self.assertIn("fcntl.F_SEAL_WRITE", missing)
        self.assertNotIn("os.MFD_CLOEXEC", missing)

    def test_the_message_diagnoses_the_interpreter_rather_than_the_kernel(self):
        with mock.patch.object(os, "memfd_create", None):
            with self.assertRaises(VaultError) as caught:
                require_support()
        message = str(caught.exception)
        self.assertIn("os.memfd_create", message)                 # what is missing
        self.assertIn(sys.executable, message)                    # which interpreter
        self.assertIn(sys.version.split()[0], message)            # its version
        self.assertIn(os.uname().release, message)                # context, not blame
        self.assertIn("conda-forge", message)                     # the usual cause
        # And it must not assert a kernel fact this code never checks.
        self.assertNotIn("the kernel supports", message)

    def test_the_recommended_probe_covers_every_required_feature(self):
        # A probe that names three of the eight is worse than none: a build missing
        # F_SEAL_GROW would print True and the reader would move on.
        with mock.patch.object(os, "memfd_create", None):
            with self.assertRaises(VaultError) as caught:
                require_support()
        message = str(caught.exception)
        self.assertIn("all(hasattr", message)
        for name in _memory._FROM_OS + _memory._FROM_FCNTL:
            with self.subTest(name=name):
                self.assertIn("'%s'" % name, message)

    def test_the_probe_actually_fails_on_this_interpreter_right_now(self):
        # The recommendation has to be a working command, not a plausible-looking one.
        # Run it with this interpreter's own path, so the test does not depend on a
        # bare `python` being on PATH.
        probe = _memory._probe_command().replace("python -c", "%s -c" % sys.executable, 1)
        self.assertIn("print(all(hasattr", probe)
        completed = subprocess.run(probe, shell=True, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "True")

    def test_a_partial_build_gets_advice_that_would_actually_help(self):
        # memfd_create present and only a seal constant missing: telling the reader to
        # check hasattr(os, 'memfd_create') would already print True and help nobody.
        with mock.patch.object(fcntl, "F_ADD_SEALS", None):
            self.assertEqual(missing_support(), ("fcntl.F_ADD_SEALS",))
            with self.assertRaises(VaultError) as caught:
                require_support()
        message = str(caught.exception)
        self.assertIn("fcntl.F_ADD_SEALS", message)
        self.assertIn("all(hasattr", message)                     # the full probe
        self.assertIn("'F_SEAL_GROW'", message)                   # which it checks too
        self.assertIn("'memfd_create'", message)                  # and the module side
        # And it must blame only what is actually absent.
        missing_line = [line for line in message.splitlines()
                        if "missing:" in line][0]
        self.assertEqual(missing_line.strip(), "missing: fcntl.F_ADD_SEALS")

    def test_a_non_posix_interpreter_says_so_plainly(self):
        with mock.patch.object(_memory, "fcntl", None):
            self.assertEqual(missing_support(), ("fcntl",))
            with self.assertRaises(VaultError) as caught:
                require_support()
        self.assertIn("requires Linux", str(caught.exception))

    def test_an_unknown_interpreter_path_and_kernel_are_still_reported(self):
        with mock.patch.object(os, "memfd_create", None), \
                mock.patch.object(sys, "executable", ""), \
                mock.patch.object(os, "uname", None):
            with self.assertRaises(VaultError) as caught:
                require_support()
        self.assertEqual(str(caught.exception).count("<unknown>"), 2)

    def test_a_path_with_control_characters_cannot_break_the_message(self):
        with mock.patch.object(os, "memfd_create", None), \
                mock.patch.object(sys, "executable", "/tmp/odd\nname"):
            with self.assertRaises(VaultError) as caught:
                require_support()
        message = str(caught.exception)
        self.assertIn("/tmp/odd?name", message)
        self.assertNotIn("/tmp/odd\nname", message)

    def test_the_store_refuses_with_the_same_diagnosis(self):
        with mock.patch.object(os, "memfd_create", None):
            with self.assertRaises(VaultError) as caught:
                SecretMemoryFile(b"{}")
        self.assertIn("conda-forge", str(caught.exception))


class SecretMemoryFileTests(unittest.TestCase):
    def test_payload_is_an_anonymous_sealed_memory_file(self):
        memory = SecretMemoryFile(PAYLOAD)
        try:
            target = os.readlink("/proc/self/fd/%d" % memory.fd)
            self.assertIn("memfd:ecmwf-vault-secret", target)
            self.assertEqual(memory.size, len(PAYLOAD))
            self.assertEqual(memory.read(), PAYLOAD)
            # F_SEAL_WRITE and F_SEAL_SHRINK: the bytes cannot change.
            with self.assertRaises(OSError):
                os.write(memory.fd, b"changed")
            with self.assertRaises(OSError):
                os.ftruncate(memory.fd, 0)
        finally:
            memory.close()

    def test_read_does_not_move_the_shared_offset(self):
        memory = SecretMemoryFile(PAYLOAD)
        try:
            self.assertEqual(memory.read(), PAYLOAD)
            self.assertEqual(memory.read(), PAYLOAD)
            self.assertEqual(os.lseek(memory.fd, 0, os.SEEK_CUR), 0)
        finally:
            memory.close()

    def test_close_is_idempotent_and_read_fails_afterwards(self):
        memory = SecretMemoryFile(PAYLOAD)
        fd = memory.fd
        memory.close()
        memory.close()
        with self.assertRaises(OSError):
            os.fstat(fd)
        with self.assertRaises(VaultError):
            memory.read()

    def test_short_writes_are_retried(self):
        payload = b'{"key":"' + b"x" * 5000 + b'"}'
        real_write = os.write

        def one_byte_at_a_time(fd, chunk):
            return real_write(fd, bytes(chunk[:1]))

        with mock.patch("os.write", side_effect=one_byte_at_a_time):
            memory = SecretMemoryFile(payload)
        try:
            self.assertEqual(memory.read(), payload)
        finally:
            memory.close()

    def test_a_failed_write_closes_the_descriptor_and_raises(self):
        opened = []
        real_memfd_create = os.memfd_create

        def record(*args, **kwargs):
            fd = real_memfd_create(*args, **kwargs)
            opened.append(fd)
            return fd

        with mock.patch("os.memfd_create", side_effect=record), \
                mock.patch("os.write", side_effect=OSError(28, "no space")):
            with self.assertRaises(OSError):
                SecretMemoryFile(PAYLOAD)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_a_zero_length_write_is_an_error(self):
        with mock.patch("os.write", return_value=0):
            with self.assertRaises(VaultError):
                SecretMemoryFile(PAYLOAD)

    def test_duplicate_is_independent_and_not_inheritable(self):
        memory = SecretMemoryFile(PAYLOAD)
        copy = memory.duplicate()
        try:
            self.assertNotEqual(copy.fd, memory.fd)
            self.assertFalse(os.get_inheritable(copy.fd))
            memory.close()
            self.assertEqual(copy.read(), PAYLOAD)
        finally:
            copy.close()

    def test_duplicate_of_a_closed_file_fails(self):
        memory = SecretMemoryFile(PAYLOAD)
        memory.close()
        with self.assertRaises(VaultError):
            memory.duplicate()

    def test_context_manager_closes(self):
        with SecretMemoryFile(PAYLOAD) as memory:
            fd = memory.fd
            self.assertEqual(memory.read(), PAYLOAD)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_collecting_a_memory_file_closes_its_descriptor(self):
        # The default-instance pool relies on this: an evicted Vault is dropped
        # rather than closed, and its sealed descriptor must still go.
        memory = SecretMemoryFile(PAYLOAD)
        fd = memory.fd
        reference = weakref.ref(memory)
        del memory
        gc.collect()
        self.assertIsNone(reference())
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_a_failed_dup_closes_the_new_descriptor(self):
        memory = SecretMemoryFile(PAYLOAD)
        seen = []
        real_dup = os.dup

        def record(fd):
            new_fd = real_dup(fd)
            seen.append(new_fd)
            return new_fd

        try:
            with mock.patch("os.dup", side_effect=record), \
                    mock.patch("os.set_inheritable",
                               side_effect=OSError(9, "bad file descriptor")):
                with self.assertRaises(OSError):
                    memory.duplicate()
            self.assertTrue(seen)
            for fd in seen:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            # The original is untouched.
            self.assertEqual(memory.read(), PAYLOAD)
        finally:
            memory.close()

    def test_repr_hides_the_payload(self):
        memory = SecretMemoryFile(PAYLOAD)
        try:
            self.assertNotIn("synthetic-value", repr(memory))
            self.assertIn("sealed=True", repr(memory))
        finally:
            memory.close()

    def test_rejects_non_bytes_and_oversized_payloads(self):
        with self.assertRaises(VaultError):
            SecretMemoryFile("not bytes")  # type: ignore[arg-type]
        with self.assertRaises(VaultError):
            SecretMemoryFile(bytearray(b"x" * (MAX_SECRET + 1)))

    def test_accepts_a_bytearray_of_the_maximum_size(self):
        memory = SecretMemoryFile(bytearray(b"x" * MAX_SECRET))
        try:
            self.assertEqual(memory.size, MAX_SECRET)
        finally:
            memory.close()

    def test_requires_linux_memfd_create(self):
        with mock.patch.object(os, "memfd_create", None):
            with self.assertRaises(VaultError):
                SecretMemoryFile(PAYLOAD)


if __name__ == "__main__":
    unittest.main()
