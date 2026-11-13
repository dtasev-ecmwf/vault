"""A secret held in a sealed, anonymous Linux memory file.

This is the AgMon ``SealedMemoryFile`` technique
(``agmon/mcp-server/lease_registry/memory.py``): an ``memfd`` never appears in
the filesystem, is mode 0600, and is sealed ``WRITE|GROW|SHRINK|SEAL`` once
written, so the bytes cannot change afterwards. Reads go through ``pread``,
which does not move the shared file offset.
"""
from __future__ import annotations

import os
import sys
from contextlib import suppress
from typing import Tuple

from ._errors import VaultError

try:  # fcntl is POSIX-only; the module still imports elsewhere and fails at use.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]

MEMFD_NAME = "ecmwf-vault-secret"
MAX_SECRET = 256 * 1024

_MEMFD_MESSAGE = (
    "ecmwf-vault needs Linux memfd_create with file sealing, and this interpreter "
    "lacks it")
_NOT_LINUX_MESSAGE = "ecmwf-vault requires Linux: there is no fcntl module here"
_PAYLOAD_MESSAGE = "the secret payload must be bytes"
_SIZE_MESSAGE = "the secret payload exceeds the size limit"
_WRITE_MESSAGE = "could not write the secret to memory"
_CLOSED_MESSAGE = "the secret memory file is closed"

# Every interpreter feature this module needs. They arrive together or not at all:
# CPython decides once, at build time, whether it has memfd_create and the fcntl
# seal constants, so a build that lacks one lacks them all. conda-forge Pythons are
# compiled against an old glibc sysroot and are the usual case: the kernel and the
# runtime glibc both support sealing, and the interpreter still cannot see it.
_FROM_OS = ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")
_FROM_FCNTL = ("F_ADD_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK",
               "F_SEAL_SEAL")


def missing_support() -> Tuple[str, ...]:
    """Names of the interpreter features this package needs and cannot see."""
    if fcntl is None:
        return ("fcntl",)
    missing = []
    for module, prefix, attributes in ((os, "os", _FROM_OS),
                                       (fcntl, "fcntl", _FROM_FCNTL)):
        missing.extend("%s.%s" % (prefix, name) for name in attributes
                       if getattr(module, name, None) is None)
    return tuple(missing)


def _printable(text: str) -> str:
    """Replace anything unprintable in a path, so it cannot reshape the message."""
    return "".join(character if character.isprintable() else "?" for character in text)


def _probe_command() -> str:
    """A one-liner that is satisfied only if *every* required feature is present.

    Generated from ``_FROM_OS`` and ``_FROM_FCNTL`` so it cannot drift from the check
    that produced the message. A shorter probe is worse than useless: naming three of
    the eight features means a build missing, say, ``F_SEAL_GROW`` prints True and the
    reader concludes the interpreter is fine.
    """
    pairs = ", ".join("(%s, %r)" % (module, name)
                      for module, names in (("os", _FROM_OS), ("fcntl", _FROM_FCNTL))
                      for name in names)
    return ("python -c \"import os, fcntl; print(all(hasattr(m, n) for m, n in [%s]))\""
            % pairs)


def _unsupported_message(missing: Tuple[str, ...]) -> str:
    if missing == ("fcntl",):
        return _NOT_LINUX_MESSAGE
    return (
        "%s\n"
        "  interpreter: %s (Python %s)\n"
        "  kernel: %s\n"
        "  missing: %s\n"
        "These are all decided when Python is built, so a build that lacks one usually\n"
        "lacks them all: a Python compiled against an old glibc sysroot - conda-forge\n"
        "builds are the common case - is missing the lot, even where the kernel is new\n"
        "enough to support it. To test a candidate interpreter, every name above must\n"
        "be present, so this must print True:\n"
        "  %s\n"
        "This package fails closed rather than putting the secret on disk."
        % (_MEMFD_MESSAGE,
           _printable(sys.executable or "<unknown>"),
           sys.version.split()[0],
           _printable(_kernel_release()),
           ", ".join(missing),
           _probe_command()))


def _kernel_release() -> str:
    uname = getattr(os, "uname", None)
    return uname().release if uname is not None else "<unknown>"


def require_support() -> None:
    """Fail closed, naming exactly what this interpreter is missing and why.

    Called before anything is fetched as well as before anything is stored, so a
    missing capability is reported before the network call. It checks that the API
    is *present*, not that sealing will succeed, so a sealing failure still aborts
    after the fetch - storing and returning nothing.
    """
    missing = missing_support()
    if missing:
        raise VaultError(_unsupported_message(missing))


def _write_all(fd: int, payload: bytes) -> None:
    """Write every byte, retrying short writes.

    ``os.write`` is allowed to write fewer bytes than it was given; a partial
    write sealed and later returned as a complete secret would be a silent
    corruption of a credential, so this loops until the payload is accounted
    for and refuses a zero-byte write.
    """
    view = memoryview(payload)
    written = 0
    while written < len(view):
        chunk = os.write(fd, view[written:])
        if chunk <= 0:
            raise VaultError(_WRITE_MESSAGE)
        written += chunk


class SecretMemoryFile:
    """Owns one sealed memfd holding secret bytes.

    The descriptor belongs to this object; :meth:`close` closes it and is
    idempotent. Use :meth:`duplicate` to hand out an independent descriptor.
    """

    def __init__(self, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise VaultError(_PAYLOAD_MESSAGE)
        if len(payload) > MAX_SECRET:
            raise VaultError(_SIZE_MESSAGE)
        require_support()
        fd = os.memfd_create(  # type: ignore[attr-defined]
            MEMFD_NAME, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, bytes(payload))
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(  # type: ignore[union-attr]
                fd, fcntl.F_ADD_SEALS,  # type: ignore[union-attr]
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW  # type: ignore[union-attr]
                | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)  # type: ignore[union-attr]
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        self.size = len(payload)
        self.sealed = True

    @classmethod
    def _adopt(cls, fd: int, size: int) -> "SecretMemoryFile":
        """Wrap an already-sealed descriptor without copying the payload."""
        instance = cls.__new__(cls)
        instance.fd = fd
        instance.size = size
        instance.sealed = True
        return instance

    def read(self) -> bytes:
        """Return the sealed bytes. Does not move the file offset."""
        if self.fd < 0:
            raise VaultError(_CLOSED_MESSAGE)
        return os.pread(self.fd, self.size, 0)

    def duplicate(self) -> "SecretMemoryFile":
        """Return an independent, caller-owned descriptor for the same bytes.

        ``dup`` shares the sealed file, so the copy can be read and closed
        without disturbing this object or the cache it may belong to. ``dup``
        clears ``FD_CLOEXEC``, so it is set again here: an ``exec`` in a child
        must not inherit the secret unless the caller passes the descriptor
        explicitly (``subprocess(..., pass_fds=...)``).
        """
        if self.fd < 0:
            raise VaultError(_CLOSED_MESSAGE)
        fd = os.dup(self.fd)
        try:
            os.set_inheritable(fd, False)
        except OSError:
            os.close(fd)
            raise
        return SecretMemoryFile._adopt(fd, self.size)

    def close(self) -> None:
        """Close the descriptor. Idempotent; never raises for an open fd."""
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            with suppress(OSError):
                os.close(fd)

    def __enter__(self) -> "SecretMemoryFile":
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    def __repr__(self) -> str:
        return "<SecretMemoryFile fd=%d size=%d sealed=%s>" % (
            self.fd, self.size, self.sealed)
