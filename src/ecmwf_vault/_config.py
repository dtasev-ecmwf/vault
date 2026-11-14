# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Where the Vault token comes from: the token file.

``~/.ecmwf-vault/token`` holds the token and nothing else, sealed with a passphrase derived
from the account. ``vault_login`` fills it; :mod:`ecmwf_vault._sealed_token_file` is the
format.

A token found in the clear is sealed in place before it is used, and the fact is printed.
Sealing is part of reading: a credential this package cannot seal is one it does not use.

Nothing is cached. Every call reads and decrypts the file, so a re-login takes effect on the
call after it.

Permissions are enforced the way OpenSSH enforces key permissions, with no policy to relax
them: a file another user could read or write, or one you do not own, is refused, and so is
the directory holding it — the directory is what lets another user list the file, replace it,
or add one beside it. A symlink, a non-regular file and an oversized file are refused at any
mode. Errors name the mode required, never the content.

This decides where the token is read from and whether it is safe to read. It does not protect
the token from a process running as you, or from root.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from typing import Optional, Tuple

from . import _sealed_token_file
from ._errors import (
    VaultError,
    VaultTokenFileError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
)
from ._policy import warn_once

TOKEN_FILE_ENV = "ECMWF_VAULT_TOKEN_FILE"
DEFAULT_TOKEN_FILE = "~/.ecmwf-vault/token"

MAX_TOKEN_BYTES = 64 * 1024
READ_SIZE = 4096

# A Vault token is printable ASCII with no space. This is not tidiness:
# http.client raises ValueError("Invalid header value b'<token>'") for an
# embedded CR/LF and UnicodeEncodeError for a character outside latin-1, and
# both messages carry the token. A NUL or other control character must never
# reach a header either.
_TOKEN = re.compile(r"[!-~]+")

# O_NONBLOCK matters here: opening a FIFO read-only would otherwise block until a
# writer appears, before the regular-file check below can reject it.
_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))

MISSING_MESSAGE = (
    "no Vault token: the token file holds nothing; run vault_login to fetch one")
MISSING_FILE_MESSAGE = (
    "the Vault token file named by ECMWF_VAULT_TOKEN_FILE does not exist")
INVALID_TOKEN_MESSAGE = (
    "the Vault token contains characters that cannot be sent in a header")
UNREADABLE_MESSAGE = "the Vault token file could not be read"
SYMLINK_MESSAGE = (
    "the Vault token file is a symlink; point ECMWF_VAULT_TOKEN_FILE at the real path")
NOT_FILE_MESSAGE = "the Vault token file is not a regular file"
TOO_LARGE_MESSAGE = "the Vault token file is too large"
ENCODING_MESSAGE = "the Vault token file is not valid UTF-8 text"
OWNER_MESSAGE = "the Vault token file is not owned by the current user"
MODE_MESSAGE = (
    "the Vault token file is readable or writable by another user (make it mode 600)")
DIRECTORY_OWNER_MESSAGE = (
    "the directory holding the Vault token file is not owned by the current user")
DIRECTORY_MESSAGE = (
    "the directory holding the Vault token file is readable or writable by another "
    "user (make it mode 700)")


def token_file_path() -> Tuple[str, bool]:
    """Return ``(path, was_named)`` for the token file.

    ``was_named`` is true when the caller asked for a specific file, in which case a missing
    file is an error rather than "no token file configured".
    """
    named = os.environ.get(TOKEN_FILE_ENV)
    if isinstance(named, str) and named.strip():
        return named.strip(), True
    return os.path.expanduser(DEFAULT_TOKEN_FILE), False


def resolve_token() -> str:
    """Return the Vault token, read from the token file.

    Read fresh on every call; nothing is cached. See the module docstring for what is refused
    and what :func:`token_in_file` does about a file in the clear.
    """
    path, was_named = token_file_path()
    content = read_token_file(path)
    if content is None:
        if was_named:
            raise VaultTokenFileError(MISSING_FILE_MESSAGE)
        raise VaultTokenMissingError(MISSING_MESSAGE)
    if not content.strip():
        # A file that exists but is empty or whitespace: nothing to use, and nothing wrong with
        # the file itself, so this is the same "no token" as no file at all.
        raise VaultTokenMissingError(MISSING_MESSAGE)
    return validated(token_in_file(content, path))


def token_in_file(content: bytes, path: str) -> str:
    """The token in the token file's content.

    No ``hvs.`` prefix means the content is a cipher, and it is unsealed. The prefix means a
    token in the clear: it is checked, sealed in place, and only then returned. A file that is
    neither is refused by :mod:`ecmwf_vault._sealed_token_file`, whose message names the
    account the passphrase is derived from — another account, or another machine, is the usual
    reason a sealed file will not open here.
    """
    if not _sealed_token_file.plaintext(content):
        return _sealed_token_file.unseal(content)
    try:
        token = validated(content.strip().decode("utf-8"))
    except UnicodeDecodeError:
        raise VaultTokenFileError(ENCODING_MESSAGE) from None
    seal_in_place(path, token)
    return token


def seal_in_place(path: str, token: str) -> None:
    """Seal a token file found in the clear, or refuse the token.

    Writing the sealed form is part of reading it. Continuing after a failed seal would leave
    a credential on disk as text and report success, so the failure is raised with what to fix.
    The message beneath it is one of this package's own and carries no token.
    """
    try:
        _sealed_token_file.write(path, token)
    except (VaultError, OSError) as error:
        raise VaultTokenFileError(
            "the Vault token file holds a token in the clear that could not be sealed (%s); "
            "make the file writable, or replace it with a sealed one" % error) from None
    warn_once("token-file-sealed",
              "ecmwf-vault: %s held a token in the clear and has been sealed with the "
              "passphrase derived from your account" % path)


def validated(token: object) -> str:
    """Return a token that is safe to put in a header, or raise."""
    if not isinstance(token, str) or not token or not _TOKEN.fullmatch(token):
        raise VaultTokenInvalidError(INVALID_TOKEN_MESSAGE)
    return token


def read_token_file(path: str) -> Optional[bytes]:
    """Read the token file as bytes, or return None when there is no file.

    Bytes and not text, because a *sealed* file is a gpg message: decoding it as UTF-8 would
    fail on a file this package wrote itself. What the bytes mean — a token in the clear or a
    sealed one — is :func:`token_in_file`'s question, not this one's.

    Symlinks, non-regular files and oversized files are refused as unreadable. Ownership and
    the group/other mode bits are refused by :func:`check_permissions` and
    :func:`check_directory_permissions`, unconditionally: there is no policy that lets an
    accessible credential be used.
    """
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise VaultTokenFileError(SYMLINK_MESSAGE) from None
        raise VaultTokenFileError(UNREADABLE_MESSAGE) from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VaultTokenFileError(NOT_FILE_MESSAGE)
        if info.st_size > MAX_TOKEN_BYTES:
            raise VaultTokenFileError(TOO_LARGE_MESSAGE)
        check_permissions(info)
        check_directory_permissions(path)
        raw = read_all(descriptor)
    finally:
        os.close(descriptor)
    return bytes(raw)


def problem_with(info: os.stat_result, owner_message: str,
                 mode_message: str) -> Optional[str]:
    """The permission problem a stat result has, or None."""
    if info.st_uid != os.geteuid():
        return owner_message
    if stat.S_IMODE(info.st_mode) & 0o077:
        return mode_message
    return None


def check_permissions(info: os.stat_result) -> None:
    """Refuse a file another user could read or write, or that is not ours."""
    problem = problem_with(info, OWNER_MESSAGE, MODE_MESSAGE)
    if problem is not None:
        raise VaultTokenFileError(problem)


def check_directory_permissions(path: str) -> None:
    """Refuse a token directory another user could reach.

    The same rule as the file, because the directory is what lets another user list the file,
    replace it, or add something beside it. A symlinked directory is resolved first: what
    matters is the mode of wherever the file actually lives, which is also where an attacker
    would have to reach.

    A directory that cannot be stat'd is left alone: the file was opened, so the directory
    going away between the two calls is a race rather than a misconfiguration.
    """
    directory = os.path.dirname(os.path.realpath(path))
    try:
        info = os.stat(directory)
    except OSError:
        return
    problem = problem_with(info, DIRECTORY_OWNER_MESSAGE, DIRECTORY_MESSAGE)
    if problem is not None:
        raise VaultTokenFileError(problem)


def read_all(descriptor: int) -> bytes:
    """Read at most MAX_TOKEN_BYTES, re-checking as we go."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, READ_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_TOKEN_BYTES:
            raise VaultTokenFileError(TOO_LARGE_MESSAGE)
        chunks.append(chunk)
