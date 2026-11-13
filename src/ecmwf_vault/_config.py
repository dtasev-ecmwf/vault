# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Where the Vault token comes from: the environment, then a private config file.

Precedence is ``ECMWF_VAULT_TOKEN`` first, then ``~/.ecmwf-vault/config``. That
ordering matches HashiCorp's own CLI (``VAULT_TOKEN`` overrides
``~/.vault-token``), and it means a caller that already supplies the token in the
environment is unaffected by this file existing.

A source that is *absent or blank* falls through to the next one; a source that
is *present but cannot be a token* is an error, never a silent fall-through.
Using a different credential than the one the caller supplied would be exactly
the class of surprise this package exists to avoid.

The config file is read as data and never executed, and its permissions are
enforced the way OpenSSH enforces key permissions: a file another user could
read or write is refused rather than used.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from typing import Dict, Optional, Tuple

from ._errors import (
    VaultConfigFileError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
)
from ._policy import warn_once

CONFIG_ENV = "ECMWF_VAULT_CONFIG"
POLICY_ENV = "ECMWF_VAULT_CONFIG_POLICY"
DEFAULT_CONFIG = "~/.ecmwf-vault/config"
TOKEN_KEY = "ECMWF_VAULT_TOKEN"

POLICY_REFUSE = "refuse"
POLICY_WARN = "warn"
POLICY_ALLOW = "allow"
POLICIES = (POLICY_REFUSE, POLICY_WARN, POLICY_ALLOW)

MAX_CONFIG_BYTES = 64 * 1024
READ_SIZE = 4096

# A Vault token is printable ASCII with no space. This is not tidiness:
# http.client raises ValueError("Invalid header value b'<token>'") for an
# embedded CR/LF and UnicodeEncodeError for a character outside latin-1, and
# both messages carry the token. A NUL or other control character must never
# reach a header either.
_TOKEN = re.compile(r"[!-~]+")
_QUOTES = "\"'"

# O_NONBLOCK matters here: opening a FIFO read-only would otherwise block until a
# writer appears, before the regular-file check below can reject it.
_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))

MISSING_MESSAGE = (
    "ECMWF_VAULT_TOKEN is not set and no token is configured in the config file")
MISSING_FILE_MESSAGE = "the Vault config file named by ECMWF_VAULT_CONFIG does not exist"
INVALID_TOKEN_MESSAGE = (
    "the Vault token contains characters that cannot be sent in a header")
POLICY_MESSAGE = "ECMWF_VAULT_CONFIG_POLICY must be one of refuse, warn or allow"
UNREADABLE_MESSAGE = "the Vault config file could not be read"
SYMLINK_MESSAGE = (
    "the Vault config file is a symlink; point ECMWF_VAULT_CONFIG at the real path")
NOT_FILE_MESSAGE = "the Vault config file is not a regular file"
TOO_LARGE_MESSAGE = "the Vault config file is too large"
ENCODING_MESSAGE = "the Vault config file is not valid UTF-8 text"
OWNER_MESSAGE = "the Vault config file is not owned by the current user"
MODE_MESSAGE = (
    "the Vault config file is readable or writable by another user "
    "(make it mode 600)")
SYNTAX_MESSAGE = "the Vault config file has a malformed entry"
UNSUPPORTED_MESSAGE = "the Vault config file has an unsupported entry"
DUPLICATE_MESSAGE = "the Vault config file sets the same entry twice"
QUOTED_MESSAGE = "the Vault config file must not quote the token value"


def resolve_policy(explicit: Optional[str] = None) -> str:
    """Resolve the config-file permission policy.

    Unlike the swap policy this has no constructor argument: the token source is
    deliberately resolved per call rather than held as client state.
    """
    if explicit is None:
        explicit = os.environ.get(POLICY_ENV, POLICY_REFUSE)
    if not isinstance(explicit, str) or explicit not in POLICIES:
        raise VaultConfigFileError(POLICY_MESSAGE)
    return explicit


def config_path() -> Tuple[str, bool]:
    """Return ``(path, was_named)`` for the config file.

    ``was_named`` is true when the caller asked for a specific file, in which case
    a missing file is an error rather than "no config file configured".
    """
    named = os.environ.get(CONFIG_ENV)
    if isinstance(named, str) and named.strip():
        return named.strip(), True
    return os.path.expanduser(DEFAULT_CONFIG), False


def resolve_token(explicit_policy: Optional[str] = None) -> str:
    """Return the Vault token from the environment or the config file."""
    from_environment = os.environ.get(TOKEN_KEY)
    if isinstance(from_environment, str) and from_environment.strip():
        return validated(from_environment.strip())

    path, was_named = config_path()
    entries = read_config(path, resolve_policy(explicit_policy))
    if entries is None:
        if was_named:
            raise VaultConfigFileError(MISSING_FILE_MESSAGE)
        raise VaultTokenMissingError(MISSING_MESSAGE)
    token = entries.get(TOKEN_KEY)
    if token is None or not token.strip():
        raise VaultTokenMissingError(MISSING_MESSAGE)
    return validated(token.strip())


def validated(token: object) -> str:
    """Return a token that is safe to put in a header, or raise."""
    if not isinstance(token, str) or not token or not _TOKEN.fullmatch(token):
        raise VaultTokenInvalidError(INVALID_TOKEN_MESSAGE)
    return token


def read_config(path: str, policy: str) -> Optional[Dict[str, str]]:
    """Read and parse the config file, or return None when there is no file.

    Symlinks, non-regular files and oversized files are refused whatever the
    policy says; ownership and group/other mode bits are what the policy governs,
    so ``allow`` is a deliberate escape hatch for an unusual situation rather
    than a way to read a shared file by accident.
    """
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise VaultConfigFileError(SYMLINK_MESSAGE) from None
        raise VaultConfigFileError(UNREADABLE_MESSAGE) from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VaultConfigFileError(NOT_FILE_MESSAGE)
        if info.st_size > MAX_CONFIG_BYTES:
            raise VaultConfigFileError(TOO_LARGE_MESSAGE)
        check_permissions(info, policy)
        raw = read_all(descriptor)
    finally:
        os.close(descriptor)
    return parse(decode(raw))


def check_permissions(info: os.stat_result, policy: str) -> None:
    """Refuse (or warn once about) a file another user could read or write."""
    problem = None
    if info.st_uid != os.geteuid():
        problem = OWNER_MESSAGE
    elif stat.S_IMODE(info.st_mode) & 0o077:
        problem = MODE_MESSAGE
    if problem is None:
        return
    if policy == POLICY_REFUSE:
        raise VaultConfigFileError(problem)
    # Both relaxed policies warn, exactly as the swap policy does: there is
    # deliberately no silent way to run with a token another user can read.
    warn_once("config-permissions", "ecmwf-vault: %s (continuing because %s=%s)"
              % (problem, POLICY_ENV, policy))


def read_all(descriptor: int) -> bytes:
    """Read at most MAX_CONFIG_BYTES, re-checking as we go."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, READ_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_CONFIG_BYTES:
            raise VaultConfigFileError(TOO_LARGE_MESSAGE)
        chunks.append(chunk)


def decode(raw: bytes) -> str:
    """Decode the file as UTF-8, or raise a fixed error."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultConfigFileError(ENCODING_MESSAGE) from None


def parse(text: str) -> Dict[str, str]:
    """Parse ``KEY=VALUE`` lines without ever echoing their contents.

    Blank lines and lines starting with ``#`` are ignored; the value is taken
    literally apart from surrounding whitespace, and quoting it is refused rather
    than guessed at. Errors carry the line number and nothing else, because a
    malformed file can put a secret in the key position.
    """
    entries: Dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator:
            raise VaultConfigFileError("%s (line %d)" % (SYNTAX_MESSAGE, number))
        if key != TOKEN_KEY:
            raise VaultConfigFileError("%s (line %d)" % (UNSUPPORTED_MESSAGE, number))
        if key in entries:
            raise VaultConfigFileError("%s (line %d)" % (DUPLICATE_MESSAGE, number))
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in _QUOTES:
            raise VaultConfigFileError("%s (line %d)" % (QUOTED_MESSAGE, number))
        entries[key] = value
    return entries
