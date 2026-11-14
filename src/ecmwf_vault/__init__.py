# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Read one secret from the ECMWF Vault and keep it off disk.

    from ecmwf_vault import value    # token from ~/.ecmwf-vault/token, filled by vault_login

    password = value("user_applications_and_services_team/cems_web/k8s-cems-test",
                     field="password").reveal()

What ``value()`` returns is a :class:`Secret`, never a ``str``: anything that merely
renders it — a log line, ``print``, an f-string — shows ``<Secret>``, while writing it
to a file, a stream, an environment variable or a child process argument list raises
``TypeError`` instead of succeeding by accident. ``reveal()`` is the one explicit way
to the plaintext, and ``Vault.memory_file()`` hands it to a child process through an
inherited descriptor, with no file involved. That is a guard-rail against the accident, not a
sandbox: ``reveal()`` is right there, and ``os.write``, a C extension or another process
bypass it.

The token comes from one place: ``~/.ecmwf-vault/token``, a file sealed with a passphrase
derived from the account, so a token is never left on disk as a string. The ``vault_login``
command fills it: it reads a token without echoing it, checks it with Vault, and stores it
sealed. A call made with no usable token raises :class:`VaultTokenMissingError` (a
:class:`RuntimeError`) before any network use. The secret is held in a sealed, anonymous Linux
memfd, and is never written to a file, a log, an exception message or a child process argument
list.

What this does *not* cover is documented in the README's threat model: the token lives in a
mode-600 file on disk that is sealed with a passphrase anyone on the machine can derive, and
the value a caller reveals is an ordinary Python object. The guarantee is "this package never
puts the secret on disk", not "the secret is unreadable in a compromised process".
"""
from __future__ import annotations

from ._client import Vault, clear_cache, close, cubbyhole_read, value
from ._errors import (
    InvalidSecretPathError,
    SecretFieldMissingError,
    SecretNotFoundError,
    SwapPolicyError,
    VaultTokenFileError,
    VaultError,
    VaultPermissionError,
    VaultResponseError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
    VaultUnavailableError,
)
from ._memory import MAX_SECRET, SecretMemoryFile
from ._secret import Secret

__version__ = "0.3.0"

__all__ = [
    "InvalidSecretPathError",
    "MAX_SECRET",
    "Secret",
    "SecretFieldMissingError",
    "SecretMemoryFile",
    "SecretNotFoundError",
    "SwapPolicyError",
    "Vault",
    "VaultTokenFileError",
    "VaultError",
    "VaultPermissionError",
    "VaultResponseError",
    "VaultTokenInvalidError",
    "VaultTokenMissingError",
    "VaultUnavailableError",
    "__version__",
    "clear_cache",
    "close",
    "cubbyhole_read",
    "value",
]
