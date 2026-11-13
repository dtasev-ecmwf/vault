"""Read one secret from the ECMWF Vault and keep it off disk.

    import os
    os.environ["ECMWF_VAULT_TOKEN"] = "..."        # or ~/.ecmwf-vault/config

    from ecmwf_vault import value

    password = value("user_applications_and_services_team/cems_web/k8s-cems-test",
                     field="password").reveal()

What ``value()`` returns is a :class:`Secret`, never a ``str``: anything that merely
renders it — a log line, ``print``, an f-string — shows ``<Secret>``, while writing it
to a file, a stream, an environment variable or a child process argument list raises
``TypeError`` instead of succeeding by accident. ``reveal()`` is the one explicit way
to the plaintext, and
``Vault.memory_file()`` hands it to a child process through an inherited
descriptor with no file involved. That is a guard-rail against the accident, not a
sandbox: ``reveal()`` is right there, and ``os.write``, a C extension or another
process bypass it.

The token comes from ``ECMWF_VAULT_TOKEN`` or ``~/.ecmwf-vault/config`` (mode 600);
a call made with neither raises
:class:`VaultTokenMissingError` (a :class:`RuntimeError`) before any network use.
The secret is held in a sealed, anonymous Linux memory file and is never written
to a file, a log, an exception message or a child process argument list.

What this does *not* cover is documented in the README's threat model: the token
arrives in the environment — which a child process inherits — or lives in a
mode-600 file on disk, and the value a caller reveals is an ordinary Python
object. The guarantee is "this package never puts the secret on disk", not "the
secret is unreadable in a compromised process".
"""
from __future__ import annotations

from ._client import Vault, clear_cache, close, value
from ._errors import (
    InvalidSecretPathError,
    SecretFieldMissingError,
    SecretNotFoundError,
    SwapPolicyError,
    VaultConfigFileError,
    VaultError,
    VaultPermissionError,
    VaultResponseError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
    VaultUnavailableError,
)
from ._memory import MAX_SECRET, SecretMemoryFile
from ._secret import Secret

__version__ = "0.2.0"

__all__ = [
    "InvalidSecretPathError",
    "MAX_SECRET",
    "Secret",
    "SecretFieldMissingError",
    "SecretMemoryFile",
    "SecretNotFoundError",
    "SwapPolicyError",
    "Vault",
    "VaultConfigFileError",
    "VaultError",
    "VaultPermissionError",
    "VaultResponseError",
    "VaultTokenInvalidError",
    "VaultTokenMissingError",
    "VaultUnavailableError",
    "__version__",
    "clear_cache",
    "close",
    "value",
]
