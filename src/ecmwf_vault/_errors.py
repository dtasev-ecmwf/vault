# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Exception types raised by :mod:`ecmwf_vault`.

Every error is a :class:`RuntimeError`, so a caller that only wants the
documented "it RuntimeErrors" behaviour can catch the whole family with one
``except RuntimeError``. The subclasses exist so a caller who cares can be more
precise.

No message ever contains a secret value or the Vault token.
"""
from __future__ import annotations


class VaultError(RuntimeError):
    """Base class for every error this package raises."""


class VaultTokenMissingError(VaultError):
    """No token source has a token: no command, and nothing usable in the token file."""


class VaultTokenInvalidError(VaultError):
    """The token holds characters that cannot go in an HTTP header."""


class SwapPolicyError(VaultError):
    """The host has swap enabled and the swap policy forbids that."""


class InvalidSecretPathError(VaultError):
    """The Vault mount or secret path is not in the permitted shape."""


class SecretNotFoundError(VaultError):
    """Vault has no readable version of the requested secret."""


class VaultPermissionError(VaultError):
    """Vault refused the request: bad, expired or under-privileged token."""


class VaultUnavailableError(VaultError):
    """Vault could not be reached, or answered 429 or an unexpected status."""


class VaultResponseError(VaultError):
    """Vault answered with a body this package refuses to interpret."""


class VaultTokenFileError(VaultError):
    """The Vault token file is missing, unreadable, unsafe or oversized."""


class SecretFieldMissingError(VaultError):
    """The requested field is not present in the secret."""
