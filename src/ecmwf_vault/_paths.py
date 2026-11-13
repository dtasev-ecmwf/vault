# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Validation of the Vault base URL, mount and secret path, and request-target
construction.

The secret path is caller-supplied and ends up in an HTTPS request line, so it
is validated against one strict shape before any network use and then quoted.
The shape admits no traversal segment (``.``/``..``), no empty segment, no
percent-encoding, no whitespace and no control character, so the validated
value cannot change the request target, add a query or smuggle a fragment.
Because the permitted alphabet is pure ASCII, the length limit is the same in
characters and in bytes; the check uses characters so a hostile path can never
make this module raise an encoding error that quotes it.
"""
from __future__ import annotations

import re
from typing import Tuple
from urllib.parse import quote, urlsplit

from ._errors import InvalidSecretPathError, VaultError

MAX_PATH_BYTES = 512
MAX_MOUNT = 64

_SEGMENT = re.compile(r"[A-Za-z0-9._@+-]+")
_EMPTY_SEGMENTS = ("", ".", "..")


def validate_mount(mount: object) -> str:
    """Return the mount if it is one permitted path segment."""
    if (not isinstance(mount, str) or not 1 <= len(mount) <= MAX_MOUNT
            or mount in _EMPTY_SEGMENTS or not _SEGMENT.fullmatch(mount)):
        raise InvalidSecretPathError("invalid Vault mount name")
    return mount


def validate_path(path: object) -> Tuple[str, ...]:
    """Return the path segments, or raise if the path is not permitted."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_BYTES:
        raise InvalidSecretPathError("invalid Vault secret path")
    segments = path.split("/")
    for segment in segments:
        if segment in _EMPTY_SEGMENTS or not _SEGMENT.fullmatch(segment):
            raise InvalidSecretPathError("invalid Vault secret path")
    return tuple(segments)


def build_target(mount: str, segments: Tuple[str, ...]) -> str:
    """Build the KV v2 read target for a validated mount and path."""
    quoted = [quote(segment, safe="") for segment in segments]
    return "/v1/" + quote(mount, safe="") + "/data/" + "/".join(quoted)


def split_base_url(base_url: object) -> Tuple[str, int]:
    """Return ``(host, port)`` for an https base URL, or raise.

    Only ``https`` is accepted: the request carries a Vault token in a header,
    so a plaintext transport would expose it. The URL may not carry userinfo,
    a query, a fragment or a path.
    """
    if not isinstance(base_url, str) or not base_url:
        raise VaultError("the Vault base URL must be a string")
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise VaultError("the Vault base URL must use https")
    if not parts.hostname or parts.username or parts.password:
        raise VaultError("invalid Vault base URL")
    if not parts.hostname.isascii():
        # A non-ASCII host would be encoded to IDNA further down and can throw a
        # UnicodeError that names the host; refuse it here with a fixed message.
        raise VaultError("the Vault base URL host must be ASCII")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise VaultError("invalid Vault base URL")
    try:
        port = parts.port or 443
    except ValueError:
        raise VaultError("invalid Vault base URL port") from None
    return parts.hostname, port
