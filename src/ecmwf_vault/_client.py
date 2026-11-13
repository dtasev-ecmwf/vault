"""The Vault client: configuration, the process-wide default instance, caching
and the ``value()`` entry point.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Dict, Optional, Tuple, Union

from . import _config, _transport
from ._errors import (
    SecretFieldMissingError,
    VaultError,
    VaultResponseError,
)
from ._memory import SecretMemoryFile, require_support
from ._paths import build_target, split_base_url, validate_mount, validate_path
from ._policy import enforce, resolve_harden, resolve_policy
from ._secret import Secret

ADDR_ENV = "ECMWF_VAULT_ADDR"
MOUNT_ENV = "ECMWF_VAULT_MOUNT"
CA_BUNDLE_ENV = "ECMWF_VAULT_CA_BUNDLE"
TIMEOUT_ENV = "ECMWF_VAULT_TIMEOUT"

DEFAULT_ADDR = "https://secrets.ecmwf.int"
DEFAULT_MOUNT = "groups"
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 300.0

TIMEOUT_MESSAGE = "ECMWF_VAULT_TIMEOUT must be a number of seconds"
TIMEOUT_RANGE_MESSAGE = "the Vault timeout must be more than 0 and at most 300 seconds"
CLOSED_MESSAGE = "this Vault instance is closed"
FIELD_MESSAGE = "the secret does not contain the requested field"
DECODE_MESSAGE = "the stored secret could not be read back"

# Cache key: (base URL, mount, path). Entries also record the digest of the
# token that produced them, so a different token can never be served a value
# the previous token was authorized for.
_CacheKey = Tuple[str, str, str]


class _Entry:
    """One cached secret: the sealed bytes, and the token that fetched them."""

    __slots__ = ("memory", "token_digest")

    def __init__(self, memory: SecretMemoryFile, token_digest: bytes) -> None:
        self.memory = memory
        self.token_digest = token_digest


def _read_token() -> str:
    """Return the Vault token, or raise.

    Resolved at call time through :mod:`ecmwf_vault._config`: the environment
    first, then a private config file. Never cached and never stored on the
    client, so ``os.environ.pop`` — or replacing the config file — takes effect on
    the very next call.
    """
    return _config.resolve_token()


def _resolve_timeout(explicit: Optional[float]) -> float:
    raw: Any = explicit if explicit is not None else os.environ.get(TIMEOUT_ENV)
    if raw is None:
        return DEFAULT_TIMEOUT
    if type(raw) is bool or not isinstance(raw, (int, float, str)):
        raise VaultError(TIMEOUT_MESSAGE)
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        raise VaultError(TIMEOUT_MESSAGE) from None
    if not 0 < seconds <= MAX_TIMEOUT:
        raise VaultError(TIMEOUT_RANGE_MESSAGE)
    return seconds


def _decode(raw: bytes) -> Dict[str, Secret]:
    """Read back the canonical payload written by this package.

    Every value is wrapped in a :class:`Secret`, so nothing this package returns
    can be used as a string without asking for it.
    """
    try:
        fields = json.loads(raw)
    except ValueError:
        raise VaultResponseError(DECODE_MESSAGE) from None
    if not isinstance(fields, dict):
        raise VaultResponseError(DECODE_MESSAGE)
    return {key: Secret(value) for key, value in fields.items()}


class Vault:
    """One configured Vault client with its own cache.

    Configuration other than the token is read from the environment when the
    instance is constructed, so pass an argument to override it. Call
    :meth:`close` when finished; instances also work as context managers.
    """

    def __init__(self, *, base_url: Optional[str] = None, mount: Optional[str] = None,
                 timeout: Optional[float] = None, swap_policy: Optional[str] = None,
                 harden: Optional[bool] = None,
                 ca_bundle: Optional[str] = None) -> None:
        self.base_url = base_url if base_url is not None else os.environ.get(
            ADDR_ENV, DEFAULT_ADDR)
        self.mount = validate_mount(
            mount if mount is not None else os.environ.get(MOUNT_ENV, DEFAULT_MOUNT))
        self.host, self.port = split_base_url(self.base_url)
        self.timeout = _resolve_timeout(timeout)
        self.swap_policy = resolve_policy(swap_policy)
        self.harden = resolve_harden(harden)
        self.ca_bundle = ca_bundle if ca_bundle is not None else (
            os.environ.get(CA_BUNDLE_ENV) or None)
        self._entries: Dict[_CacheKey, _Entry] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._context = None

    # -- public API -------------------------------------------------------

    def value(self, path: str, *, field: Optional[str] = None,
              cache: bool = True) -> Union[Dict[str, Secret], Secret]:
        """Return the secret's fields, or one field of it.

        Every value is a :class:`Secret`, never a ``str``: reaching the plaintext
        takes an explicit ``reveal()``. Anything that merely renders a value — a log
        line, an f-string, ``print`` — shows ``<Secret>``, while writing it to a
        file, a stream, an environment variable or a child process argument list
        raises instead. With
        ``field`` unset the whole field mapping is returned, each value wrapped the
        same way. With ``cache=False`` the secret is fetched and not retained.
        """
        memory = self._obtain(path, cache=cache)
        try:
            fields = _decode(memory.read())
        finally:
            memory.close()
        if field is None:
            return fields
        if not isinstance(field, str) or field not in fields:
            raise SecretFieldMissingError(FIELD_MESSAGE)
        return fields[field]

    def keys(self, path: str, *, cache: bool = True) -> Tuple[str, ...]:
        """Return the secret's field names, sorted, without handling values."""
        return tuple(sorted(self._obtain_and_decode(path, cache=cache)))

    def memory_file(self, path: str, *, cache: bool = True) -> SecretMemoryFile:
        """Return a caller-owned sealed memfd holding the secret's canonical bytes.

        The descriptor can be handed to a child process without a file
        (``subprocess(..., pass_fds=(memory.fd,))``). Closing it never disturbs
        this instance's cache, which keeps its own descriptor.
        """
        return self._obtain(path, cache=cache)

    def clear_cache(self) -> None:
        """Close and forget every cached secret."""
        with self._lock:
            for entry in self._entries.values():
                entry.memory.close()
            self._entries.clear()

    def close(self) -> None:
        """Drop the cache and refuse further use of this instance."""
        with self._lock:
            for entry in self._entries.values():
                entry.memory.close()
            self._entries.clear()
            self._closed = True

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return ("<Vault base_url=%r mount=%r swap_policy=%r harden=%r>"
                % (self.base_url, self.mount, self.swap_policy, self.harden))

    # -- internals --------------------------------------------------------

    def _obtain_and_decode(self, path: str, *, cache: bool) -> Dict[str, Any]:
        memory = self._obtain(path, cache=cache)
        try:
            return _decode(memory.read())
        finally:
            memory.close()

    def _obtain(self, path: str, *, cache: bool) -> SecretMemoryFile:
        """Return a caller-owned :class:`SecretMemoryFile` for ``path``.

        The token and the host policy are checked first, then the path, and
        only then is anything fetched. A failure anywhere leaves the cache
        untouched.
        """
        if self._closed:
            raise VaultError(CLOSED_MESSAGE)
        token = _read_token()
        enforce(self.swap_policy, self.harden)
        segments = validate_path(path)
        target = build_target(self.mount, segments)
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        key: _CacheKey = (self.base_url, self.mount, "/".join(segments))
        # One in-flight fetch per instance: the lock is held across the request
        # so concurrent callers cannot duplicate a fetch. Callers who want
        # concurrency use separate instances.
        with self._lock:
            if self._closed:
                raise VaultError(CLOSED_MESSAGE)
            if cache:
                entry = self._live_entry(key, digest)
                if entry is not None:
                    return entry.memory.duplicate()
            # cache=False always fetches, even when an entry is already warm:
            # the point of the flag is to observe the current server state
            # (rotation, revocation, a permission change) rather than what this
            # process saw earlier.
            memory = self._fetch_into_memory(target, token)
            if not cache:
                return memory
            self._entries[key] = _Entry(memory, digest)
            return memory.duplicate()

    def _live_entry(self, key: _CacheKey, digest: bytes) -> Optional[_Entry]:
        """Return the cache entry for ``key`` if it belongs to this token.

        Caller must hold the lock. An entry fetched with a different token is
        closed and dropped rather than served: the current token has not been
        authorized for that value.
        """
        entry = self._entries.get(key)
        if entry is not None and entry.token_digest != digest:
            del self._entries[key]
            entry.memory.close()
            return None
        return entry

    def _fetch_into_memory(self, target: str, token: str) -> SecretMemoryFile:
        """Fetch one secret and seal its canonical bytes in a memfd."""
        # Checked before the request as well as inside the store, so a missing
        # capability is reported before the network call. Sealing itself can still
        # fail afterwards; it then aborts without storing or returning anything.
        require_support()
        if self._context is None:
            self._context = _transport.create_context(self.ca_bundle)
        fields = _transport.fetch_secret(
            self.host, self.port, target, token, self.timeout, self._context)
        payload = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
        return SecretMemoryFile(payload)


# -- the process-wide default instances ----------------------------------
#
# One default Vault per (base URL, mount) pair, so the module-level helpers
# cache exactly like a hand-built instance does. The pair is part of the key
# because a short-lived throwaway instance would silently defeat caching for
# callers who pass an override. The pool is bounded and least-recently-used: a
# script that walks many mounts must not accumulate instances, each holding a
# TLS context.

MAX_DEFAULT_INSTANCES = 8
MODULE_CLOSED_MESSAGE = (
    "ecmwf_vault.close() has been called; construct a Vault to read a secret again")

_default_lock = threading.Lock()
_defaults: Dict[Tuple[Optional[str], Optional[str]], Vault] = {}
_default_closed = False


def _default_vault(mount: Optional[str], base_url: Optional[str]) -> Vault:
    key = (base_url, mount)
    with _default_lock:
        if _default_closed:
            raise VaultError(MODULE_CLOSED_MESSAGE)
        instance = _defaults.pop(key, None)
        if instance is None:
            instance = Vault(mount=mount, base_url=base_url)
        _defaults[key] = instance  # re-inserting makes this the most recent
        while len(_defaults) > MAX_DEFAULT_INSTANCES:
            # Drop the pool's reference rather than closing the instance:
            # another thread may already be inside a call on it, and closing it
            # would make that call fail for no reason the caller could see. The
            # instance and its sealed descriptors go when the last reference
            # does, and `SecretMemoryFile` closes its descriptor on collection.
            _defaults.pop(next(iter(_defaults)))
        return instance


def value(path: str, *, field: Optional[str] = None, mount: Optional[str] = None,
          cache: bool = True, base_url: Optional[str] = None) -> Union[Dict[str, Secret], Secret]:
    """Read one secret using a default instance.

    Returns a :class:`Secret` (or a mapping of them), never a ``str``: call
    ``reveal()`` when you actually want the value.

    The token is resolved before anything else, so a token that is in neither
    source — or is present but malformed — is reported even when ``mount`` or
    ``base_url`` would themselves be rejected.
    """
    _read_token()
    return _default_vault(mount, base_url).value(path, field=field, cache=cache)


def clear_cache() -> None:
    """Close and forget every secret cached by the default instances."""
    with _default_lock:
        instances = list(_defaults.values())
    for instance in instances:
        instance.clear_cache()


def close() -> None:
    """Close every default instance and refuse further module-level reads.

    Terminal, like closing a :class:`Vault`: a caller who has said "I am done
    with secrets" must not have one silently re-fetched. Construct a ``Vault``
    for a new lifetime.
    """
    global _defaults, _default_closed
    with _default_lock:
        instances, _defaults = list(_defaults.values()), {}
        _default_closed = True
    for instance in instances:
        instance.close()
