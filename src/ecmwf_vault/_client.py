# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The Vault client: configuration, the process-wide default instance, caching
and the ``value()`` entry point.

It resolves the token at call time through :mod:`ecmwf_vault._config`, and holds no
credential of its own: the token is an argument to the calls that need it, never state on
the instance.
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
from ._paths import (
    CUBBYHOLE,
    build_cubbyhole_target,
    build_target,
    split_base_url,
    validate_mount,
    validate_path,
)
from ._policy import enforce, harden_process, resolve_harden, resolve_policy
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

# Put in place of a lookup's ``id`` when that field holds the token itself: the value is
# replaced rather than the key removed, so nothing is silently dropped from a report and the
# shape a caller parses does not change between token types.
WITHHELD_ID = "(withheld: this is the token itself)"
FIELD_MESSAGE = "the secret does not contain the requested field"
DECODE_MESSAGE = "the stored secret could not be read back"

# Cache key: which engine was asked, and the request target it built. The target names the
# endpoint, mount and path together, and the base URL is fixed per instance, so neither belongs
# in the key. The engine does, because a target cannot identify it: a KV read through the mount
# ``cubbyhole`` of path ``x``, and a cubbyhole read of path ``data/x``, are the same URL —
# ``/v1/cubbyhole/data/x`` — parsed by two different shape checks. A mount may be called
# anything, including ``cubbyhole``, so the discriminator is the engine and not the mount.
# Entries also record the digest of the token that produced them, so a different token is never
# served a value the previous token was authorized for.
_CacheKey = Tuple[str, str]

# The read engines, named for the response shape each parses.
_KV_ENGINE = "kv-v2"
_CUBBYHOLE_ENGINE = "cubbyhole"


class _Entry:
    """One cached secret: the sealed bytes, and the token that fetched them."""

    __slots__ = ("memory", "token_digest")

    def __init__(self, memory: SecretMemoryFile, token_digest: bytes) -> None:
        self.memory = memory
        self.token_digest = token_digest


def _read_token() -> str:
    """Return the Vault token, or raise.

    Resolved at call time through :mod:`ecmwf_vault._config`: a command if one is
    configured, then the token file. Never cached and never stored on the client, so
    replacing the token file — ``vault_login`` does exactly that — takes effect on the very
    next call.
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

        The token is resolved exactly once per call, so a command that unseals it is
        run once and not twice.
        """
        self._check_open()
        return self._value_with_token(path, _read_token(), field=field, cache=cache)

    def cubbyhole_read(self, path: str, *, field: Optional[str] = None,
                       cache: bool = True) -> Union[Dict[str, Secret], Secret]:
        """Read from the caller's own cubbyhole, with the same guarantees as :meth:`value`.

        A cubbyhole is scoped to the **token**, not to the account: only the token making the
        request can read it, its contents are deleted when that token expires or is revoked,
        and no policy widens it. A value stored here is therefore only as durable as the
        token in ``~/.ecmwf-vault/token``, and unreachable by any other caller — including
        another token belonging to the same person.

        There is no mount argument: the mount *is* ``cubbyhole``, and it has no ``data/``
        version layer, so the request is ``/v1/cubbyhole/<path>``.
        """
        self._check_open()
        return self._value_with_token(path, _read_token(), field=field, cache=cache,
                                      cubbyhole=True)

    def _check_open(self) -> None:
        """Refuse a call on a closed instance *before* anything else happens.

        This has to come before the token is resolved, and not only in ``_obtain``: a
        closed instance is going to fail whatever the token says, so resolving first
        would read a credential — and unsealing it runs a program — for a call that
        cannot succeed.

        The guarantee is about calls *made after* the close. A call already in flight
        when ``close()`` lands may still read the token file, because nothing here
        cancels work mid-flight — what this prevents is a call that starts on an
        instance which is already closed.
        """
        if self._closed:
            raise VaultError(CLOSED_MESSAGE)

    def _value_with_token(self, path: str, token: str, *, field: Optional[str] = None,
                          cache: bool = True,
                          cubbyhole: bool = False) -> Union[Dict[str, Secret], Secret]:
        """``value`` with the token already resolved.

        Separate so that a caller who had to resolve the token *before* this point —
        the module-level :func:`value`, which reports a bad token even when ``mount``
        would itself be rejected — does not make the command run a second time. A
        second run is not merely wasteful: a one-shot or rate-limited helper may
        already have consumed the credential by then.

        ``cubbyhole`` selects the engine; see :meth:`cubbyhole_read`.
        """
        memory = self._obtain(path, token=token, cache=cache, cubbyhole=cubbyhole)
        try:
            fields = _decode(memory.read())
        finally:
            memory.close()
        if field is None:
            return fields
        if not isinstance(field, str) or field not in fields:
            raise SecretFieldMissingError(FIELD_MESSAGE)
        return fields[field]

    def token_info(self) -> Dict[str, Any]:
        """The token's own metadata, as Vault reports it.

        Whatever ``auth/token/lookup-self`` returns is passed through unchanged — ``ttl``,
        ``creation_ttl``, ``expire_time``, ``issue_time``, ``renewable``, ``num_uses``,
        ``policies``, ``display_name``, ``accessor`` and anything else Vault chooses to
        include — so a field this package has never heard of still reaches the caller.

        Nothing secret is retained here: the answer is metadata *about* the token and no
        sealed memory file is created, so the swap policy — which exists because such a
        file can still be paged out — has nothing of its own to guard. Hardening is still
        applied, because the token itself is in this process's memory.

        One field is not passed through verbatim. Vault reports the token's ``id``, and for
        some token types that field *is* the token's value; when it matches the token this
        call used, it is replaced with :data:`WITHHELD_ID` rather than returned. This package
        does not hand a credential back as a plain string, for the same reason no secret is
        returned unwrapped — and the identifier you actually want is the ``accessor``, which
        is documented as safe to share and can be used for a lookup or a revocation without
        revealing the token. A masked ``id`` (a UUID, as Vault sends when it is not the token
        itself) is passed through untouched.

        The ``accessor`` is a reference to the token rather than a way to use it: looking a
        token up by accessor needs ``sudo``, so it identifies the token without being a
        credential for anything on its own.
        """
        self._check_open()
        if self.harden:
            harden_process()
        return self._lookup(_read_token())

    def _lookup(self, token: str) -> Dict[str, Any]:
        """Ask Vault about ``token``: the lookup behind :meth:`token_info`.

        Separate so that a token this instance did not resolve itself — the one a person has
        just typed and that has not been stored yet — can be checked without putting it
        anywhere first. The caller applies the host policy; the withholding below belongs to
        the answer rather than to where the token came from, so it happens here.
        """
        if self._context is None:
            self._context = _transport.create_context(self.ca_bundle)
        info = _transport.fetch_token_info(
            self.host, self.port, token, self.timeout, self._context)
        if info.get("id") == token:
            # Decided from what Vault actually sent, not from an assumption about which
            # token types do this: if the value *is* the token, it is a credential and it
            # does not leave here. Otherwise it is an identifier and is returned as sent.
            info["id"] = WITHHELD_ID
        return info

    def keys(self, path: str, *, cache: bool = True) -> Tuple[str, ...]:
        """Return the secret's field names, sorted, without handling values."""
        self._check_open()
        return tuple(sorted(self._obtain_and_decode(
            path, token=_read_token(), cache=cache)))

    def memory_file(self, path: str, *, cache: bool = True) -> SecretMemoryFile:
        """Return a caller-owned sealed memfd holding the secret's canonical bytes.

        The descriptor can be handed to a child process without a file
        (``subprocess(..., pass_fds=(memory.fd,))``). Closing it never disturbs
        this instance's cache, which keeps its own descriptor.
        """
        self._check_open()
        return self._obtain(path, token=_read_token(), cache=cache)

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

    def _obtain_and_decode(self, path: str, *, token: str, cache: bool,
                           cubbyhole: bool = False) -> Dict[str, Any]:
        memory = self._obtain(path, token=token, cache=cache, cubbyhole=cubbyhole)
        try:
            return _decode(memory.read())
        finally:
            memory.close()

    def _obtain(self, path: str, *, token: str, cache: bool,
                cubbyhole: bool = False) -> SecretMemoryFile:
        """Return a caller-owned :class:`SecretMemoryFile` for ``path``.

        The token arrives already resolved, so that one public call resolves it once:
        see :meth:`_value_with_token`. The host policy is checked next, then the path,
        and only then is anything fetched. A failure anywhere leaves the cache
        untouched.

        ``cubbyhole`` selects which of the two engines reads the path; everything after the
        target — caching, locking, sealing — is the same code. See :meth:`cubbyhole_read`.
        """
        if self._closed:
            raise VaultError(CLOSED_MESSAGE)
        enforce(self.swap_policy, self.harden)
        segments = validate_path(path)
        if cubbyhole:
            engine = _CUBBYHOLE_ENGINE
            target = build_cubbyhole_target(segments)
            fetch_fields = _transport.fetch_cubbyhole
        else:
            engine = _KV_ENGINE
            target = build_target(self.mount, segments)
            fetch_fields = _transport.fetch_secret
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        key: _CacheKey = (engine, target)
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
            memory = self._fetch_into_memory(target, token, fetch_fields)
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

    def _fetch_into_memory(self, target: str, token: str, fetch_fields) -> SecretMemoryFile:
        """Fetch one secret and seal its canonical bytes in a memfd."""
        # Checked before the request as well as inside the store, so a missing
        # capability is reported before the network call. Sealing itself can still
        # fail afterwards; it then aborts without storing or returning anything.
        require_support()
        if self._context is None:
            self._context = _transport.create_context(self.ca_bundle)
        fields = fetch_fields(self.host, self.port, target, token, self.timeout,
                              self._context)
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


def _check_module_open() -> None:
    """Refuse a module-level call on a closed module before any helper runs.

    Checked here as well as in :func:`_default_vault` so that ``close()`` does not run a
    command that may prompt for a passphrase for a call that cannot succeed. The token is
    still resolved before ``mount`` or ``base_url`` are judged, which is the documented
    order; only the already-closed case moves ahead of it. As in
    :meth:`Vault._check_open`, the guarantee covers calls made after the close, not calls
    already in flight.
    """
    with _default_lock:
        if _default_closed:
            raise VaultError(MODULE_CLOSED_MESSAGE)


def value(path: str, *, field: Optional[str] = None, mount: Optional[str] = None,
          cache: bool = True, base_url: Optional[str] = None) -> Union[Dict[str, Secret], Secret]:
    """Read one secret using a default instance.

    Returns a :class:`Secret` (or a mapping of them), never a ``str``: call
    ``reveal()`` when you actually want the value.

    The token is resolved before anything else, so a token that is in neither
    source — or is present but malformed — is reported even when ``mount`` or
    ``base_url`` would themselves be rejected. It is resolved exactly once: the
    already-resolved token is handed to the instance rather than looked up again,
    because a command that unseals it should run once per call and no more.
    """
    _check_module_open()
    token = _read_token()
    return _default_vault(mount, base_url)._value_with_token(
        path, token, field=field, cache=cache)


def cubbyhole_read(path: str, *, field: Optional[str] = None, cache: bool = True,
                    base_url: Optional[str] = None
                    ) -> Union[Dict[str, Secret], Secret]:
    """Read from the token's own cubbyhole using a default instance.

    See :meth:`Vault.cubbyhole_read` for what a cubbyhole is and why it is per-token. No mount
    is taken: the read always goes to ``/v1/cubbyhole/<path>``.
    """
    _check_module_open()
    token = _read_token()
    return _default_vault(None, base_url)._value_with_token(
        path, token, field=field, cache=cache, cubbyhole=True)


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
