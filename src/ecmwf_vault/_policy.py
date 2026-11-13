# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Host policy: refuse to hold secrets in memory on a swapping host, and harden
the process once so a crash cannot dump them.

Both behaviours are copied from the AgMon MCP executor
(``agmon/mcp-server/lease_registry/policy.py`` and ``agmon/mcp-server/utils.py``)
because it already carries the reasoning and the failure modes.
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Optional, Set

from ._errors import SwapPolicyError, VaultError

SWAP_REFUSE = "refuse"
SWAP_WARN = "warn"
SWAP_ALLOW = "allow"
SWAP_POLICIES = (SWAP_REFUSE, SWAP_WARN, SWAP_ALLOW)
DEFAULT_SWAP_POLICY = SWAP_REFUSE

SWAP_POLICY_ENV = "ECMWF_VAULT_SWAP_POLICY"
HARDEN_ENV = "ECMWF_VAULT_HARDEN"

SWAP_POLICY_MESSAGE = (
    "ECMWF_VAULT_SWAP_POLICY must be one of refuse, warn or allow"
)
HARDEN_MESSAGE = "ECMWF_VAULT_HARDEN must be 0 or 1"
SWAP_ACTIVE_MESSAGE = (
    "host swap is enabled; refusing to hold a Vault secret in memory"
)
SWAP_WARNING = (
    "ecmwf-vault: host swap is enabled; the secret may be written to swap"
)

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

_hardened = False
_hardening_lock = threading.Lock()
_warned: Set[str] = set()
_warning_lock = threading.Lock()


def swap_is_active() -> bool:
    """Report whether the host has active swap.

    A host where swap cannot be proven off is reported as swapping, so the
    default policy fails closed. ``/proc/swaps`` has exactly one line (its
    header) when no swap area is in use.
    """
    try:
        with open("/proc/swaps", encoding="ascii") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return True
    return len(lines) != 1


def resolve_policy(explicit: Optional[str] = None) -> str:
    """Resolve the swap policy from an argument, the environment or the default."""
    if explicit is None:
        explicit = os.environ.get(SWAP_POLICY_ENV, DEFAULT_SWAP_POLICY)
    if not isinstance(explicit, str) or explicit not in SWAP_POLICIES:
        raise SwapPolicyError(SWAP_POLICY_MESSAGE)
    return explicit


def resolve_harden(explicit: Optional[bool] = None) -> bool:
    """Resolve whether to harden the process, from an argument or the environment."""
    if explicit is None:
        raw = os.environ.get(HARDEN_ENV, "1")
        if not isinstance(raw, str) or raw.strip().lower() not in _TRUE + _FALSE:
            raise VaultError(HARDEN_MESSAGE)
        return raw.strip().lower() in _TRUE
    if type(explicit) is not bool:
        raise VaultError(HARDEN_MESSAGE)
    return explicit


def warn_once(key: str, message: str) -> None:
    """Write one fixed message to stderr, once per key for this process."""
    with _warning_lock:
        if key in _warned:
            return
        _warned.add(key)
    print(message, file=sys.stderr)


def enforce(policy: str, harden: bool) -> None:
    """Apply the host policy before any secret is read.

    The swap check runs on every call, not just the first: swap must stay off
    for the whole life of the process, and once enabled it could already have
    paged out memory this process holds. Hardening runs once.
    """
    if swap_is_active():
        if policy == SWAP_REFUSE:
            raise SwapPolicyError(SWAP_ACTIVE_MESSAGE)
        warn_once("swap", SWAP_WARNING)
    if harden:
        harden_process()


def harden_process() -> None:
    """Disable core dumps and make the process non-dumpable, once."""
    global _hardened
    if _hardened:
        return
    with _hardening_lock:
        if _hardened:
            return
        harden_now()
        _hardened = True


def harden_now() -> None:
    """Perform the hardening calls. Raises :class:`VaultError` on failure."""
    try:
        import ctypes
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        raise VaultError("ecmwf-vault requires POSIX resource limits") from None
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        raise VaultError("could not disable core dumps") from None
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise VaultError("could not disable process dumps")
