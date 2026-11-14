# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""A test-harness guard: nothing in this suite may connect off loopback.

Every network test talks to :class:`tests._fakes.FakeVault` on ``127.0.0.1``. A test that
forgets to pin ``ECMWF_VAULT_ADDR`` falls back to the package's default address and sends a
real request, carrying its fixture's token, to the production Vault. That has happened; it is
why this file exists.

With the guard installed, such a connection is an ordinary test failure naming the address
instead of a request nobody asked for.

Three entry points are checked, because they are three ways out:

* ``socket.getaddrinfo``, how a *name* reaches the network. Checking it here means the refusal
  names the host a test asked for rather than an address, and that no DNS lookup happens;
* ``socket.socket.connect`` and ``connect_ex``, which a caller passing a numeric address never
  routes through ``getaddrinfo``. ``connect_ex`` returns an errno instead of raising, so it
  needs its own check rather than sharing one.

``socket.create_connection`` is deliberately not wrapped: it resolves through the first and
connects through the second, so a check there could not fail without one of these failing too.

The patch is process-local, and the commands under test also run as fresh interpreters, so
:func:`child_python_path` arranges for a spawned interpreter to install it at startup too.
"""
from __future__ import annotations

import atexit
import contextlib
import ipaddress
import os
import shutil
import socket
import sys
import tempfile
from typing import Any, List, Optional

TESTS_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# A name and an address a test may aim at when it means to be refused: 192.0.2.0/24 is
# documentation space (RFC 5737) and a ``.invalid`` name cannot resolve (RFC 6761). These are
# a convenience for reading a failure, not a safety property — see block_network_layer().
UNRESOLVABLE_HOST = "ecmwf-vault-guard.invalid"
UNROUTABLE_ADDRESS = "192.0.2.1"

# The names this machine answers to. Bare ``127.0.0.1`` is not the whole loopback range, so
# numeric forms are decided by ipaddress as well, below.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Only Internet sockets are checked. Some other families use a tuple address whose first
# element is not a host — an interface name for AF_PACKET, a port id for AF_NETLINK — and a
# guard that refused those would be deleted rather than trusted.
_CHECKED_FAMILIES = frozenset({socket.AF_INET, socket.AF_INET6})

_installed = False

# The implementations the wrappers fall through to, as module-level names looked up on every
# call. That indirection is what lets a test replace the thing that would touch the network
# and check the guard stopped it first. Choosing an unroutable-looking address is not that
# control, and a broken version of this harness proved it by completing a TCP connection to a
# live host. With these replaced, a broken guard cannot emit a packet.
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def _host_text(value: Any) -> Optional[str]:
    """The host a byte string spells, so bytes cannot slip past a check written for text.

    ``socket`` takes ``bytes`` for a host in ``getaddrinfo`` and in ``connect``, so a check
    written only for text lets the same unpinned host through with a ``b`` in front of it.
    Undecodable bytes come back as replacement text, never in the loopback set, so an
    unreadable spelling is refused rather than waved through.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("ascii", "replace")
    return None


def _is_loopback_host(host: str) -> bool:
    """Whether this host text names this machine."""
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _refuse_address(address: Any, family: Any = None) -> None:
    """Raise unless this is an address a test is allowed to talk to."""
    if family is not None and family not in _CHECKED_FAMILIES:
        return
    if not isinstance(address, tuple) or not address:
        return
    host = _host_text(address[0])
    if host is not None and not _is_loopback_host(host):
        raise AssertionError(_message(host))


def _refuse_host(host: Any) -> None:
    """Raise unless a name being resolved belongs to this machine.

    A blank host is a bind, not a connection: ``getaddrinfo(None, port)`` is how a server
    listens on every address, which creates no traffic of its own.
    """
    text = _host_text(host)
    if text and not _is_loopback_host(text):
        raise AssertionError(_message(text))


def _message(host: str) -> str:
    return ("a test tried to reach %r, which is not this machine. Point it at "
            "_fakes.FakeVault: an unpinned ECMWF_VAULT_ADDR falls back to the package's "
            "default host, which is the real Vault" % host)


def install_socket_guard() -> None:
    """Check name resolution and every Internet connection. Idempotent, never undone.

    The wrappers look their fall-through up as a module global on each call rather than closing
    over it, which is what lets :func:`block_network_layer` make a broken guard unreachable
    rather than unreachable-looking.
    """
    global _installed
    if _installed:
        return
    _installed = True

    def connect(self: socket.socket, address: Any) -> None:
        _refuse_address(address, self.family)
        return _real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        _refuse_address(address, self.family)
        return _real_connect_ex(self, address)

    def getaddrinfo(host: Any, port: Any, *args: Any, **keywords: Any):
        _refuse_host(host)
        return _real_getaddrinfo(host, port, *args, **keywords)

    socket.socket.connect = connect                     # type: ignore[assignment]
    socket.socket.connect_ex = connect_ex               # type: ignore[assignment]
    socket.getaddrinfo = getaddrinfo                    # type: ignore[assignment]


class NetworkLayerReached(AssertionError):
    """Code under test reached the call the guard was supposed to stop.

    Raised by the replacements :func:`block_network_layer` installs. It is an
    ``AssertionError`` so a fall-through fails the test that caused it instead of performing
    the I/O — which means a test asserting on refusals must check the type, not just the
    family.
    """


def _is_guard_wrapper(function: Any) -> bool:
    """Whether this entry point is one of this module's wrappers, rather than the stdlib's."""
    return getattr(function, "__module__", None) == __name__


@contextlib.contextmanager
def block_network_layer():
    """Make it impossible for the code inside to put a packet on the wire.

    Every test that checks a *refusal* goes through this. Without it, the test's own failure
    mode is the packet the guard exists to stop: at the moment the guard is wrong, the test
    starts doing network I/O. No choice of target fixes that, so this removes the reach
    instead.

    The guard's wrappers stay installed and this replaces what they fall *through* to. Where no
    guard is installed there is no fall-through to sit under, so the recorder goes onto the
    entry point itself. Either way nothing leaves the process, and the exception says which
    happened.

    Yields the calls that reached the network layer, for a test to assert on. Everything is
    restored on exit: leaving the floor in place would break later tests that legitimately
    connect to the fake Vault on loopback.
    """
    global _real_connect, _real_connect_ex, _real_getaddrinfo
    reached: List[str] = []

    def refused(name: str):
        def call(*args: Any, **keywords: Any):
            reached.append("%s%r" % (name, args[-1:]))
            raise NetworkLayerReached(
                "code under test reached the real %s with %r; nothing was sent, but the guard "
                "was expected to stop it before the network layer saw the address"
                % (name, args[-1:]))
        return call

    replacements = {
        "_real_connect": refused("connect"),
        "_real_connect_ex": refused("connect_ex"),
        "_real_getaddrinfo": refused("getaddrinfo"),
    }
    this_module = sys.modules[__name__]
    targets = [(this_module, name, replacement) for name, replacement in replacements.items()]
    if not _is_guard_wrapper(socket.socket.connect):
        targets.append((socket.socket, "connect", replacements["_real_connect"]))
    if not _is_guard_wrapper(socket.socket.connect_ex):
        targets.append((socket.socket, "connect_ex", replacements["_real_connect_ex"]))
    if not _is_guard_wrapper(socket.getaddrinfo):
        targets.append((socket, "getaddrinfo", replacements["_real_getaddrinfo"]))

    saved = [(owner, name, getattr(owner, name)) for owner, name, _ in targets]
    try:
        for owner, name, replacement in targets:
            setattr(owner, name, replacement)
        yield reached
    finally:
        for owner, name, original in saved:
            setattr(owner, name, original)


def child_sandbox_probe(target: str, timeout: float = 5) -> str:
    """A ``python -c`` program that tries to reach ``target`` inside a child's sandbox.

    It prints one of three things and never raises. ``REFUSED`` with the guard's wording means
    the child's startup installation worked. ``REACHED-NETWORK-LAYER`` with the recorded calls
    means it did not, and that a packet would have gone out. ``CONNECTED`` cannot happen: the
    sandbox goes in before the attempt, unconditionally.

    The probe deliberately does *not* install the guard itself: doing that would let the test
    pass by repairing the very startup regression it exists to catch.
    """
    return (
        "import socket\n"
        "import _loopback_guard as g\n"
        "with g.block_network_layer() as reached:\n"
        "    try:\n"
        "        socket.create_connection((%r, 443), timeout=%s)\n"
        "        print('CONNECTED')\n"
        "    except g.NetworkLayerReached:\n"
        "        print('REACHED-NETWORK-LAYER', reached)\n"
        "    except AssertionError as error:\n"
        "        print('REFUSED', error)\n" % (target, timeout))


def sitecustomize_dir(startup_source: str = "") -> str:
    """A directory whose ``sitecustomize`` runs ``startup_source``, then installs the guard.

    CPython imports the *first* ``sitecustomize`` on the path and no others, so a test needing
    startup code of its own — taking ``os.memfd_create`` away, the way a conda-forge build
    lacks it — cannot simply prepend a directory and keep the guard. Both go in one file here,
    in the order that makes both true.
    """
    directory = tempfile.mkdtemp(prefix="ecmwf-vault-guard-")
    atexit.register(shutil.rmtree, directory, True)
    source = startup_source + ("\n" if startup_source else "") + (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "import _loopback_guard\n"
        "_loopback_guard.install_socket_guard()\n" % TESTS_DIRECTORY)
    with open(os.path.join(directory, "sitecustomize.py"), "w", encoding="utf-8") as handle:
        handle.write(source)
    return directory


def child_python_path(*entries: str, install_guard: bool = True) -> str:
    """A ``PYTHONPATH`` for a spawned interpreter, with the guard installed at its startup.

    Patching ``socket`` here says nothing about a process the test spawns, and the commands
    under test run as fresh interpreters — which is how an unpinned address in a black-box test
    would still reach production.

    ``install_guard=False`` leaves the guard importable but not installed: how a test simulates
    the startup installation having gone missing, without disabling anything it is checking.
    """
    if not install_guard:
        return os.pathsep.join((TESTS_DIRECTORY,) + entries)
    return os.pathsep.join((sitecustomize_dir(),) + entries)
