# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The harness guard that stops a test connecting off loopback.

These tests exist because a guard nobody checks is worth nothing, and because a *test* of such
a guard has a particular trap: the moment the guard is wrong, the test doing the checking
starts sending the packet the guard was supposed to stop. Choosing an unroutable-looking
address does not solve that — documentation space is not guaranteed unroutable, and a name that
cannot resolve still reaches a resolver. This was demonstrated, not theorised: a broken version
of this harness completed a TCP connection to a live host.

So every attempt here runs behind :func:`_loopback_guard.block_network_layer`, which replaces
what the guard falls through to with a recorder that raises. A refusal test therefore fails *in
place of* reaching the network, whichever of the two controls breaks, and that is why some of
them name a live host on purpose.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from unittest import mock

import _fakes
import _loopback_guard
from ecmwf_vault import _client, cubbyhole_read

EXAMPLE = "madt/efas"
SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
DEAD_NAME = _loopback_guard.UNRESOLVABLE_HOST
DEAD_ADDRESS = _loopback_guard.UNROUTABLE_ADDRESS
# A real host, used only where the sandbox makes contacting it impossible. Refusing a name that
# exists is the case that matters; a made-up name would let a resolver's NXDOMAIN stand in for
# the guard having worked.
LIVE_NAME = "example.org"


class GuardTests(unittest.TestCase):
    # -- the assertion every attempted connection goes through -------------

    def assert_refused(self, action, expect_in=None):
        """Require the guard to refuse ``action``, with no packet able to leave either way.

        ``NetworkLayerReached`` is an ``assertRaises(AssertionError)`` would accept, so the
        type is checked as well: reaching the network layer is a failure even though it fails
        the same family of exception.
        """
        with _loopback_guard.block_network_layer() as reached:
            with self.assertRaises(AssertionError) as caught:
                action()
        self.assertNotIsInstance(caught.exception, _loopback_guard.NetworkLayerReached,
                                 "the guard let this through and only the sandbox stopped it")
        self.assertEqual(reached, [], "something reached the network layer")
        message = str(caught.exception)
        self.assertIn("not this machine", message)
        if expect_in is not None:
            self.assertIn(expect_in, message)
        return message

    def connect(self, address, timeout=2):
        def attempt():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(sock.close)
            sock.settimeout(timeout)
            sock.connect(address)
        return attempt

    # -- presence ----------------------------------------------------------

    def test_importing_the_fakes_installs_the_guard(self):
        # The install is a side effect of importing _fakes, which every network test does. If
        # that ever stops being true the guard is absent while looking present.
        self.assertTrue(_loopback_guard._installed)

    def test_the_entry_points_are_the_wrappers_not_the_stdlibs(self):
        # Identity, not behaviour: a test that only checks behaviour cannot tell a wrapper from
        # an absent one if the sandbox happens to cover for it.
        for name in ("connect", "connect_ex"):
            with self.subTest(entry_point=name):
                self.assertTrue(_loopback_guard._is_guard_wrapper(
                    getattr(socket.socket, name)))
        self.assertTrue(_loopback_guard._is_guard_wrapper(socket.getaddrinfo))

    # -- refusals, all behind the sandbox ----------------------------------

    def test_the_client_route_http_client_uses_is_refused(self):
        # http.client resolves through the patched getaddrinfo and connects through the patched
        # connect, and the refusal has to name the host rather than a resolved address.
        self.assert_refused(lambda: socket.create_connection((LIVE_NAME, 443), timeout=5),
                            expect_in=LIVE_NAME)

    def test_a_name_that_cannot_resolve_is_refused_before_the_resolver(self):
        for host in (DEAD_NAME, "ecmwf-vault-guard-2.invalid"):
            with self.subTest(host=host):
                self.assert_refused(lambda host=host: socket.getaddrinfo(host, 443),
                                    expect_in=host)

    def test_a_numeric_address_is_refused_without_being_resolved(self):
        # The other way out: an address that never names a host, so getaddrinfo is skipped.
        self.assert_refused(self.connect((DEAD_ADDRESS, 443)), expect_in=DEAD_ADDRESS)

    def test_connect_ex_is_refused_too(self):
        # connect_ex returns an errno instead of raising, so it needs its own check rather than
        # inheriting the one on connect; a caller that used it would otherwise slip past.
        def attempt():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(sock.close)
            sock.connect_ex((DEAD_ADDRESS, 443))
        self.assert_refused(attempt, expect_in=DEAD_ADDRESS)

    def test_a_host_spelled_as_bytes_is_refused_too(self):
        # socket takes bytes for a host in getaddrinfo and in connect, so a check written for
        # str only lets the same address through with a b"" in front of it. This was verified
        # against the patched entry points: bytes did sail past both, SYN included.
        for host in (LIVE_NAME.encode(), bytearray(LIVE_NAME.encode())):
            with self.subTest(host=host):
                self.assert_refused(lambda host=host: socket.getaddrinfo(host, 443))
        for address in ((DEAD_ADDRESS.encode(), 443), (bytearray(DEAD_ADDRESS.encode()), 443)):
            with self.subTest(address=address):
                self.assert_refused(self.connect(address))

    def test_an_unroutable_looking_target_is_still_refused_by_the_guard(self):
        # Belt and braces in the other direction: even a target chosen for being harmless is
        # stopped by the guard itself, not only by the sandbox behind it.
        for address in ((DEAD_ADDRESS, 443), (DEAD_NAME, 443), ("::ffff.198.51.100.7", 53)):
            with self.subTest(address=address):
                self.assert_refused(self.connect(address, timeout=1) if isinstance(
                    address[0], str) and ":" not in address[0]
                    else lambda address=address: socket.create_connection(address, timeout=1))

    # -- the predicate, which does no I/O and so needs no sandbox ----------

    def test_an_off_loopback_address_is_refused(self):
        for address in ((DEAD_NAME, 443), (DEAD_ADDRESS, 443), ("other.invalid", 80),
                        (LIVE_NAME, 443)):
            with self.subTest(address=address):
                with self.assertRaises(AssertionError) as caught:
                    _loopback_guard._refuse_address(address)
                self.assertIn(address[0], str(caught.exception))
                self.assertIn("_fakes.FakeVault", str(caught.exception))

    def test_loopback_addresses_are_allowed(self):
        for address in (("127.0.0.1", 8200), ("localhost", 8200), ("::1", 8200)):
            with self.subTest(address=address):
                _loopback_guard._refuse_address(address)

    def test_the_whole_loopback_range_is_allowed(self):
        # 127.0.0.0/8 is all loopback, and a guard that refused 127.0.0.53 would break real
        # services that bind there.
        for host in ("127.0.0.1", "127.0.0.53", "127.1.2.3", "::1", "localhost"):
            with self.subTest(host=host):
                _loopback_guard._refuse_address((host, 443), socket.AF_INET)
        for host in ("198.51.100.9", "0.0.0.0", "fe80::1"):
            with self.subTest(host=host):
                with self.assertRaises(AssertionError):
                    _loopback_guard._refuse_address((host, 443), socket.AF_INET)

    def test_undecodable_bytes_are_refused_not_waved_through(self):
        # A host that cannot be read as text is not thereby allowed: the failure mode that
        # matters is the guard declining to decide.
        for host in (b"\xff\xfe.invalid", b"\x00"):
            with self.subTest(host=host):
                with self.assertRaises(AssertionError):
                    _loopback_guard._refuse_host(host)

    def test_a_unix_socket_path_is_not_checked(self):
        # A unix address is a filesystem path, and libraries open those for reasons that have
        # nothing to do with Vault.
        for address in ("/run/foo.sock", "", None, ("127.0.0.1",)):
            with self.subTest(address=address):
                _loopback_guard._refuse_address(address, socket.AF_UNIX)

    def test_only_internet_sockets_are_checked(self):
        # Some families use a tuple address whose first element is not a host at all — an
        # interface name for AF_PACKET, a port id for AF_NETLINK. Checking those would refuse a
        # connection that cannot carry a Vault request, and a guard producing false failures is
        # a guard that gets deleted.
        for family in (socket.AF_UNIX, getattr(socket, "AF_PACKET", socket.AF_UNIX),
                       getattr(socket, "AF_NETLINK", socket.AF_UNIX)):
            for address in (("eth0", 0x0800), ("lo", 0x0800), (0, 0, 0, 0)):
                with self.subTest(family=family, address=address):
                    _loopback_guard._refuse_address(address, family)
        for family in (socket.AF_INET, socket.AF_INET6):
            with self.subTest(family=family):
                with self.assertRaises(AssertionError):
                    _loopback_guard._refuse_address((LIVE_NAME, 443), family)

    # -- the guard must not over-block -------------------------------------

    def test_loopback_still_works_afterwards(self):
        # The sandbox is undone on exit, or it would break every later test that talks to the
        # fake Vault. Checked by doing the thing rather than by inspecting the restore.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        with _loopback_guard.block_network_layer() as reached:
            pass
        client = socket.socket()
        self.addCleanup(client.close)
        client.connect(listener.getsockname())
        self.assertEqual(reached, [])

    def test_resolving_this_machine_is_allowed(self):
        # A blank host is a bind, and "localhost" is what a loopback server resolves to; both
        # must keep working or the guard blocks the suite it protects.
        self.assertTrue(socket.getaddrinfo("localhost", 8200))
        self.assertTrue(socket.getaddrinfo(None, 8200))

    def test_the_guard_does_not_break_the_fake_vault(self):
        fake = _fakes.FakeVault()
        self.addCleanup(fake.stop)
        fake.fields = {"password": "synthetic-value"}
        with _fakes.vault_environment(token="hvs.synthetic",
                                      ECMWF_VAULT_ADDR=fake.base_url,
                                      ECMWF_VAULT_CA_BUNDLE=fake.ca_bundle):
            self._use_this_fake()
            self.assertEqual(cubbyhole_read(EXAMPLE, field="password").reveal(),
                             "synthetic-value")
        self.assertEqual([request.path for request in fake.requests],
                         ["/v1/cubbyhole/" + EXAMPLE])

    # -- the two controls fail independently --------------------------------

    def test_the_sandbox_alone_stops_an_unguarded_call(self):
        # The property that makes the rest of this file safe: with the guard's predicates made
        # inert, an attempt still cannot leave the process. Without this, every refusal test
        # here would depend on the thing it is testing.
        with mock.patch.object(_loopback_guard, "_refuse_address", lambda *a, **k: None), \
                mock.patch.object(_loopback_guard, "_refuse_host", lambda *a, **k: None), \
                _loopback_guard.block_network_layer() as reached:
            with self.assertRaises(_loopback_guard.NetworkLayerReached):
                socket.create_connection((LIVE_NAME, 443), timeout=5)
        self.assertTrue(reached, "the sandbox recorded nothing, so it was not what stopped it")

    def test_the_guard_stops_it_before_the_sandbox_is_needed(self):
        # The matching half: with both in place, the refusal is the guard's and the sandbox
        # never sees the call. So a message naming the host comes from the guard, not from a
        # recorder.
        with _loopback_guard.block_network_layer() as reached:
            with self.assertRaises(AssertionError) as caught:
                socket.create_connection((LIVE_NAME, 443), timeout=5)
        self.assertNotIsInstance(caught.exception, _loopback_guard.NetworkLayerReached)
        self.assertEqual(reached, [])

    # -- the mistake the guard was written for ------------------------------

    def test_an_unpinned_address_is_refused_instead_of_reaching_the_vault(self):
        # A module-level read with no ECMWF_VAULT_ADDR falls back to the package's default
        # host. The default is redirected here so the test names a host this suite must never
        # contact, and the sandbox means a guard regression cannot reach even that one.
        with _fakes.vault_environment(token="hvs.synthetic"), \
                mock.patch.object(_client, "DEFAULT_ADDR", "https://" + LIVE_NAME):
            os.environ.pop("ECMWF_VAULT_ADDR", None)
            self._use_this_fake()
            self.assert_refused(lambda: cubbyhole_read(EXAMPLE), expect_in=LIVE_NAME)

    def _use_this_fake(self) -> None:
        """Start from an empty instance pool, so a pooled instance cannot answer instead.

        The pool is process-wide and keyed by (mount, base URL), and clearing the *secret*
        cache does not empty it — only ``close()`` does. So the pool is closed here, and the
        module-level API reopened for the duration of the test, with the patch undone only
        after the next ``close()``.
        """
        _client.close()
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        self.addCleanup(_client.close)


class SpawnedProcessTests(unittest.TestCase):
    """The guard reaching an interpreter the test spawns.

    The black-box suites run the commands as fresh interpreters, and a patch applied here says
    nothing about a process started there. Each probe installs the sandbox in the child
    *without* installing the guard, so a child whose startup installation is missing fails the
    test instead of putting a packet on the wire.
    """

    GUARD_STATE = ("import socket;"
                   "print('GUARDED' if getattr(socket.getaddrinfo, '__module__', '')"
                   " == '_loopback_guard' else 'UNGUARDED')")

    def child(self, python_path: str, program: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-c", program], capture_output=True, text=True,
                              timeout=60,
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                   "PYTHONPATH": python_path,
                                   "PYTHONDONTWRITEBYTECODE": "1",
                                   "HOME": os.environ.get("HOME", "/")})

    def test_a_child_on_the_guarded_path_is_guarded(self):
        result = self.child(_loopback_guard.child_python_path(), self.GUARD_STATE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "GUARDED")

    def test_a_child_on_the_plain_path_is_not(self):
        # The control that makes the assertion above about the helper rather than about how
        # Python starts up.
        result = self.child(SOURCE, self.GUARD_STATE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "UNGUARDED")

    def test_a_guarded_child_refuses_a_live_host_itself(self):
        # The startup installation, proven by behaviour: the child's own guard does the
        # refusing.
        result = self.child(_loopback_guard.child_python_path(),
                            _loopback_guard.child_sandbox_probe(LIVE_NAME))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn(LIVE_NAME, result.stdout)

    def test_an_unguarded_child_is_caught_by_the_sandbox_not_the_network(self):
        # The regression that matters: startup installation broken. The child must report
        # reaching the network layer, and must not have contacted the host it named.
        result = self.child(_loopback_guard.child_python_path(install_guard=False),
                            _loopback_guard.child_sandbox_probe(LIVE_NAME))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REACHED-NETWORK-LAYER", result.stdout)

    def test_a_childs_own_startup_code_and_the_guard_both_run(self):
        # Only the first sitecustomize on the path is imported, so a test needing startup code
        # of its own must not lose the guard — or lose its own code to the guard.
        directory = _loopback_guard.sitecustomize_dir("import os; os.VEB_PROBE = 'ran'")
        result = self.child(os.pathsep.join((directory, SOURCE)), self.GUARD_STATE)
        self.assertEqual(result.stdout.strip(), "GUARDED")
        probe = self.child(os.pathsep.join((directory, SOURCE)),
                           "import os; print(getattr(os, 'VEB_PROBE', 'missing'))")
        self.assertEqual(probe.stdout.strip(), "ran")


if __name__ == "__main__":
    unittest.main()
