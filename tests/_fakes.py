# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Offline test helpers: a loopback HTTPS server and a throwaway TLS identity.

Nothing here ships. The certificate is generated at test setup with the
``openssl`` command line into a temporary directory, so no key material is
committed. No test contacts ``secrets.ecmwf.int`` or any host other than
``127.0.0.1``.
"""
from __future__ import annotations

import atexit
import contextlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock


# Vault's own cubbyhole endpoint prefix, spelled out here rather than imported from
# ``ecmwf_vault._paths``: this is what HashiCorp's server does, not what this package chooses,
# and the fake below decides a response *shape* from it.
CUBBYHOLE_TARGET_PREFIX = "/v1/cubbyhole/"


class RecordedRequest:
    """One request the fake Vault received."""

    def __init__(self, method: str, path: str, headers: Dict[str, str]) -> None:
        self.method = method
        self.path = path
        self.headers = headers

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "RecordedRequest(%r, %r)" % (self.method, self.path)


def make_tls_identity(directory: str) -> Tuple[str, str]:
    """Write a self-signed certificate and key for ``127.0.0.1``.

    The certificate is also used as the CA bundle in most tests, so it carries
    both CA and server extensions.
    """
    return _self_signed(directory, "cert", "127.0.0.1", _SERVER_AND_CA_EXTENSIONS)


_identity_lock = threading.Lock()
_identity: Optional[Tuple[str, str]] = None


def shared_tls_identity() -> Tuple[str, str]:
    """One throwaway TLS identity per test process (generating one is slow)."""
    global _identity
    with _identity_lock:
        if _identity is None:
            directory = tempfile.mkdtemp(prefix="ecmwf-vault-test-identity-")
            atexit.register(shutil.rmtree, directory, True)
            _identity = make_tls_identity(directory)
        return _identity


_absent_directory: Optional[str] = None


SEALED_TOKEN = "hvs.synthetic-sealed-token"


def absent_home() -> str:
    """An empty home directory, so the default token path does not exist.

    Tests point ``HOME`` here so the suite cannot start reading (or failing on) the
    token file of whoever is running it, and so "no token file configured" is a real
    state rather than "a named file is missing".
    """
    global _absent_directory
    with _identity_lock:
        if _absent_directory is None:
            _absent_directory = tempfile.mkdtemp(prefix="ecmwf-vault-absent-")
            atexit.register(shutil.rmtree, _absent_directory, True)
        return _absent_directory


def absent_token_file_path() -> str:
    """A token-file path that never exists, for tests that name a missing file."""
    return os.path.join(absent_home(), "no-such-token-file")


def revealed(mapping: Any) -> Dict[str, Any]:
    """Reveal a field mapping for comparison, and check it really is wrapped.

    Values come back as :class:`ecmwf_vault.Secret`, which compares equal to the
    underlying value, so asserting through here keeps a test from passing merely
    because the wrapper compares equal. It also fails if a value is not a
    ``Secret`` at all — which would mean the test had stopped checking the wrapper
    — or if revealing one yields another ``Secret``, which would let a
    double-wrapped value hide the same way.
    """
    from ecmwf_vault import Secret

    values: Dict[str, Any] = {}
    for key, value in mapping.items():
        if not isinstance(value, Secret):
            raise AssertionError(
                "%r is not a Secret, so this assertion no longer checks the "
                "wrapper" % (key,))
        inner = value.reveal()
        if isinstance(inner, Secret):
            raise AssertionError("%r reveals another Secret" % (key,))
        values[key] = inner
    return values


def write_bytes(payload: bytes, mode: int = 0o600, directory: Optional[str] = None,
                name: str = "token") -> str:
    """Write a file with an explicit mode, and return its path."""
    directory = directory or tempfile.mkdtemp(prefix="ecmwf-vault-token-")
    if not os.path.exists(directory):
        os.makedirs(directory, 0o700)
    path = os.path.join(directory, name)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with open(descriptor, "wb") as handle:
        handle.write(payload)
    os.chmod(path, mode)  # O_CREAT's mode is filtered by the umask
    return path


def write_file(text: str, mode: int = 0o600, directory: Optional[str] = None,
               name: str = "token") -> str:
    """Write a text file with an explicit mode, and return its path."""
    return write_bytes(text.encode("utf-8"), mode=mode, directory=directory, name=name)


def write_sealed_token_file(token: str = SEALED_TOKEN, mode: int = 0o600,
                            directory: Optional[str] = None, name: str = "token") -> str:
    """Write a token file in the sealed form, with an explicit mode.

    The realistic fixture for anything about the token file's *permissions*: a file that is
    already sealed is read without the library having to seal it first, so those tests do not
    turn into tests of the sealing path by accident.
    """
    return write_bytes(seal_isolated(token), mode=mode, directory=directory, name=name)


import _loopback_guard

# Imported for the side effect: once this module is in play, no test in the suite can open a
# connection off loopback. See its docstring for why that is worth enforcing.
_loopback_guard.install_socket_guard()

# Everything the isolated environment starts with, apart from what a test passes explicitly.
#
# This is an ALLOW list, deliberately. The alternative was a list of names to remove, and that
# failed twice over: the suite's fake field names are whatever a test invents (PGUSER today,
# PGOPTIONS tomorrow), so any denylist is complete only until the next test is written, and a
# name missing from it makes a correct command look like it clashed with something the runner
# exported. Starting from nothing means a test cannot inherit an input it never asked for.
BASE_ENVIRONMENT = ("PATH", "HOME")

# Names a test may pretend the runner exported, to prove none of them leak in. Nothing here
# depends on the list being complete: the fixture clears everything, so an unlisted name is
# excluded for the same reason the listed ones are.
ISOLATION_PROBE_NAMES = (
    "PGOPTIONS", "PGUSER", "PGPASSWORD", "DB_USER", "DB_PASSWORD",
    "AWS_SECRET_ACCESS_KEY", "SOME_FIELD_A_TEST_MIGHT_INVENT",
    "ECMWF_VAULT_ADDR", "ECMWF_VAULT_TOKEN",
)

# The package's own settings, which a test must never pick up from the machine running it.
VAULT_VARIABLES = (
    "ECMWF_VAULT_TOKEN_FILE", "ECMWF_VAULT_ADDR", "ECMWF_VAULT_MOUNT",
    "ECMWF_VAULT_CA_BUNDLE", "ECMWF_VAULT_TIMEOUT", "ECMWF_VAULT_SWAP_POLICY",
    "ECMWF_VAULT_HARDEN",
)

# Test fixtures only, and named for what it is: the KEY is the plaintext token and the value is
# its cipher, so this is a gpg-avoidance cache and not a secure store of anything.
_sealed_cache: Dict[str, bytes] = {}


def seal_isolated(token: str) -> bytes:
    """Seal a token with the host's gnupg configuration removed from the environment.

    ``GNUPGHOME`` is gpg's own setting and the product deliberately does not override it,
    so sealing inherits it. In a fixture that is wrong twice over: token creation fails on
    a host whose ``GNUPGHOME`` points somewhere unusable, and whatever that machine has
    configured changes what the test is handed. Clearing it here keeps the product
    behaviour under test and makes the fixture mean the same thing everywhere.
    """
    from ecmwf_vault import _sealed_token_file
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("GNUPGHOME", None)
        return _sealed_token_file.seal(token)


def token_file(token: str) -> str:
    """A private directory holding ``token`` in a sealed token file; returns the path.

    The one way a test can make a token available, because the token file is the one
    source the package reads. Each call gets its own directory — a shared one would let
    one test's replacement of the file be another test's fixture — and sealing is cached
    per token so a run does not pay gpg for every test.
    """
    payload = _sealed_cache.get(token)
    if payload is None:
        payload = seal_isolated(token)
        _sealed_cache[token] = payload
    directory = tempfile.mkdtemp(prefix="ecmwf-vault-token-home-")
    atexit.register(shutil.rmtree, directory, True)
    path = os.path.join(directory, "token")
    write_bytes(payload, directory=directory, name="token")
    return path


@contextlib.contextmanager
def vault_environment(**overrides: Any):
    """An environment that inherits none of this package's variables.

    Somebody running the suite with their own ``ECMWF_VAULT_*`` exports, or a real
    ``~/.ecmwf-vault/token``, must not be able to change what is tested: every variable
    this package reads is removed and ``HOME`` points at an empty directory, so the
    default token file cannot exist either. ``overrides`` are applied after that, and the
    caller's environment is restored on exit.

    ``token=`` is not an override but a fixture: it writes a sealed token file and points
    ``ECMWF_VAULT_TOKEN_FILE`` at it, which is how a test supplies a token at all. Without
    it, there is no token anywhere.
    """
    token = overrides.pop("token", None)
    # HOME is pinned to a directory that always exists, so the default token file cannot be
    # found. PATH is passed through unchanged: tests run gpg, kubectl and interpreters for
    # real, and os.defpath does not include /usr/local/bin, where gpg commonly lives.
    settings: Dict[str, Any] = {name: os.environ[name] for name in BASE_ENVIRONMENT
                                if name in os.environ}
    settings["HOME"] = absent_home()
    settings.update(overrides)
    # clear=True: during a test the environment is exactly BASE_ENVIRONMENT plus what that
    # test asked for. Nothing needs removing any more, which is the point — VAULT_VARIABLES
    # survives only as documentation of what a caller must pass explicitly to be honoured.
    with mock.patch.dict(os.environ, settings, clear=True):
        if token is not None:
            # Built *inside* the isolation. Sealing runs gpg, and gpg reads GNUPGHOME,
            # trust-home and agent settings from the environment: doing this first meant a
            # hostile or unusable setting on the host could break fixture setup before a
            # single assertion ran.
            os.environ["ECMWF_VAULT_TOKEN_FILE"] = token_file(token)
        yield


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _write_openssl_file(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)
    return path


# The certificate fixtures drive the openssl *command line*, which is not the
# same version as the interpreter's linked OpenSSL. `-addext` only arrived in
# OpenSSL 1.1.1, so extensions are supplied through a config file instead, which
# every version from 1.0.0 understands.
_CA_EXTENSIONS = (
    "basicConstraints = critical,CA:TRUE,pathlen:0\n"
    "keyUsage = critical,keyCertSign,cRLSign\n"
    "subjectKeyIdentifier = hash\n"
    "authorityKeyIdentifier = keyid,issuer\n")
_SERVER_AND_CA_EXTENSIONS = (
    "basicConstraints = critical,CA:TRUE\n"
    "keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\n"
    "extendedKeyUsage = serverAuth\n"
    "subjectAltName = IP:127.0.0.1\n"
    "subjectKeyIdentifier = hash\n")
_LEAF_EXTENSIONS = (
    "basicConstraints = critical,CA:FALSE\n"
    "keyUsage = critical,digitalSignature,keyEncipherment\n"
    "extendedKeyUsage = serverAuth\n"
    "subjectAltName = IP:127.0.0.1\n"
    "subjectKeyIdentifier = hash\n"
    "authorityKeyIdentifier = keyid,issuer\n")


def _request_config(directory: str, name: str, common_name: str,
                    extensions: str) -> str:
    return _write_openssl_file(directory, name + ".cnf", (
        "[req]\ndefault_md = sha256\ndistinguished_name = dn\nprompt = no\n"
        "[dn]\nCN = %s\n[ext]\n%s" % (common_name, extensions)))


def _self_signed(directory: str, name: str, common_name: str,
                 extensions: str) -> Tuple[str, str]:
    """Create a self-signed certificate with config-file extensions."""
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(directory, name + ".key"),
             "-out", os.path.join(directory, name + ".crt"), "-days", "1",
             "-config", _request_config(directory, name, common_name, extensions),
             "-extensions", "ext")
    return (os.path.join(directory, name + ".crt"),
            os.path.join(directory, name + ".key"))


def make_tls_chain(directory: str) -> Tuple[str, str, str]:
    """Write a root, an intermediate and a ``127.0.0.1`` leaf.

    Returns ``(chain_pem, leaf_key, intermediate_pem)``: serve the chain with
    the leaf key, and trust only the intermediate. That only verifies when
    ``VERIFY_X509_PARTIAL_CHAIN`` is in effect, because the trust anchor is not
    self-signed.
    """
    join = lambda name: os.path.join(directory, name)  # noqa: E731 - local helper
    _self_signed(directory, "root", "Test Root CA", _CA_EXTENSIONS)
    _openssl("req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", join("int.key"), "-out", join("int.csr"),
             "-config", _request_config(directory, "int", "Test Intermediate CA",
                                       _CA_EXTENSIONS))
    _openssl("x509", "-req", "-in", join("int.csr"),
             "-CA", join("root.crt"), "-CAkey", join("root.key"),
             "-CAcreateserial", "-out", join("int.crt"), "-days", "1",
             "-extfile", _write_openssl_file(directory, "int.ext", _CA_EXTENSIONS))
    _openssl("req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", join("leaf.key"), "-out", join("leaf.csr"),
             "-config", _request_config(directory, "leaf", "127.0.0.1",
                                       _LEAF_EXTENSIONS))
    _openssl("x509", "-req", "-in", join("leaf.csr"),
             "-CA", join("int.crt"), "-CAkey", join("int.key"),
             "-CAcreateserial", "-out", join("leaf.crt"), "-days", "1",
             "-extfile", _write_openssl_file(directory, "leaf.ext", _LEAF_EXTENSIONS))
    chain = join("chain.pem")
    with open(chain, "w", encoding="ascii") as handle:
        for part in ("leaf.crt", "int.crt"):
            with open(join(part), encoding="ascii") as source:
                handle.write(source.read())
    return chain, join("leaf.key"), join("int.crt")


class FakeVault:
    """A loopback TLS server that answers like the KV v2 read endpoint."""

    def __init__(self, certificate: Optional[str] = None,
                 key: Optional[str] = None) -> None:
        self.requests: List[RecordedRequest] = []
        self.status = 200
        self.fields: Dict[str, Any] = {}
        self.raw: Optional[bytes] = None
        self.extra_headers: Dict[str, str] = {}
        if certificate is None:
            self.certificate, self.key = shared_tls_identity()
        else:
            self.certificate, self.key = certificate, key

        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "fake-vault"

            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                fake.requests.append(
                    RecordedRequest("GET", self.path, dict(self.headers)))
                body = fake.body()
                self.send_response(fake.status)
                for name, value in fake.extra_headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    # A client that stops reading (the size-limit tests) is not
                    # an error worth a traceback.
                    pass

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate, self.key)
        self._httpd.socket = context.wrap_socket(
            self._httpd.socket, server_side=True)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()

    def body(self) -> bytes:
        """The response body for the next request.

        The shape follows the *endpoint*, as a real Vault's does: anything under
        ``/v1/cubbyhole/`` answers flat, everything else with the nested KV v2 shape. A
        cubbyhole path may begin ``data/``, which there is an ordinary path and not a version
        layer, so a KV read through a mount named ``cubbyhole`` gets the flat answer and fails
        its own shape check — as a server with no KV engine at that prefix does.
        """
        if self.raw is not None:
            return self.raw
        path = self.requests[-1].path if self.requests else ""
        if path.startswith(CUBBYHOLE_TARGET_PREFIX):
            return json.dumps({"data": self.fields}).encode("utf-8")
        return json.dumps(
            {"data": {"data": self.fields, "metadata": {}}}).encode("utf-8")

    @property
    def base_url(self) -> str:
        return "https://127.0.0.1:%d" % self._httpd.server_port

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return self._httpd.server_port

    @property
    def ca_bundle(self) -> str:
        return self.certificate

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def isolate(test: Any, **overrides: Any) -> None:
    """Remove every variable this package and its tests read, for one test.

    In-process tests call the command functions directly, so an ambient ``PGUSER`` or a
    stale ``ECMWF_VAULT_*`` export reaches the code under test and changes what an
    assertion means: a clash refusal triggered by the runner is a failure the package did
    not cause. Registering the context manager through ``addCleanup`` keeps teardown
    ordered with the test's own.
    """
    environment = vault_environment(**overrides)
    environment.__enter__()
    test.addCleanup(environment.__exit__, None, None, None)


def make_vault(fake: FakeVault, **overrides: Any) -> Any:
    """Build a :class:`ecmwf_vault.Vault` pointed at ``fake``.

    The default swap policy is ``allow`` and hardening is off so the suite never
    depends on, or mutates, the host it runs on; both behaviours are pinned
    directly in ``test_policy.py``.
    """
    from ecmwf_vault import Vault

    settings: Dict[str, Any] = {
        "base_url": fake.base_url,
        "mount": "groups",
        "timeout": 5.0,
        "ca_bundle": fake.ca_bundle,
        "swap_policy": "allow",
        "harden": False,
    }
    settings.update(overrides)
    return Vault(**settings)
