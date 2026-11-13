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


def absent_home() -> str:
    """An empty home directory, so the default config path does not exist.

    Tests point ``HOME`` here so the suite cannot start reading (or failing on)
    the config file of whoever is running it, and so "no config file configured"
    is a real state rather than "a named file is missing".
    """
    global _absent_directory
    with _identity_lock:
        if _absent_directory is None:
            _absent_directory = tempfile.mkdtemp(prefix="ecmwf-vault-absent-")
            atexit.register(shutil.rmtree, _absent_directory, True)
        return _absent_directory


def absent_config_path() -> str:
    """A config path that never exists, for tests that name a missing file."""
    return os.path.join(absent_home(), "no-such-config")


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


def write_config(text: str, mode: int = 0o600, directory: Optional[str] = None,
                 name: str = "config") -> str:
    """Write a token config file with an explicit mode, and return its path."""
    directory = directory or tempfile.mkdtemp(prefix="ecmwf-vault-config-")
    if not os.path.exists(directory):
        os.makedirs(directory, 0o700)
    path = os.path.join(directory, name)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with open(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, mode)  # O_CREAT's mode is filtered by the umask
    return path


VAULT_VARIABLES = (
    "ECMWF_VAULT_TOKEN",
    "ECMWF_VAULT_CONFIG",
    "ECMWF_VAULT_CONFIG_POLICY",
    "ECMWF_VAULT_ADDR",
    "ECMWF_VAULT_MOUNT",
    "ECMWF_VAULT_CA_BUNDLE",
    "ECMWF_VAULT_TIMEOUT",
    "ECMWF_VAULT_SWAP_POLICY",
    "ECMWF_VAULT_HARDEN",
)


@contextlib.contextmanager
def vault_environment(**overrides: Any):
    """An environment that inherits none of this package's variables.

    Somebody running the suite with their own ``ECMWF_VAULT_*`` exports, or a real
    ``~/.ecmwf-vault/config``, must not be able to change what is tested: every
    variable this package reads is removed and ``HOME`` points at an empty
    directory, so the default config path cannot exist either. ``overrides`` are
    applied after that, and the caller's environment is restored on exit.
    """
    settings: Dict[str, Any] = {"HOME": absent_home()}
    settings.update(overrides)
    with mock.patch.dict(os.environ, settings):
        for name in VAULT_VARIABLES:
            if name not in settings:
                os.environ.pop(name, None)
        yield


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _write_file(directory: str, name: str, text: str) -> str:
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
    return _write_file(directory, name + ".cnf", (
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
             "-extfile", _write_file(directory, "int.ext", _CA_EXTENSIONS))
    _openssl("req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", join("leaf.key"), "-out", join("leaf.csr"),
             "-config", _request_config(directory, "leaf", "127.0.0.1",
                                       _LEAF_EXTENSIONS))
    _openssl("x509", "-req", "-in", join("leaf.csr"),
             "-CA", join("int.crt"), "-CAkey", join("int.key"),
             "-CAcreateserial", "-out", join("leaf.crt"), "-days", "1",
             "-extfile", _write_file(directory, "leaf.ext", _LEAF_EXTENSIONS))
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
        """The response body for the next request."""
        if self.raw is not None:
            return self.raw
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
