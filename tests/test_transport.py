"""The HTTPS request, its status mapping, and the strict JSON parse."""
from __future__ import annotations

import os
import ssl
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import _transport
from ecmwf_vault._errors import (
    SecretNotFoundError,
    VaultError,
    VaultPermissionError,
    VaultResponseError,
    VaultUnavailableError,
)

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TARGET = "/v1/groups/data/" + EXAMPLE
TOKEN = "synthetic-vault-token"


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fields = {"password": "synthetic-value"}
        self.context = _transport.create_context(self.fake.ca_bundle)

    def fetch(self, token=TOKEN):
        return _transport.fetch_secret(
            self.fake.host, self.fake.port, TARGET, token, 5.0, self.context)

    # -- the request ------------------------------------------------------

    def test_the_request_line_and_headers(self):
        self.fake.fields = self.fields
        self.assertEqual(self.fetch(), self.fields)
        self.assertEqual(len(self.fake.requests), 1)
        request = self.fake.requests[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, TARGET)
        self.assertEqual(request.headers["X-Vault-Token"], TOKEN)
        self.assertEqual(request.headers["Accept"], "application/json")

    def test_the_token_is_never_in_the_request_line(self):
        self.fake.fields = self.fields
        self.fetch()
        self.assertNotIn(TOKEN, self.fake.requests[0].path)

    def test_a_redirect_is_not_followed(self):
        self.fake.status = 302
        self.fake.extra_headers = {"Location": "https://elsewhere.invalid/steal"}
        with self.assertRaises(VaultUnavailableError):
            self.fetch()
        self.assertEqual(len(self.fake.requests), 1)

    # -- status mapping ---------------------------------------------------

    def test_status_codes_map_to_errors(self):
        cases = ((400, VaultResponseError), (401, VaultUnavailableError),
                 (403, VaultPermissionError), (404, SecretNotFoundError),
                 (429, VaultUnavailableError), (500, VaultUnavailableError),
                 (503, VaultUnavailableError))
        for status, expected in cases:
            with self.subTest(status=status):
                self.fake.status = status
                with self.assertRaises(expected):
                    self.fetch()

    def test_an_error_body_is_never_read_or_echoed(self):
        self.fake.status = 403
        self.fake.raw = b'{"errors":["secret-body-marker-9f2a"]}'
        with self.assertRaises(VaultPermissionError) as caught:
            self.fetch()
        self.assertNotIn("secret-body-marker", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_the_status_is_reported_without_the_body(self):
        self.fake.status = 500
        with self.assertRaises(VaultUnavailableError) as caught:
            self.fetch()
        self.assertIn("500", str(caught.exception))

    # -- parsing ----------------------------------------------------------

    def test_duplicate_json_keys_are_rejected(self):
        self.fake.raw = b'{"data":{"data":{"a":1,"a":2}}}'
        with self.assertRaises(VaultResponseError):
            self.fetch()

    def test_non_finite_numbers_are_rejected(self):
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(literal=literal):
                self.fake.raw = b'{"data":{"data":{"a":' + literal + b"}}}"
                with self.assertRaises(VaultResponseError):
                    self.fetch()

    def test_a_wrong_envelope_is_rejected(self):
        for raw in (b"[]", b'{"nope":{}}', b'{"data":[]}', b'{"data":{"x":{}}}',
                    b'{"data":{"data":[]}}', b'{"data":{"data":{"":1}}}',
                    b'{"data":{"data":{"a":1},"data":{"b":2}}}', b"not json"):
            with self.subTest(body=raw):
                self.fake.raw = raw
                with self.assertRaises(VaultResponseError):
                    self.fetch()

    def test_a_null_payload_means_the_secret_is_gone(self):
        self.fake.raw = (b'{"data":{"data":null,'
                         b'"metadata":{"destroyed":true}}}')
        with self.assertRaises(SecretNotFoundError):
            self.fetch()

    def test_an_oversized_body_is_rejected(self):
        self.fake.raw = b'{"data":{"data":{"a":"' + b"x" * _transport.MAX_RESPONSE
        with self.assertRaises(VaultResponseError):
            self.fetch()

    def test_json_values_keep_their_types(self):
        self.fake.fields = {"text": "a", "number": 3, "flag": True,
                            "nothing": None, "list": [1, 2], "map": {"k": "v"}}
        self.assertEqual(self.fetch(), self.fake.fields)

    # -- TLS --------------------------------------------------------------

    def test_the_context_verifies_certificates_and_hostnames(self):
        self.assertTrue(self.context.check_hostname)
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(self.context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_an_untrusted_certificate_is_refused(self):
        system_context = _transport.create_context(None)
        with self.assertRaises(VaultUnavailableError):
            _transport.fetch_secret(self.fake.host, self.fake.port, TARGET,
                                    TOKEN, 5.0, system_context)

    def test_a_closed_port_is_reported_as_unavailable(self):
        probe = _fakes.FakeVault()
        port = probe.port
        probe.stop()
        with self.assertRaises(VaultUnavailableError):
            _transport.fetch_secret("127.0.0.1", port, TARGET, TOKEN, 5.0,
                                    self.context)

    def test_a_connection_that_cannot_be_built_is_unavailable(self):
        with mock.patch("http.client.HTTPSConnection",
                        side_effect=OSError(101, "network is unreachable")):
            with self.assertRaises(VaultUnavailableError):
                self.fetch()

    def test_sslkeylogfile_is_never_created_or_written(self):
        with tempfile.TemporaryDirectory() as directory:
            keylog = os.path.join(directory, "tls-keys.log")
            with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": keylog}):
                fresh = _transport.create_context(self.fake.ca_bundle)
                self.assertIsNone(getattr(fresh, "keylog_filename", None))
                self.fake.fields = self.fields
                self.assertEqual(_transport.fetch_secret(
                    self.fake.host, self.fake.port, TARGET, TOKEN, 5.0, fresh),
                    self.fields)
            self.assertFalse(os.path.exists(keylog))

    def test_a_broken_sslkeylogfile_path_cannot_break_a_read(self):
        unusable = "/nonexistent-directory-9f2a/tls-keys.log"
        with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": unusable}):
            fresh = _transport.create_context(self.fake.ca_bundle)
            self.fake.fields = self.fields
            self.assertEqual(_transport.fetch_secret(
                self.fake.host, self.fake.port, TARGET, TOKEN, 5.0, fresh),
                self.fields)
        self.assertFalse(os.path.exists(unusable))

    def test_the_helper_that_opens_the_key_log_is_never_called(self):
        # ssl.create_default_context() is the helper that reads SSLKEYLOGFILE and
        # opens the file it names; nothing here may call it.
        with mock.patch("ssl.create_default_context",
                        side_effect=AssertionError("key-log factory")) as factory:
            _transport.create_context(self.fake.ca_bundle)
        self.assertFalse(factory.called)

    def test_the_process_environment_is_never_touched(self):
        wanted = "/tmp/would-be-keylog.log"
        with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": wanted}):
            _transport.create_context(self.fake.ca_bundle)
            self.assertEqual(os.environ["SSLKEYLOGFILE"], wanted)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SSLKEYLOGFILE", None)
            _transport.create_context(self.fake.ca_bundle)
            self.assertNotIn("SSLKEYLOGFILE", os.environ)

    def test_the_context_is_never_weaker_than_the_platform_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SSLKEYLOGFILE", None)
            reference = ssl.create_default_context(cafile=self.fake.ca_bundle)
        ours = _transport.create_context(self.fake.ca_bundle)
        # Nothing the platform factory sets may be missing. We may be stricter:
        # the factory only gained PARTIAL_CHAIN/STRICT over 3.13-3.14.
        self.assertEqual(reference.verify_flags & ~ours.verify_flags, 0)
        self.assertTrue(ours.verify_flags & _transport._X509_STRICT)
        self.assertTrue(ours.verify_flags & _transport._PARTIAL_CHAIN)
        self.assertEqual(ours.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ours.check_hostname)
        self.assertGreaterEqual(ours.minimum_version, ssl.TLSVersion.TLSv1_2)
        # Never omit an option the platform default sets.
        self.assertEqual(reference.options & ~ours.options, 0)
        self.assertEqual([cipher["name"] for cipher in ours.get_ciphers()],
                         [cipher["name"] for cipher in reference.get_ciphers()])

    def test_the_spelled_out_openssl_flag_values_are_the_real_ones(self):
        # The fallback numbers are needed on interpreters that do not expose the
        # constants: PARTIAL_CHAIN before 3.10 and X509_STRICT before 3.13.
        for name, value in (("VERIFY_X509_PARTIAL_CHAIN", 0x00080000),
                            ("VERIFY_X509_STRICT", 0x00000020)):
            if hasattr(ssl, name):
                with self.subTest(name=name):
                    self.assertEqual(getattr(ssl, name), value)
        self.assertFalse(_transport._PARTIAL_CHAIN & _transport._X509_STRICT)

    def test_partial_chain_boundary_follows_the_openssl_that_has_it(self):
        # X509_V_FLAG_PARTIAL_CHAIN first appears in OpenSSL 1.0.2; the values
        # above were read from the OpenSSL sources for 1.0.1, 1.0.2, 1.1.0 and
        # 1.1.1.
        for version, expected in (((1, 0, 1), False), ((1, 0, 2), True),
                                  ((1, 1, 0), True), ((3, 5, 0, 7, 0), True)):
            with self.subTest(version=version):
                with mock.patch.object(ssl, "OPENSSL_VERSION_INFO", version):
                    flags = _transport._verification_hardening()
                self.assertEqual(bool(flags & _transport._PARTIAL_CHAIN), expected)
                self.assertTrue(flags & _transport._X509_STRICT)

    def test_an_intermediate_in_the_ca_bundle_is_usable_as_a_trust_anchor(self):
        # Without VERIFY_X509_PARTIAL_CHAIN OpenSSL insists the trust store hold
        # a self-signed root, so a bundle holding an intermediate fails.
        with tempfile.TemporaryDirectory() as directory:
            chain, leaf_key, intermediate = _fakes.make_tls_chain(directory)
            server = _fakes.FakeVault(certificate=chain, key=leaf_key)
            self.addCleanup(server.stop)
            server.fields = self.fields
            context = _transport.create_context(intermediate)
            self.assertEqual(_transport.fetch_secret(
                server.host, server.port, TARGET, TOKEN, 5.0, context),
                self.fields)

    def test_a_ca_bundle_replaces_the_trust_store(self):
        context = _transport.create_context(self.fake.ca_bundle)
        self.assertEqual(context.cert_store_stats()["x509"], 1)

    def test_without_a_bundle_the_system_store_is_loaded(self):
        with mock.patch.object(ssl.SSLContext, "load_default_certs") as load:
            context = _transport.create_context(None)
        load.assert_called_once_with(ssl.Purpose.SERVER_AUTH)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_an_unusable_ca_bundle_is_a_fixed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            malformed = os.path.join(directory, "ca.pem")
            with open(malformed, "w", encoding="ascii") as handle:
                handle.write("not a certificate")
            for bundle in ("/nonexistent-directory-9f2a/ca.pem", malformed):
                with self.subTest(bundle=bundle):
                    with self.assertRaises(VaultError) as caught:
                        _transport.create_context(bundle)
                    self.assertIn("CA bundle", str(caught.exception))
                    self.assertNotIn(bundle, str(caught.exception))

    def test_the_keylog_attribute_is_pinned_off(self):
        self.assertIsNone(getattr(self.context, "keylog_filename", None))

    # -- buffer handling --------------------------------------------------

    def test_wipe_overwrites_in_place(self):
        buffer = bytearray(b"synthetic-secret")
        identity = id(buffer)
        _transport.wipe(buffer)
        self.assertEqual(id(buffer), identity)
        self.assertEqual(bytes(buffer), bytes(len(buffer)))

    def test_parse_fields_wipes_the_buffer_it_was_given(self):
        buffer = bytearray(b'{"data":{"data":{"a":"b"}}}')
        self.assertEqual(_transport.parse_fields(buffer), {"a": "b"})
        self.assertEqual(bytes(buffer), bytes(len(buffer)))

    def test_a_lone_surrogate_field_parses_without_an_encoding_error(self):
        body = bytearray(
            b'{"data":{"data":{"password":"synthetic-value",'
            b'"other":"\\ud800"}}}')
        fields = _transport.parse_fields(body)
        self.assertEqual(fields["password"], "synthetic-value")
        self.assertEqual(fields["other"], "\ud800")
        self.assertEqual(bytes(body), bytes(len(body)))

    def test_parse_fields_refuses_a_non_json_buffer(self):
        with self.assertRaises(VaultResponseError):
            _transport.parse_fields(bytearray(b"{"))


if __name__ == "__main__":
    unittest.main()
