# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The HTTPS request, its status mapping, and the strict JSON parse."""
from __future__ import annotations

import gc
import json
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


def _open_descriptors():
    """How many descriptors this process holds open, for the leak tests."""
    return len(os.listdir("/proc/self/fd"))


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

    # -- what a request must not leave behind -----------------------------

    def test_a_refused_request_closes_the_response_and_the_connection(self):
        # An error response is never read — that is deliberate, so a refusal cannot put a
        # response fragment in a message — and one left open holds the socket's descriptor for
        # as long as the exception (and the traceback keeping its frame alive) does.
        response = mock.Mock(status=403)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch("http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(VaultPermissionError):
                self.fetch()
        response.close.assert_called_once_with()
        connection.close.assert_called_once_with()

    def test_a_body_over_the_size_limit_closes_the_response_too(self):
        response = mock.Mock(status=200)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(_transport, "_read_bounded",
                               side_effect=VaultResponseError("too large")):
            with mock.patch("http.client.HTTPSConnection", return_value=connection):
                with self.assertRaises(VaultResponseError):
                    self.fetch()
        response.close.assert_called_once_with()

    def test_a_close_that_fails_does_not_replace_the_reason_we_are_leaving(self):
        response = mock.Mock(status=403)
        response.close.side_effect = OSError(9, "bad file descriptor")
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch("http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(VaultPermissionError):
                self.fetch()

    def test_a_response_that_was_never_reached_is_not_closed(self):
        # getresponse() itself failing leaves nothing to close, and closing a None must not be
        # attempted: this is the path a connection that breaks mid-request takes.
        connection = mock.Mock()
        connection.getresponse.side_effect = OSError(104, "connection reset")
        with mock.patch("http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(VaultUnavailableError):
                self.fetch()
        connection.close.assert_called_once_with()

    def test_a_refused_request_does_not_hold_a_descriptor_open(self):
        # The integration form of the test above, and the reason it matters: an exception that
        # is kept alive — which is what a caller that logs it does — keeps its traceback, and
        # this frame, and the response object read out of it, so the descriptor went with the
        # exception rather than with the request.
        #
        # assertRaises cannot be used here. unittest clears the exception's traceback on purpose
        # (to break the reference cycle), so holding caught.exception holds no frame at all and
        # this test would pass with the response never closed. Verified: 5 exceptions retained
        # that way carry 0 live tracebacks; retained the way below, 5.
        self.fake.status = 403
        self.fake.raw = b'{"errors": ["permission denied"]}'
        held = []
        for _ in range(5):
            try:
                self.fetch()
            except VaultPermissionError as error:
                held.append(error)
        self.assertTrue(all(error.__traceback__ is not None for error in held),
                        "the test is holding nothing without a traceback to hold")
        gc.collect()
        while_held = _open_descriptors()
        held.clear()
        del held
        gc.collect()
        self.assertEqual(while_held, _open_descriptors())

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


class TokenLookupTests(unittest.TestCase):
    """``auth/token/lookup-self``: the same request, a shallower envelope.

    A lookup answers with a flat ``data`` object, so it has its own parse — the KV v2 one
    would reject it as malformed. What is checked here is that the request is the one
    intended, that the metadata passes through untouched, and that a refusal is reported
    as the lookup's own answer rather than as a permission detail.
    """

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.metadata = {"ttl": 7112, "renewable": True, "display_name": "a-token"}
        self.fake.raw = json.dumps({"data": self.metadata}).encode("utf-8")
        self.context = _transport.create_context(self.fake.ca_bundle)

    def lookup(self, token=TOKEN):
        return _transport.fetch_token_info(
            self.fake.host, self.fake.port, token, 5.0, self.context)

    def test_the_request_is_the_token_lookup_path_and_carries_the_token(self):
        self.assertEqual(self.lookup(), self.metadata)
        (request,) = self.fake.requests
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/v1/auth/token/lookup-self")
        self.assertEqual(request.headers["X-Vault-Token"], TOKEN)
        self.assertNotIn(TOKEN, request.path)

    def test_the_lookup_path_does_not_follow_the_data_mount(self):
        # auth endpoints are fixed; ECMWF_VAULT_MOUNT names the KV data mount only.
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_MOUNT": "somewhere-else"}):
            self.lookup()
        self.assertEqual(self.fake.requests[0].path, "/v1/auth/token/lookup-self")

    def test_every_metadata_field_passes_through_untouched(self):
        # Including one this package has never heard of: the caller gets Vault's answer, not
        # this package's idea of which fields matter.
        self.fake.raw = json.dumps({"data": {
            "ttl": 0, "creation_ttl": 43200, "expire_time": None,
            "renewable": False, "num_uses": 5, "policies": ["default", "cems-read"],
            "meta": {"owner": "cems"}, "something_new": [1, {"deep": True}],
        }}).encode("utf-8")
        info = self.lookup()
        self.assertEqual(info["creation_ttl"], 43200)
        self.assertIsNone(info["expire_time"])
        self.assertEqual(info["something_new"], [1, {"deep": True}])
        self.assertEqual(info["meta"], {"owner": "cems"})

    def test_the_strict_json_hooks_apply_here_too(self):
        for raw in (b"not json", b'{"data":{"a":1,"a":2}}', b'{"data":{"a":NaN}}'):
            with self.subTest(body=raw):
                self.fake.raw = raw
                with self.assertRaises(VaultResponseError):
                    self.lookup()

    def test_a_wrong_shape_is_refused(self):
        for raw in (b"[]", b'{"nope":{}}', b'{"data":[]}', b'{"data":null}',
                    b'{"data":"a-string"}', b"{}"):
            with self.subTest(body=raw):
                self.fake.raw = raw
                with self.assertRaises(VaultResponseError):
                    self.lookup()

    def test_a_refused_token_is_reported_as_the_lookup_failing(self):
        # 403 here means the token cannot read itself, which is the answer the caller needs:
        # the generic "cannot read this secret" wording would send them looking elsewhere.
        self.fake.status = 403
        with self.assertRaises(VaultPermissionError) as caught:
            self.lookup()
        message = str(caught.exception)
        self.assertIn("look itself up", message)
        self.assertNotIn("read this secret", message)
        # A policy can deny this lookup for a perfectly valid token, so the message names
        # both causes rather than asserting which one it was.
        self.assertIn("expired or been revoked", message)
        self.assertIn("policy", message)

    def test_other_statuses_keep_their_own_meaning(self):
        for status, expected in ((404, SecretNotFoundError), (429, VaultUnavailableError),
                                 (500, VaultUnavailableError)):
            with self.subTest(status=status):
                self.fake.status = status
                with self.assertRaises(expected):
                    self.lookup()

    def test_an_unreachable_vault_is_reported_as_unavailable(self):
        context = _transport.create_context(self.fake.ca_bundle)
        with self.assertRaises(VaultUnavailableError):
            _transport.fetch_token_info("127.0.0.1", 1, TOKEN, 5.0, context)

    def test_parse_token_info_wipes_the_buffer_it_was_given(self):
        buffer = bytearray(b'{"data":{"ttl":7112}}')
        self.assertEqual(_transport.parse_token_info(buffer), {"ttl": 7112})
        self.assertEqual(bytes(buffer), bytes(len(buffer)))

    def test_parse_token_info_refuses_a_non_json_buffer(self):
        with self.assertRaises(VaultResponseError):
            _transport.parse_token_info(bytearray(b"{"))

    def test_the_two_parses_are_not_interchangeable(self):
        # The nesting is the whole difference between the two reads. A lookup body parsed as
        # a KV v2 read is rejected outright; a KV v2 body parsed as a lookup is *not* — it
        # is passed through as metadata that happens to have "data" and "metadata" fields,
        # which is correct for a parse whose contract is "check the shape and hand it over".
        # Pinned so the asymmetry is a known one and the two cannot drift into each other.
        flat = bytearray(b'{"data":{"ttl":7112}}')
        with self.assertRaises(VaultResponseError):
            _transport.parse_fields(flat)
        nested = bytearray(b'{"data":{"data":{"x":1},"metadata":{}}}')
        self.assertEqual(_transport.parse_token_info(nested),
                         {"data": {"x": 1}, "metadata": {}})


class CubbyholeParseTests(unittest.TestCase):
    """The flat response shape a cubbyhole read answers with, and what is refused."""

    def test_a_flat_body_is_parsed_into_its_fields(self):
        body = bytearray(b'{"data":{"password":"x","user":"madt"}}')
        self.assertEqual(_transport.parse_cubbyhole_fields(body),
                         {"password": "x", "user": "madt"})

    def test_the_buffer_is_wiped_after_parsing(self):
        body = bytearray(b'{"data":{"password":"hunter2"}}')
        _transport.parse_cubbyhole_fields(body)
        self.assertEqual(bytes(body), b"\0" * len(body))

    def test_a_nested_KV_v2_body_is_not_read_as_a_cubbyhole_one(self):
        # The two shapes differ by one level, and mixing them up would hand the caller a
        # mapping whose only key is "data". Pinned in both directions.
        nested = bytearray(b'{"data":{"data":{"x":1},"metadata":{}}}')
        self.assertEqual(_transport.parse_cubbyhole_fields(nested),
                         {"data": {"x": 1}, "metadata": {}})
        with self.assertRaises(VaultResponseError):
            _transport.parse_fields(bytearray(b'{"data":{"x":1}}'))

    def test_a_body_with_no_object_under_data_is_refused(self):
        for body in (b'{}', b'{"data":null}', b'{"data":[]}', b'{"data":"x"}', b'[1]',
                     b'{"data":true}'):
            with self.subTest(body=body):
                with self.assertRaises(VaultResponseError):
                    _transport.parse_cubbyhole_fields(bytearray(body))

    def test_other_top_level_members_are_ignored_as_vaults_to_include(self):
        body = bytearray(b'{"data":{"a":"1"},"lease_duration":60,"warnings":[]}')
        self.assertEqual(_transport.parse_cubbyhole_fields(body), {"a": "1"})

    def test_a_field_name_must_be_a_non_empty_string(self):
        for body in (b'{"data":{"":"x"}}',):
            with self.subTest(body=body):
                with self.assertRaises(VaultResponseError):
                    _transport.parse_cubbyhole_fields(bytearray(body))

    def test_a_non_finite_number_or_duplicate_key_is_refused(self):
        # The same strict JSON hooks the other parses use, so a cubbyhole body cannot smuggle
        # a value that is not a JSON number, or shadow one field with a later duplicate.
        for body in (b'{"data":{"a":NaN}}', b'{"data":{"a":1,"a":2}}'):
            with self.subTest(body=body):
                with self.assertRaises(VaultResponseError):
                    _transport.parse_cubbyhole_fields(bytearray(body))

    def test_the_cubbyhole_fetcher_sends_one_request_to_the_cubbyhole_target(self):
        fake = _fakes.FakeVault()
        self.addCleanup(fake.stop)
        fake.fields = {"password": "hunter2"}
        context = _transport.create_context(fake.ca_bundle)
        fields = _transport.fetch_cubbyhole(
            fake.host, fake.port, "/v1/cubbyhole/madt/efas", "hvs.a-token", 10.0, context)
        self.assertEqual(fields, {"password": "hunter2"})
        self.assertEqual([(r.method, r.path) for r in fake.requests],
                         [("GET", "/v1/cubbyhole/madt/efas")])
        self.assertEqual(fake.requests[0].headers["X-Vault-Token"], "hvs.a-token")

    def test_a_cubbyhole_404_is_reported_as_no_such_secret(self):
        fake = _fakes.FakeVault()
        self.addCleanup(fake.stop)
        fake.status = 404
        context = _transport.create_context(fake.ca_bundle)
        with self.assertRaises(SecretNotFoundError):
            _transport.fetch_cubbyhole(fake.host, fake.port, "/v1/cubbyhole/nope",
                                       "hvs.a-token", 10.0, context)


if __name__ == "__main__":
    unittest.main()
