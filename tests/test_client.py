# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The client: configuration, caching, token binding and the public API."""
from __future__ import annotations

import gc
import json
import os
import traceback
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import _fakes
from ecmwf_vault import (
    InvalidSecretPathError,
    Secret,
    SecretFieldMissingError,
    SecretMemoryFile,
    Vault,
    VaultError,
    VaultPermissionError,
    VaultResponseError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
    clear_cache,
    close,
    cubbyhole_read,
    value,
)
from ecmwf_vault import _client

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TOKEN = "synthetic-vault-token"


class ClientTests(unittest.TestCase):
    def setUp(self):
        # Isolate the environment first: a Vault built under an inherited
        # ECMWF_VAULT_* variable would not be the one this test means to build.
        environment = _fakes.vault_environment(token=TOKEN)
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value", "user": "cems"}
        self.vault = _fakes.make_vault(self.fake)
        self.addCleanup(self.vault.close)

    # -- the returned value -----------------------------------------------

    def test_the_whole_field_mapping_is_returned(self):
        fields = self.vault.value(EXAMPLE)
        self.assertEqual(_fakes.revealed(fields), self.fake.fields)
        self.assertTrue(all(isinstance(field, Secret) for field in fields.values()))
        with self.assertRaises(TypeError):
            json.dumps(fields)

    def test_one_field_is_returned_as_a_secret(self):
        secret = self.vault.value(EXAMPLE, field="password")
        self.assertIsInstance(secret, Secret)
        self.assertEqual(secret.reveal(), "synthetic-value")
        self.assertEqual(repr(secret), "<Secret>")

    def test_an_absent_field_is_an_error(self):
        with self.assertRaises(SecretFieldMissingError):
            self.vault.value(EXAMPLE, field="nope")
        with self.assertRaises(SecretFieldMissingError):
            self.vault.value(EXAMPLE, field=7)  # type: ignore[arg-type]

    def test_keys_are_returned_without_values(self):
        self.assertEqual(self.vault.keys(EXAMPLE), ("password", "user"))

    def test_the_mount_and_base_url_can_be_overridden(self):
        other = _fakes.make_vault(self.fake, mount="kv")
        self.addCleanup(other.close)
        other.value(EXAMPLE)
        self.assertEqual(self.fake.requests[0].path,
                         "/v1/kv/data/" + EXAMPLE)

    # -- caching ----------------------------------------------------------

    def test_a_cached_secret_is_fetched_once(self):
        self.vault.value(EXAMPLE)
        self.vault.value(EXAMPLE)
        self.vault.value(EXAMPLE, field="password")
        self.assertEqual(len(self.fake.requests), 1)

    def test_cache_can_be_skipped_per_call(self):
        self.vault.value(EXAMPLE, cache=False)
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(len(self.fake.requests), 2)

    def test_cache_is_skipped_even_when_an_entry_is_warm(self):
        self.vault.value(EXAMPLE)
        self.fake.fields = {"password": "rotated-value", "user": "cems"}
        self.assertEqual(
            self.vault.value(EXAMPLE, field="password", cache=False).reveal(),
            "rotated-value")
        self.assertEqual(len(self.fake.requests), 2)
        # An uncached call does not disturb the warm entry either.
        self.assertEqual(self.vault.value(EXAMPLE, field="password").reveal(),
                         "synthetic-value")
        self.assertEqual(len(self.fake.requests), 2)

    def test_cache_false_observes_a_permission_change(self):
        self.vault.value(EXAMPLE)
        self.fake.status = 403
        with self.assertRaises(VaultPermissionError):
            self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(len(self.fake.requests), 2)
        self.fake.status = 200
        self.assertEqual(self.vault.value(EXAMPLE, field="password").reveal(),
                         "synthetic-value")
        self.assertEqual(len(self.fake.requests), 2)

    def test_keys_and_memory_file_also_honour_cache_false(self):
        self.vault.value(EXAMPLE)
        self.fake.fields = {"password": "rotated-value", "user": "cems"}
        self.assertEqual(self.vault.keys(EXAMPLE, cache=False),
                         ("password", "user"))
        memory = self.vault.memory_file(EXAMPLE, cache=False)
        try:
            self.assertIn(b"rotated-value", memory.read())
        finally:
            memory.close()
        self.assertEqual(len(self.fake.requests), 3)

    def test_an_uncached_call_does_not_populate_the_cache(self):
        self.vault.value(EXAMPLE, cache=False)
        self.vault.value(EXAMPLE)
        self.assertEqual(len(self.fake.requests), 2)

    def test_clear_cache_forces_a_refetch(self):
        self.vault.value(EXAMPLE)
        self.vault.clear_cache()
        self.vault.value(EXAMPLE)
        self.assertEqual(len(self.fake.requests), 2)

    def test_two_instances_do_not_share_a_cache(self):
        other = _fakes.make_vault(self.fake)
        self.addCleanup(other.close)
        self.vault.value(EXAMPLE)
        other.value(EXAMPLE)
        self.assertEqual(len(self.fake.requests), 2)

    def test_a_different_token_is_not_served_a_cached_secret(self):
        self.vault.value(EXAMPLE)
        self.fake.fields = {"password": "second-value"}
        # A re-login replaces the file, and a cached secret belongs to the token that
        # fetched it, not to whoever reads next.
        _fakes.write_sealed_token_file("hvs.other-token",
                                       directory=os.path.dirname(
                                           os.environ["ECMWF_VAULT_TOKEN_FILE"]))
        self.assertEqual(self.vault.value(EXAMPLE, field="password").reveal(),
                         "second-value")
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual(self.fake.requests[1].headers["X-Vault-Token"],
                         "hvs.other-token")

    def test_closing_refuses_further_use(self):
        self.vault.close()
        with self.assertRaises(VaultError):
            self.vault.value(EXAMPLE)
        self.vault.close()

    def test_an_instance_works_as_a_context_manager(self):
        with _fakes.make_vault(self.fake) as instance:
            self.assertEqual(_fakes.revealed(instance.value(EXAMPLE)), self.fake.fields)
        with self.assertRaises(VaultError):
            instance.value(EXAMPLE)

    # -- the token --------------------------------------------------------

    def test_a_missing_token_is_a_runtime_error_before_any_request(self):
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN_FILE": ""}):
            with self.assertRaises(VaultTokenMissingError) as caught:
                self.vault.value(EXAMPLE)
        self.assertIsInstance(caught.exception, RuntimeError)
        self.assertEqual(self.fake.requests, [])

    def test_the_token_is_re_read_on_every_call(self):
        # Nothing is cached, so a re-login's new token is in use on the very next call.
        directory = os.path.dirname(os.environ["ECMWF_VAULT_TOKEN_FILE"])
        self.vault.value(EXAMPLE, cache=False)
        _fakes.write_sealed_token_file("hvs.rotated-token", directory=directory)
        self.vault.value(EXAMPLE, cache=False)
        tokens = [request.headers["X-Vault-Token"] for request in self.fake.requests]
        self.assertEqual(tokens, [TOKEN, "hvs.rotated-token"])

    def test_a_malformed_token_is_rejected_before_any_request(self):
        # hvs. marks "this is a token", so a bad one is judged here rather than handed to
        # http.client, whose rejection message would carry the value. Neither the message
        # nor the traceback may contain it.
        for token in ("hvs.bad\ntoken", "hvs.bad token", "hvs.tab\there",
                      "hvs.tok\u00e9n", "hvs.bad\x00token"):
            with self.subTest(token=repr(token)):
                path = os.environ["ECMWF_VAULT_TOKEN_FILE"]
                _fakes.write_bytes(token.encode("utf-8"), directory=os.path.dirname(path))
                raised = None
                try:
                    self.vault.value(EXAMPLE)
                except VaultTokenInvalidError as error:
                    raised = error
                self.assertIsNotNone(raised, "the malformed token was accepted")
                self.assertIsInstance(raised, RuntimeError)
                # Held as it was raised, not through assertRaises: unittest clears the
                # traceback there, and the traceback is one of the three renderings checked.
                self.assertIsNotNone(raised.__traceback__)
                trace = "".join(traceback.format_exception(
                    type(raised), raised, raised.__traceback__))
                for rendering in (str(raised), repr(raised), trace):
                    self.assertNotIn(token.strip(), rendering)
        self.assertEqual(self.fake.requests, [])

    def test_a_field_with_a_lone_surrogate_round_trips(self):
        self.fake.fields = {"password": "synthetic-value", "other": "\ud800"}
        fields = self.vault.value(EXAMPLE)
        self.assertEqual(_fakes.revealed(fields),
                         {"password": "synthetic-value", "other": "\ud800"})
        # It survives the sealed store too, and never raises an encoding error
        # whose repr would carry the rest of the mapping.
        self.assertEqual(self.vault.value(EXAMPLE)["other"].reveal(), "\ud800")
        self.assertEqual(len(self.fake.requests), 1)

    def test_the_token_is_not_in_the_repr_or_errors(self):
        self.fake.status = 403
        with self.assertRaises(VaultError) as caught:
            self.vault.value(EXAMPLE)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn(TOKEN, repr(self.vault))

    # -- memory files -----------------------------------------------------

    def test_memory_file_hands_out_an_owned_descriptor(self):
        first = self.vault.memory_file(EXAMPLE)
        second = self.vault.memory_file(EXAMPLE)
        try:
            self.assertIsInstance(first, SecretMemoryFile)
            self.assertNotEqual(first.fd, second.fd)
            first.close()
            # Closing one handed-out copy must not disturb the cache.
            self.assertEqual(second.read(), first_bytes(self.fake.fields))
            third = self.vault.memory_file(EXAMPLE)
            try:
                self.assertEqual(third.read(), first_bytes(self.fake.fields))
            finally:
                third.close()
            self.assertEqual(len(self.fake.requests), 1)
        finally:
            second.close()

    def test_an_uncached_memory_file_is_the_only_descriptor(self):
        memory = self.vault.memory_file(EXAMPLE, cache=False)
        try:
            self.assertEqual(memory.read(), first_bytes(self.fake.fields))
        finally:
            memory.close()

    # -- call-time argument checking --------------------------------------

    def test_a_bad_path_never_reaches_the_network(self):
        with self.assertRaises(VaultError):
            self.vault.value("../etc/passwd")
        self.assertEqual(self.fake.requests, [])

    # -- configuration ----------------------------------------------------

    def test_configuration_errors(self):
        for kwargs in ({"base_url": "http://secrets.ecmwf.int"},
                       {"base_url": "not-a-url"},
                       {"mount": "a/b"},
                       {"mount": ""},
                       {"timeout": 0},
                       {"timeout": -1},
                       {"timeout": 301},
                       {"timeout": "soon"},
                       {"timeout": True},
                       {"timeout": [1]},
                       {"swap_policy": "maybe"},
                       {"harden": "yes"}):
            with self.subTest(**kwargs):
                with self.assertRaises(VaultError):
                    Vault(**kwargs)

    def test_a_corrupt_stored_payload_is_reported(self):
        for raw in (b"not json", b"", b"[1, 2]", b'"text"'):
            with self.subTest(raw=raw):
                with self.assertRaises(VaultResponseError):
                    _client._decode(raw)

    def test_closing_mid_call_is_caught_by_the_locked_check(self):
        class Closer:
            def __init__(self, instance):
                self.instance = instance

            def __enter__(self):
                self.instance._closed = True
                return self

            def __exit__(self, *exception):
                return False

        with mock.patch.object(self.vault, "_lock", Closer(self.vault)):
            with self.assertRaises(VaultError):
                self.vault.value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_timeout_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TIMEOUT": "2.5"}):
            self.assertEqual(Vault(swap_policy="allow", harden=False).timeout, 2.5)

    def test_address_and_mount_come_from_the_environment(self):
        # Nested inside the isolated environment so a stray inherited timeout or
        # mount cannot decide the outcome of this test.
        with _fakes.vault_environment(token=TOKEN,
                                      ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_MOUNT="kv"):
            instance = Vault(swap_policy="allow", harden=False,
                             ca_bundle=self.fake.ca_bundle)
            self.addCleanup(instance.close)
            instance.value(EXAMPLE)
        self.assertEqual(self.fake.requests[0].path, "/v1/kv/data/" + EXAMPLE)

    def test_the_swap_policy_is_enforced_before_the_network(self):
        instance = _fakes.make_vault(self.fake, swap_policy="refuse")
        self.addCleanup(instance.close)
        with mock.patch("ecmwf_vault._policy.swap_is_active", return_value=True):
            with self.assertRaises(VaultError):
                instance.value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_an_unsupported_interpreter_is_reported_before_the_request(self):
        # A missing capability should be reported before the network call, not after.
        with mock.patch.object(os, "memfd_create", None):
            with self.assertRaises(VaultError) as caught:
                self.vault.value(EXAMPLE, cache=False)
        self.assertIn("os.memfd_create", str(caught.exception))
        self.assertEqual(self.fake.requests, [])

    def test_a_fetch_error_leaves_the_cache_empty(self):
        self.fake.status = 404
        with self.assertRaises(VaultError):
            self.vault.value(EXAMPLE)
        self.fake.status = 200
        self.assertEqual(_fakes.revealed(self.vault.value(EXAMPLE)), self.fake.fields)
        self.assertEqual(len(self.fake.requests), 2)


class ModuleLevelApiTests(unittest.TestCase):
    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}
        # close() is terminal for the module-level API by design, so a test that
        # needs that API again has to reopen it explicitly.
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        _client.clear_cache()
        environment = _fakes.vault_environment(
            token=TOKEN,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.addCleanup(close)

    def test_value_reads_through_the_default_instance(self):
        self.assertEqual(value(EXAMPLE, field="password").reveal(), "synthetic-value")
        self.assertEqual(_fakes.revealed(value(EXAMPLE)), self.fake.fields)
        self.assertEqual(len(self.fake.requests), 1)

    def test_clear_cache_forces_a_refetch(self):
        value(EXAMPLE)
        clear_cache()
        value(EXAMPLE)
        self.assertEqual(len(self.fake.requests), 2)

    def test_close_is_terminal_for_the_module_level_api(self):
        value(EXAMPLE)
        close()
        with self.assertRaises(VaultError) as caught:
            value(EXAMPLE)
        self.assertIn("close()", str(caught.exception))
        with self.assertRaises(VaultError):
            value(EXAMPLE, mount="kv")
        clear_cache()  # both stay safe after close
        close()
        self.assertEqual(len(self.fake.requests), 1)

    def test_the_pool_evicts_the_least_recently_used_not_the_oldest(self):
        cap = _client.MAX_DEFAULT_INSTANCES
        for index in range(cap):
            value(EXAMPLE, mount="kv%d" % index)
        self.assertEqual(len(self.fake.requests), cap)
        # Touch the oldest entry: it becomes the most recently used.
        value(EXAMPLE, mount="kv0")
        self.assertEqual(len(self.fake.requests), cap, "kv0 should be cached")
        # Adding one more must therefore evict kv1, not kv0.
        value(EXAMPLE, mount="fresh")
        self.assertEqual(len(_client._defaults), cap)
        self.assertIn((None, "kv0"), _client._defaults)
        self.assertNotIn((None, "kv1"), _client._defaults)
        # kv0 is still served from cache; kv1 would not be.
        value(EXAMPLE, mount="kv0")
        self.assertEqual(len(self.fake.requests), cap + 1)

    def test_an_evicted_instance_is_released_with_its_secret(self):
        cap = _client.MAX_DEFAULT_INSTANCES
        value(EXAMPLE, mount="kv0")
        evicted = _client._defaults[(None, "kv0")]
        reference = weakref.ref(evicted)
        del evicted
        for index in range(1, cap + 1):
            value(EXAMPLE, mount="kv%d" % index)
        self.assertNotIn((None, "kv0"), _client._defaults)
        gc.collect()
        self.assertIsNone(reference(), "the evicted instance must be released")
        # Releasing it is what closes its sealed descriptor; that the descriptor
        # really closes on collection is pinned in test_memory.py.

    def test_an_instance_selected_before_eviction_still_works(self):
        # Eviction must not close an instance a caller may already hold; it only
        # drops the pool's reference. Forced deterministically, not raced.
        instance = _client._default_vault(None, None)
        self.assertEqual(_fakes.revealed(instance.value(EXAMPLE)), self.fake.fields)
        for index in range(_client.MAX_DEFAULT_INSTANCES):
            value(EXAMPLE, mount="kv%d" % index)
        self.assertNotIn((None, None), _client._defaults)
        self.assertFalse(instance._closed)
        self.assertEqual(_fakes.revealed(instance.value(EXAMPLE)), self.fake.fields)
        instance.close()

    def test_concurrent_module_level_reads_do_not_fail(self):
        mounts = ["kv%d" % index for index in range(20)]

        def read(index):
            return value(EXAMPLE, mount=mounts[index % len(mounts)])

        with ThreadPoolExecutor(max_workers=8) as pool_:
            results = list(pool_.map(read, range(40)))
        self.assertEqual([_fakes.revealed(result) for result in results],
                         [self.fake.fields] * 40)
        self.assertLessEqual(len(_client._defaults), _client.MAX_DEFAULT_INSTANCES)

    def test_a_missing_token_is_reported_before_invalid_configuration(self):
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN_FILE": ""}):
            with self.assertRaises(VaultTokenMissingError):
                value(EXAMPLE, mount="not/a/mount")
            with self.assertRaises(VaultTokenMissingError):
                value(EXAMPLE, base_url="http://insecure.example")
        self.assertEqual(self.fake.requests, [])
        # With a token present the configuration error surfaces instead.
        with self.assertRaises(VaultError) as caught:
            value(EXAMPLE, mount="not/a/mount")
        self.assertNotIsInstance(caught.exception, VaultTokenMissingError)

    def test_a_mount_override_keeps_its_own_cache(self):
        self.assertEqual(_fakes.revealed(value(EXAMPLE, mount="kv")), self.fake.fields)
        self.assertEqual(_fakes.revealed(value(EXAMPLE, mount="kv")), self.fake.fields)
        self.assertEqual(len(self.fake.requests), 1)
        self.assertEqual(self.fake.requests[0].path, "/v1/kv/data/" + EXAMPLE)

    def test_overrides_do_not_share_a_cache(self):
        value(EXAMPLE)
        value(EXAMPLE, mount="kv")
        value(EXAMPLE)
        self.assertEqual(len(self.fake.requests), 2)

    def test_a_missing_token_propagates(self):
        os.environ["ECMWF_VAULT_TOKEN_FILE"] = ""
        with self.assertRaises(VaultTokenMissingError):
            value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_clear_cache_and_close_are_safe_with_no_default(self):
        close()
        clear_cache()
        close()


class RevealedHelperTests(unittest.TestCase):
    """The assertion helper must not be able to pass for the wrong reason."""

    def test_it_refuses_a_value_that_is_not_wrapped(self):
        with self.assertRaises(AssertionError):
            _fakes.revealed({"password": "plain"})

    def test_it_refuses_a_value_that_reveals_another_secret(self):
        with self.assertRaises(AssertionError):
            _fakes.revealed({"password": Secret(Secret("plain"))})


def first_bytes(fields):
    """The canonical payload the package stores for ``fields``."""
    return _client.json.dumps(fields, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii")


class TokenInfoTests(unittest.TestCase):
    """``Vault.token_info``: the token's own details from ``auth/token/lookup-self``.

    The metadata is not a secret read, and that shows up in what this method does *not* do:
    no sealed memory file, so no swap check; no secret name, so no production-naming rule.
    Both are asserted rather than assumed, because an unstated difference is one that gets
    "tidied away" later.
    """

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.metadata = {"ttl": 7112, "creation_ttl": 43200, "expire_time":
                         "2026-11-14T21:00:00.000000000Z", "renewable": True,
                         "num_uses": 0, "policies": ["default"],
                         "display_name": "a-token", "accessor": "acc-1"}
        self.fake.raw = _client.json.dumps({"data": self.metadata}).encode("utf-8")
        environment = _fakes.vault_environment(
            token=TOKEN,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)

    def vault(self, **overrides):
        instance = _fakes.make_vault(self.fake, **overrides)
        self.addCleanup(instance.close)
        return instance

    def test_it_reads_the_token_lookup_endpoint_and_returns_what_vault_said(self):
        self.assertEqual(self.vault().token_info(), self.metadata)
        self.assertEqual(self.fake.requests[0].path, "/v1/auth/token/lookup-self")

    def test_an_unknown_field_reaches_the_caller(self):
        self.fake.raw = _client.json.dumps(
            {"data": {"brand_new_field": {"nested": [1, 2]}}}).encode("utf-8")
        self.assertEqual(self.vault().token_info(),
                         {"brand_new_field": {"nested": [1, 2]}})

    def test_a_closed_instance_refuses_before_asking(self):
        instance = self.vault()
        instance.close()
        with self.assertRaises(VaultError) as caught:
            instance.token_info()
        self.assertEqual(str(caught.exception), _client.CLOSED_MESSAGE)
        self.assertEqual(self.fake.requests, [])

    def test_nothing_secret_is_retained(self):
        # No memfd, so require_support is never consulted: this works in a process that
        # cannot create one, which is also why the swap policy has nothing to guard here.
        with mock.patch.object(_client, "require_support") as support:
            self.vault().token_info()
        self.assertEqual(support.call_count, 0)

    def test_the_swap_policy_is_not_applied_to_a_lookup(self):
        # Deliberate, and documented in the method: the swap policy exists because a sealed
        # memory file holding a *secret* can be paged out, and a lookup retains no secret.
        # Enforcing it here would refuse to report a token's expiry on a swapping host for
        # a reason that does not apply.
        with mock.patch.object(_client, "enforce") as enforce:
            self.vault(swap_policy="refuse").token_info()
        self.assertEqual(enforce.call_count, 0)

    def test_the_process_is_hardened_when_that_is_configured(self):
        # The token itself is in this process's memory, so hardening does apply.
        with mock.patch.object(_client, "harden_process") as harden:
            self.vault(harden=True).token_info()
        self.assertEqual(harden.call_count, 1)

    def test_hardening_is_skipped_when_it_is_switched_off(self):
        with mock.patch.object(_client, "harden_process") as harden:
            self.vault(harden=False).token_info()
        self.assertEqual(harden.call_count, 0)

    def test_a_plaintext_token_can_still_describe_itself(self):
        # The production-naming rule is about which token may serve a *named secret*, and a
        # lookup has no secret name. So a token in the plaintext config file is refused for
        # a production secret and still able to report its own details — which is what you
        # want when the question is "is this token any good?".
        path = _fakes.write_sealed_token_file(TOKEN)
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN_FILE=path,
                                      ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            self.assertEqual(self.vault().token_info()["ttl"], 7112)

    def test_an_id_that_is_the_token_is_withheld(self):
        # For a service token Vault reports the token's own value as the id. That is a
        # credential, and this package does not return one as a plain string — so it is
        # replaced, decided from what Vault sent rather than from an assumption about token
        # types, and the key stays so the shape does not change.
        self.fake.raw = _client.json.dumps(
            {"data": {"id": TOKEN, "ttl": 60}}).encode("utf-8")
        info = self.vault().token_info()
        self.assertEqual(info["id"], _client.WITHHELD_ID)
        self.assertNotIn(TOKEN, repr(info))

    def test_an_id_that_is_not_the_token_is_returned_as_sent(self):
        self.fake.raw = _client.json.dumps(
            {"data": {"id": "8f9d8f37-6c1f-4dc6-9d9e-4c0e0e", "ttl": 60}}).encode("utf-8")
        self.assertEqual(self.vault().token_info()["id"],
                         "8f9d8f37-6c1f-4dc6-9d9e-4c0e0e")

    def test_a_missing_id_is_not_invented(self):
        self.fake.raw = _client.json.dumps({"data": {"ttl": 60}}).encode("utf-8")
        self.assertNotIn("id", self.vault().token_info())

    def test_the_tls_context_is_built_once_per_instance(self):
        # As for a secret read: the context belongs to the instance, so a second lookup
        # reuses it rather than rebuilding the trust store.
        instance = self.vault()
        instance.token_info()
        first = instance._context
        self.assertIsNotNone(first)
        instance.token_info()
        self.assertIs(first, instance._context)

    def test_a_refused_token_is_reported_with_the_lookups_own_wording(self):
        self.fake.status = 403
        with self.assertRaises(VaultPermissionError) as caught:
            self.vault().token_info()
        message = str(caught.exception)
        self.assertIn("look itself up", message)
        # The causes are named without the message asserting which one it was: a policy can
        # deny this lookup for a perfectly good token.
        self.assertIn("expired or been revoked", message)
        self.assertIn("policy", message)


class CubbyholeTests(unittest.TestCase):
    """Reading the token's own cubbyhole: same guarantees, different request.

    A cubbyhole is per-token, so nothing here can be shared with another credential; and
    because the two engines differ only in the response shape, the tests here are about the
    things that must *not* differ — the sealed memfd, the cache namespacing, the one token
    resolution per call.
    """

    PATH = "madt/efas"

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value", "user": "cems"}
        # ECMWF_VAULT_ADDR is pinned to the fake rather than left to the package default, so
        # a module-level read through the process-wide instance pool cannot reach the real
        # host. An instance built by make_vault takes the address explicitly anyway.
        environment = _fakes.vault_environment(
            token=TOKEN,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle)
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.vault = _fakes.make_vault(self.fake)
        self.addCleanup(self.vault.close)

    # -- the request ------------------------------------------------------

    def test_the_read_targets_the_cubbyhole_and_not_the_mount(self):
        self.assertEqual(_fakes.revealed(self.vault.cubbyhole_read(self.PATH)),
                         self.fake.fields)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/" + self.PATH])

    def test_the_mount_is_never_consulted(self):
        # A cubbyhole has no mount, so an instance configured for an unusual one must still
        # produce the same request; this is what stops the old "/v1/x/data/y" mistake.
        instance = _fakes.make_vault(self.fake, mount="kv-enterprise")
        self.addCleanup(instance.close)
        instance.cubbyhole_read(self.PATH)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/" + self.PATH])

    def test_a_flat_response_is_accepted_where_a_nested_one_is_required(self):
        # The fake answers a cubbyhole request with the flat shape; the point is that the
        # read succeeds rather than being rejected as an unexpected shape.
        fields = self.vault.cubbyhole_read(self.PATH)
        self.assertEqual(_fakes.revealed(fields), self.fake.fields)

    def test_one_field_of_a_cubbyhole(self):
        secret = self.vault.cubbyhole_read(self.PATH, field="password")
        self.assertIsInstance(secret, Secret)
        self.assertEqual(secret.reveal(), "synthetic-value")

    def test_an_absent_field_is_the_same_error_as_from_a_mount(self):
        with self.assertRaises(SecretFieldMissingError):
            self.vault.cubbyhole_read(self.PATH, field="nope")

    # -- the guarantees that must not differ ------------------------------

    def test_a_cubbyhole_read_is_a_secret_and_never_a_string(self):
        fields = self.vault.cubbyhole_read(self.PATH)
        self.assertTrue(all(isinstance(field, Secret) for field in fields.values()))
        self.assertEqual("%s" % fields["password"], "<Secret>")
        with self.assertRaises(TypeError):
            json.dumps(fields)

    def test_a_cubbyhole_secret_is_sealed_in_a_memory_file(self):
        memory = self.vault._obtain(self.PATH, token=TOKEN, cache=True, cubbyhole=True)
        try:
            self.assertIsInstance(memory, SecretMemoryFile)
            self.assertEqual(json.loads(memory.read().decode("utf-8")), self.fake.fields)
            with self.assertRaises(OSError):
                os.write(memory.fd, b"appended")
        finally:
            memory.close()

    def test_a_cubbyhole_read_resolves_the_token_once(self):
        with mock.patch.object(_client, "_read_token",
                               wraps=_client._read_token) as read:
            self.vault.cubbyhole_read(self.PATH)
        self.assertEqual(read.call_count, 1)

    # -- caching ----------------------------------------------------------

    def test_a_cubbyhole_path_and_a_mount_path_do_not_share_a_cache_entry(self):
        # The key is (engine, target), and the same path string means two different secrets
        # depending on which engine was asked. Serving the first read's bytes to the second
        # would be a silent substitution rather than a cache miss.
        self.assertEqual(_fakes.revealed(self.vault.value(self.PATH)), self.fake.fields)
        self.fake.fields = {"password": "cubby-value"}
        self.assertEqual(self.vault.cubbyhole_read(self.PATH)["password"].reveal(),
                         "cubby-value")
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/groups/data/" + self.PATH, "/v1/cubbyhole/" + self.PATH])

    def test_a_repeated_cubbyhole_read_is_served_from_the_cache(self):
        self.vault.cubbyhole_read(self.PATH)
        self.vault.cubbyhole_read(self.PATH)
        self.assertEqual(len(self.fake.requests), 1)

    def test_cache_false_refetches_a_cubbyhole(self):
        self.vault.cubbyhole_read(self.PATH, cache=False)
        self.vault.cubbyhole_read(self.PATH, cache=False)
        self.assertEqual(len(self.fake.requests), 2)

    def test_an_uncached_cubbyhole_read_does_not_populate_the_cache(self):
        self.vault.cubbyhole_read(self.PATH, cache=False)
        self.vault.cubbyhole_read(self.PATH)
        self.assertEqual(len(self.fake.requests), 2)

    def test_a_different_token_is_not_served_a_cached_cubbyhole(self):
        # Cubbyhole contents belong to the token that wrote them, so serving a second token
        # the cached entry is worse than wrong: it is a value that token cannot read at all.
        self.assertEqual(self.vault.cubbyhole_read(self.PATH, field="password").reveal(),
                         "synthetic-value")
        self.fake.fields = {"password": "other-cubby"}
        _fakes.write_sealed_token_file(
            "hvs.other-token",
            directory=os.path.dirname(os.environ["ECMWF_VAULT_TOKEN_FILE"]))
        self.assertEqual(self.vault.cubbyhole_read(self.PATH, field="password").reveal(),
                         "other-cubby")
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual([request.headers["X-Vault-Token"] for request in self.fake.requests],
                         [TOKEN, "hvs.other-token"])

    def test_the_same_target_under_two_engines_does_not_share_a_cache_entry(self):
        # The overlap a target alone cannot see: a KV read through the mount "cubbyhole" of
        # path "x", and a cubbyhole read of path "data/x", are both /v1/cubbyhole/data/x —
        # parsed by two different shape checks. Sharing one entry would hand one engine the
        # other's fields without ever making a request.
        instance = _fakes.make_vault(self.fake, mount="cubbyhole")
        self.addCleanup(instance.close)

        self.fake.raw = b'{"data":{"data":{"v":"from-kv"},"metadata":{}}}'
        self.assertEqual(instance.value("x", field="v").reveal(), "from-kv")
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/data/x"])

        self.fake.raw = b'{"data":{"v":"from-cubbyhole"}}'
        self.assertEqual(instance.cubbyhole_read("data/x", field="v").reveal(),
                         "from-cubbyhole")
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/data/x", "/v1/cubbyhole/data/x"])

    def test_a_read_through_a_mount_called_cubbyhole_is_not_a_cubbyhole_read(self):
        # The truthful answer: cubbyhole is not a KV engine, so a KV-shaped response never
        # arrives there. The read is refused on shape rather than served something else's body.
        instance = _fakes.make_vault(self.fake, mount="cubbyhole")
        self.addCleanup(instance.close)
        with self.assertRaises(VaultResponseError):
            instance.value(self.PATH)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/data/" + self.PATH])

    # -- refusal before any work ------------------------------------------

    def test_a_closed_instance_refuses_before_reading_the_token(self):
        self.vault.close()
        with self.assertRaises(VaultError):
            self.vault.cubbyhole_read(self.PATH)
        self.assertEqual(self.fake.requests, [])

    def test_an_invalid_path_is_refused_before_any_request(self):
        for path in ("", "..", "a/../b", "with space"):
            with self.subTest(path=path):
                with self.assertRaises(InvalidSecretPathError):
                    self.vault.cubbyhole_read(path)
        self.assertEqual(self.fake.requests, [])

    def test_the_module_level_helper_uses_a_default_instance(self):
        self._point_the_default_pool_at_this_fake()
        self.assertEqual(_fakes.revealed(cubbyhole_read(self.PATH)), self.fake.fields)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/" + self.PATH])

    def test_the_module_level_helper_resolves_the_token_once(self):
        self._point_the_default_pool_at_this_fake()
        with mock.patch.object(_client, "_read_token",
                               wraps=_client._read_token) as read:
            cubbyhole_read(self.PATH)
        self.assertEqual(read.call_count, 1)

    def _point_the_default_pool_at_this_fake(self):
        """Empty the instance pool so the helper builds one aimed at *this* fake.

        The pool is process-wide and keyed by (mount, base URL); an instance another test left
        in it would carry that test's server address. Clearing the secret cache does not empty
        the pool, so it is closed, and the module-level API reopened for this test only.
        """
        _client.close()
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        self.addCleanup(_client.close)


if __name__ == "__main__":
    unittest.main()
