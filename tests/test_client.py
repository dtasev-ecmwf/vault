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
    value,
)
from ecmwf_vault import _client

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TOKEN = "synthetic-vault-token"


class ClientTests(unittest.TestCase):
    def setUp(self):
        # Isolate the environment first: a Vault built under an inherited
        # ECMWF_VAULT_* variable would not be the one this test means to build.
        environment = _fakes.vault_environment(ECMWF_VAULT_TOKEN=TOKEN)
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
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": "other-token"}):
            self.assertEqual(self.vault.value(EXAMPLE, field="password").reveal(),
                             "second-value")
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual(self.fake.requests[1].headers["X-Vault-Token"],
                         "other-token")

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
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ECMWF_VAULT_TOKEN", None)
            with self.assertRaises(VaultTokenMissingError) as caught:
                self.vault.value(EXAMPLE)
        self.assertIsInstance(caught.exception, RuntimeError)
        self.assertEqual(self.fake.requests, [])

    def test_a_blank_token_is_rejected(self):
        for blank in ("", "   ", "\n"):
            with self.subTest(token=blank):
                with mock.patch.dict(os.environ,
                                     {"ECMWF_VAULT_TOKEN": blank}):
                    with self.assertRaises(VaultTokenMissingError):
                        self.vault.value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_the_token_is_re_read_on_every_call(self):
        self.vault.value(EXAMPLE, cache=False)
        os.environ.pop("ECMWF_VAULT_TOKEN", None)
        with self.assertRaises(VaultTokenMissingError):
            self.vault.value(EXAMPLE, cache=False)

    def test_surrounding_whitespace_is_stripped(self):
        with mock.patch.dict(os.environ,
                             {"ECMWF_VAULT_TOKEN": "  " + TOKEN + "\n"}):
            self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.fake.requests[0].headers["X-Vault-Token"], TOKEN)

    def test_a_malformed_token_is_rejected_before_any_request(self):
        for token in ("bad\ntoken", "bad\rtoken", "bad token",
                      "tab\there", "del\x7f", "tok\u00e9n", "\u4e2d\u6587"):
            with self.subTest(token=token):
                with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": token}):
                    with self.assertRaises(VaultTokenInvalidError) as caught:
                        self.vault.value(EXAMPLE)
                self.assertIsInstance(caught.exception, RuntimeError)
                trace = "".join(traceback.format_exception(
                    type(caught.exception), caught.exception,
                    caught.exception.__traceback__))
                for rendering in (str(caught.exception),
                                  repr(caught.exception), trace):
                    self.assertNotIn(token.strip(), rendering)
        self.assertEqual(self.fake.requests, [])

    def test_a_token_with_a_nul_is_rejected(self):
        # The OS environment cannot carry a NUL, so it cannot arrive through
        # os.environ; _read_token must still refuse one, because it is the last
        # check before the token becomes a header value.
        with mock.patch.object(os, "environ",
                               {"ECMWF_VAULT_TOKEN": "bad\x00token"}):
            with self.assertRaises(VaultTokenInvalidError):
                _client._read_token()

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
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN=TOKEN,
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
            ECMWF_VAULT_TOKEN=TOKEN,
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
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ECMWF_VAULT_TOKEN", None)
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
        os.environ.pop("ECMWF_VAULT_TOKEN", None)
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


if __name__ == "__main__":
    unittest.main()
