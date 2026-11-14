# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The token file is read when a call is made, and nothing about it is remembered.

There is one token source — the sealed token file — so what is left to get wrong is
*when* it is read. Two things matter and are asserted by counting the reads themselves
rather than by reading the code: a public call must read the file exactly once (a second
read would be a second decryption for nothing), and no state may survive a call, because
`vault_login` replacing the file has to take effect on the next call rather than whenever
a cache happens to expire.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import (
    InvalidSecretPathError,
    Vault,
    VaultError,
    VaultTokenFileError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
    _client,
    _config,
    clear_cache,
    value,
)

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
FIRST = "hvs.synthetic-first-token"
SECOND = "hvs.synthetic-second-token"


class CountedReads:
    """Wrap `_config.read_token_file` so a test can count the reads a call makes."""

    def __init__(self, testCase: unittest.TestCase):
        self.paths = []
        real = _config.read_token_file

        def counting(path):
            self.paths.append(path)
            return real(path)

        patch = mock.patch.object(_config, "read_token_file", counting)
        patch.start()
        testCase.addCleanup(patch.stop)

    def __len__(self):
        return len(self.paths)


class ReadOnceTests(unittest.TestCase):
    """One read per public call, whichever way in the secret is asked for."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}
        # close() is terminal for the module-level API by design, so a test that needs that
        # API again has to reopen it explicitly.
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        self.addCleanup(_client.close)
        _client.clear_cache()
        self.reads = CountedReads(self)
        environment = _fakes.vault_environment(
            token=FIRST,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)

    # -- counting ---------------------------------------------------------

    def test_one_call_reads_the_token_file_once(self):
        value(EXAMPLE)
        self.assertEqual(len(self.reads), 1)

    def test_asking_for_a_field_does_not_read_it_twice(self):
        value(EXAMPLE, field="password")
        self.assertEqual(len(self.reads), 1)

    def test_two_calls_read_it_twice_because_nothing_is_cached(self):
        value(EXAMPLE)
        value(EXAMPLE)
        self.assertEqual(len(self.reads), 2)

    def test_an_uncached_call_still_reads_it_once(self):
        value(EXAMPLE, cache=False)
        self.assertEqual(len(self.reads), 1)

    def test_an_instance_reads_it_once_per_call(self):
        vault = _fakes.make_vault(self.fake)
        self.addCleanup(vault.close)
        vault.value(EXAMPLE)
        vault.value(EXAMPLE)
        self.assertEqual(len(self.reads), 2)

    def test_keys_and_memory_file_each_read_it_once(self):
        vault = _fakes.make_vault(self.fake)
        self.addCleanup(vault.close)
        before = len(self.reads)
        vault.keys(EXAMPLE)
        self.assertEqual(len(self.reads) - before, 1)
        before = len(self.reads)
        memory = vault.memory_file(EXAMPLE)
        self.addCleanup(memory.close)
        self.assertEqual(len(self.reads) - before, 1)

    # -- refusing before reading ------------------------------------------

    def test_a_closed_instance_is_refused_before_the_token_is_read(self):
        vault = _fakes.make_vault(self.fake)
        vault.close()
        with self.assertRaises(VaultError):
            vault.value(EXAMPLE)
        self.assertEqual(len(self.reads), 0)

    def test_a_closed_module_is_refused_before_the_token_is_read(self):
        # close() is terminal for the module-level helpers, and it has to be decided before
        # anything is read: a call that cannot succeed should not decrypt a credential.
        _client.close()
        with self.assertRaises(VaultError):
            value(EXAMPLE)
        self.assertEqual(len(self.reads), 0)

    def test_an_instance_closed_between_the_check_and_the_lock_is_still_refused(self):
        # _obtain re-checks under the lock, because close() can land after the public call
        # passed its own check. Nothing is fetched, and the token was already read: that is the
        # order, and the second check is what keeps it honest.
        vault = _fakes.make_vault(self.fake)
        real = _config.read_token_file      # taken before the patch, to call it once

        def close_as_it_reads(path_argument):
            vault.close()
            return real(path_argument)

        with mock.patch.object(_config, "read_token_file", close_as_it_reads):
            with self.assertRaises(VaultError) as caught:
                vault.value(EXAMPLE)
        self.assertIn("closed", str(caught.exception))
        self.assertEqual(len(self.reads), 1)

    def test_the_pool_refuses_to_build_an_instance_after_close(self):
        # _default_vault checks the module state itself: close() can land between the caller's
        # check and this one, and an instance built after it would outlive the "no more reads"
        # promise.
        _client.close()
        with mock.patch.object(_client, "_default_closed", True):
            with self.assertRaises(VaultError) as caught:
                _client._default_vault("groups", None)
        self.assertIn("construct a Vault", str(caught.exception))

    def test_a_bad_path_is_reported_after_the_token_is_read(self):
        # Reading first is the documented order: a caller with both a bad token and a bad path
        # hears about the credential, which is the thing they can act on without a traceback.
        with self.assertRaises(InvalidSecretPathError):
            value("not/a/valid/path//")
        self.assertEqual(len(self.reads), 1)


class NothingIsRememberedTests(unittest.TestCase):
    """A replaced file is the new token on the very next call."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        self.addCleanup(_client.close)
        _client.clear_cache()

    def test_a_replaced_token_file_is_used_on_the_next_call(self):
        path = _fakes.token_file(FIRST)
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN_FILE=path,
                                      ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            value(EXAMPLE, cache=False)
            _fakes.write_sealed_token_file(SECOND, directory=os.path.dirname(path))
            value(EXAMPLE, cache=False)
        tokens = [request.headers["X-Vault-Token"] for request in self.fake.requests]
        self.assertEqual(tokens, [FIRST, SECOND])

    def test_a_file_that_becomes_unreadable_is_refused_on_the_next_call(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-becomes-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "token")
        _fakes.write_sealed_token_file(FIRST, directory=directory)
        environment = _fakes.vault_environment(
            ECMWF_VAULT_TOKEN_FILE=path,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        value(EXAMPLE, cache=False)
        os.chmod(directory, 0o755)  # a directory another user can reach
        with self.assertRaises(VaultTokenFileError):
            value(EXAMPLE, cache=False)


class NoTokenTests(unittest.TestCase):
    """What a caller hears when the token file is not there, and what they never hear."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}

    def read(self):
        """One read through an instance of this test's own, so no module state is involved."""
        vault = Vault(base_url=self.fake.base_url, ca_bundle=self.fake.ca_bundle,
                      swap_policy="allow", harden=False)
        self.addCleanup(vault.close)
        return vault.value(EXAMPLE)

    def test_no_token_anywhere_fails_before_any_request(self):
        with _fakes.vault_environment(ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            with self.assertRaises(VaultTokenMissingError) as caught:
                self.read()
        self.assertIn("vault_login", str(caught.exception))
        self.assertEqual(self.fake.requests, [])

    def test_the_message_names_the_file_and_what_fills_it(self):
        # The only thing a caller can be told to do is the thing that works.
        with _fakes.vault_environment(ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            with self.assertRaises(VaultTokenMissingError) as caught:
                self.read()
        message = str(caught.exception)
        self.assertIn("token file", message)
        self.assertIn("vault_login", message)

    def test_a_file_named_by_the_environment_that_does_not_exist_is_its_own_error(self):
        missing = _fakes.absent_token_file_path()
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN_FILE=missing,
                                      ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            with self.assertRaises(VaultTokenFileError) as caught:
                self.read()
        self.assertIn("ECMWF_VAULT_TOKEN_FILE", str(caught.exception))
        self.assertEqual(self.fake.requests, [])

    def test_an_empty_file_is_no_token_rather_than_a_token(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-empty-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "token")
        _fakes.write_file("", directory=directory)
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN_FILE=path,
                                      ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            with self.assertRaises(VaultTokenMissingError):
                self.read()

    def test_a_malformed_token_is_refused_and_never_reaches_the_transport(self):
        # `hvs.` marks a token in the clear, so a bad one is judged as a token here rather than
        # sent on to http.client, whose rejection message would carry the value.
        for token in ("hvs.bad token", "hvs.tokén", "hvs.two\nlines"):
            with self.subTest(token=repr(token)):
                path = _fakes.write_file(token)
                self.addCleanup(shutil.rmtree, os.path.dirname(path), True)
                with _fakes.vault_environment(ECMWF_VAULT_TOKEN_FILE=path,
                                              ECMWF_VAULT_ADDR=self.fake.base_url,
                                              ECMWF_VAULT_SWAP_POLICY="allow",
                                              ECMWF_VAULT_HARDEN="0"):
                    with self.assertRaises(VaultTokenInvalidError) as caught:
                        self.read()
                    self.assertNotIn(token, str(caught.exception))
        self.assertEqual(self.fake.requests, [])


if __name__ == "__main__":
    unittest.main()
