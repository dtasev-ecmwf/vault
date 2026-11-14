# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The three commands replacing a token that Vault refused, and carrying on.

This is the wiring between the commands and the login workflow — that a refusal becomes one
question and one retry rather than a failure, and that a token which cannot be replaced is
said rather than asked about. The workflow itself is tested in ``test_login.py``.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import _client, _login
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import kubectl_vault, vault_expiry, vaultenv

OLD = "hvs.synthetic-expired-token"
NEW = "hvs.synthetic-fresh-token"
SECRET = "user_applications_and_services_team/cems_web"
FIELD = "k8s-cems-test"
LATER = "2026-11-14T21:00:00.000000000Z"


class RetryTestCase(unittest.TestCase):
    """A refused token in a sealed file, a fake Vault, and no terminal of its own."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-retry-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.token_path = os.path.join(self.home, "token")
        _fakes.write_sealed_token_file(OLD, directory=self.home)
        environment = _fakes.vault_environment(
            ECMWF_VAULT_TOKEN_FILE=self.token_path,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        # The commands that read a secret use the module-level default instances, which keep
        # their address from whichever test built them first — so this test's fake has to be
        # the one that instance is built against, and the instance has to go afterwards.
        reopen = mock.patch.object(_client, "_default_closed", False)
        reopen.start()
        self.addCleanup(reopen.stop)
        self.addCleanup(_client.close)
        _client.clear_cache()
        self.fake.status = 403
        self.prefixes = []

    def logging_in(self):
        """Patch ``log_in`` to do what a real one would: a fresh token file, and a Vault that
        accepts it — so the retried request is what proves the token was replaced."""
        def pretend(*, prefix, **kwargs):
            _fakes.write_sealed_token_file(NEW, directory=self.home)
            self.fake.status = 200
            self.prefixes.append(prefix)
            return {"expire_time": LATER}

        return mock.patch.object(_login, "log_in", side_effect=pretend)

    def tokens_seen(self):
        return [request.headers["X-Vault-Token"] for request in self.fake.requests]


class VaultenvRetryTests(RetryTestCase):
    def test_a_refused_token_is_replaced_and_the_secret_is_read(self):
        self.fake.fields = {"PASSWORD": "s3cret"}
        stderr = io.StringIO()
        with self.logging_in(), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(contract, "run_child", return_value=0) as run_child, \
                contextlib.redirect_stderr(stderr):
            status = vaultenv.run(["--secret", SECRET, "--", "/bin/true"])
        self.assertEqual(status, 0)
        self.assertEqual(self.prefixes, ["vaultenv:"])
        self.assertEqual(self.tokens_seen(), [OLD, OLD, NEW])
        self.assertEqual(run_child.call_count, 1)

    def test_a_refused_token_with_no_terminal_is_reported_rather_than_asked_about(self):
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False), \
                mock.patch.object(_login, "log_in") as log_in, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = vaultenv.run(["--secret", SECRET, "--", "/bin/true"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        log_in.assert_not_called()
        self.assertIn("vaultenv: ", stderr.getvalue())
        self.assertIn("no terminal", stderr.getvalue())


class KubectlRetryTests(RetryTestCase):
    def test_a_refused_token_is_replaced_and_the_kubeconfig_is_read(self):
        self.fake.fields = {FIELD: "apiVersion: v1\nkind: Config\n"}
        stderr = io.StringIO()
        with self.logging_in(), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(contract, "run_child", return_value=0) as run_child, \
                contextlib.redirect_stderr(stderr):
            status = kubectl_vault.run(
                ["--secret", SECRET, "--field", FIELD, "--kubectl", "kubectl",
                 "--", "version"])
        self.assertEqual(status, 0)
        self.assertEqual(self.prefixes, ["kubectl_vault:"])
        self.assertEqual(self.tokens_seen(), [OLD, OLD, NEW])
        self.assertEqual(run_child.call_count, 1)

    def test_a_refused_token_with_no_terminal_is_reported_rather_than_asked_about(self):
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False), \
                mock.patch.object(_login, "log_in") as log_in, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = kubectl_vault.run(
                ["--secret", SECRET, "--field", FIELD, "--kubectl", "kubectl", "--",
                 "version"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        log_in.assert_not_called()
        self.assertIn("kubectl_vault: ", stderr.getvalue())
        self.assertIn("no terminal", stderr.getvalue())


class VaultExpiryRetryTests(RetryTestCase):
    def test_a_refused_token_is_replaced_and_the_report_is_written(self):
        self.fake.raw = json.dumps({"data": {"expire_time": LATER}}).encode("utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.logging_in(), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = vault_expiry.run([])
        self.assertEqual(status, 0)
        self.assertEqual(self.prefixes, ["vault_expiry:"])
        self.assertEqual(self.tokens_seen(), [OLD, OLD, NEW])
        self.assertIn("expire time", stdout.getvalue())

    def test_a_refused_token_with_no_terminal_is_reported_rather_than_asked_about(self):
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False), \
                mock.patch.object(_login, "log_in") as log_in, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = vault_expiry.run([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        log_in.assert_not_called()
        self.assertIn("vault_expiry: ", stderr.getvalue())
        self.assertIn("no terminal", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
