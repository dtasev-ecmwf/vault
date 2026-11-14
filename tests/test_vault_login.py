# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vault_login`` command: that it runs the login flow, and how it fails.

The flow itself is tested in ``test_login.py``; what is checked here is the thin command around
it — the arguments it refuses, the prefix it reports under, and the exit status it promises.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import VaultError
from ecmwf_vault import _login, _sealed_token_file
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import vault_login

TOKEN = "hvs.synthetic-login-token"
LATER = "2026-11-14T21:00:00+00:00"


class RunTests(unittest.TestCase):
    def test_the_login_flow_runs_under_this_command_s_prefix(self):
        with mock.patch.object(vault_login._login, "log_in") as log_in:
            self.assertEqual(vault_login.run([]), 0)
        log_in.assert_called_once_with(prefix="vault_login:")

    def test_a_refused_login_is_reported_with_the_prefix_and_status_2(self):
        with mock.patch.object(vault_login._login, "log_in",
                               side_effect=VaultError("no token was entered")):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = vault_login.run([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_login: no token was entered", stderr.getvalue())

    def test_an_unrecognised_argument_is_refused_by_argparse(self):
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                vault_login.run(["--not-a-thing"])
        self.assertEqual(caught.exception.code, 2)


class EndToEndTests(unittest.TestCase):
    """The command against the loopback fake, with the terminal the only thing stubbed."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.raw = json.dumps(
            {"data": {"expire_time": LATER, "ttl": 3600}}).encode("utf-8")
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-login-command-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.token_path = os.path.join(self.home, "token")
        environment = _fakes.vault_environment(
            ECMWF_VAULT_TOKEN_FILE=self.token_path,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)

    def test_a_pasted_token_is_checked_and_stored_sealed(self):
        stderr = io.StringIO()
        with mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login.getpass, "getpass", return_value=TOKEN), \
                contextlib.redirect_stderr(stderr):
            status = vault_login.run([])
        self.assertEqual(status, 0)
        with open(self.token_path, "rb") as handle:
            self.assertEqual(_sealed_token_file.unseal(handle.read()), TOKEN)
        self.assertIn("expires at %s" % LATER, stderr.getvalue())
        self.assertNotIn(TOKEN, stderr.getvalue())

    def test_the_token_never_reaches_the_command_s_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login.getpass, "getpass", return_value=TOKEN), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            vault_login.run([])
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(TOKEN, stderr.getvalue())

    def test_a_login_that_ends_at_the_end_of_input_is_status_2(self):
        stderr = io.StringIO()
        with mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login.getpass, "getpass", side_effect=EOFError), \
                contextlib.redirect_stderr(stderr):
            status = vault_login.run([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_login: no token was entered", stderr.getvalue())
        self.assertFalse(os.path.exists(self.token_path))

    def test_no_terminal_at_all_is_status_2_rather_than_a_read_of_stdin(self):
        stderr = io.StringIO()
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False), \
                contextlib.redirect_stderr(stderr):
            status = vault_login.run([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_login: there is no terminal", stderr.getvalue())
        self.assertFalse(os.path.exists(self.token_path))


class MainTests(unittest.TestCase):
    def test_main_passes_argparses_status_through(self):
        with mock.patch.object(sys, "argv", ["vault_login", "--not-a-thing"]):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = vault_login.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_login: ", stderr.getvalue())

    def test_main_returns_zero_when_a_token_was_stored(self):
        with mock.patch.object(sys, "argv", ["vault_login"]), \
                mock.patch.object(vault_login._login, "log_in"):
            self.assertEqual(vault_login.main(), 0)


if __name__ == "__main__":
    unittest.main()
