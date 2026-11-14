# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The login workflow: asking for a token, storing it, and replacing one that ran out.

Driven against the loopback fake for the part that talks to Vault, and with injected
``read``/``write`` for the part that talks to a person — so nothing here needs a terminal and
nothing contacts ``secrets.ecmwf.int``.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from unittest import mock

import _fakes
from ecmwf_vault import (
    VaultError,
    VaultPermissionError,
    VaultTokenMissingError,
    VaultUnavailableError,
)
from ecmwf_vault import _login, _policy, _sealed_token_file

TOKEN = "hvs.synthetic-login-token"
OTHER = "hvs.synthetic-second-token"
LATER = "2026-11-14T21:00:00.000000000Z"
# The one instant those two name, as the diagnostics render it: re-rendered, not passed through.
CANONICAL = "2026-11-14T21:00:00+00:00"


class _Stream:
    """A stand-in for ``sys.stdin`` whose ``isatty`` does whatever the test wants."""

    def __init__(self, answer):
        self.answer = answer

    def isatty(self):
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class _Answers:
    """Feeds a sequence of pastes to the prompt, raising as itself on a failure item."""

    def __init__(self, answers):
        self.answers = iter(answers)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        answer = next(self.answers)
        if isinstance(answer, BaseException):
            raise answer
        return answer


class LoginTestCase(unittest.TestCase):
    """A fake Vault, a throwaway home, and the token file pointing into it."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-login-")
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
        _policy._warned.clear()
        self.addCleanup(_policy._warned.clear)

    def metadata(self, expire_time=LATER):
        return {"expire_time": expire_time, "ttl": 3600}

    def serve_lookup(self, **overrides):
        body = dict(self.metadata())
        body.update(overrides)
        self.fake.raw = json.dumps({"data": body}).encode("utf-8")

    def stored_token(self):
        with open(self.token_path, "rb") as handle:
            return _sealed_token_file.unseal(handle.read())

    def write_token(self, token=TOKEN):
        """A sealed token file where a read would look for one."""
        return _fakes.write_sealed_token_file(token, directory=self.home)


class ConstantsTests(unittest.TestCase):
    def test_the_token_marker_is_the_one_the_token_file_uses(self):
        self.assertEqual(_login.TOKEN_PREFIX, "hvs.")
        self.assertEqual(_login.TOKEN_PREFIX,
                         _sealed_token_file.PLAINTEXT_PREFIX.decode("ascii"))


class StdinIsTerminalTests(unittest.TestCase):
    def test_a_terminal_is_a_terminal(self):
        with mock.patch.object(_login.sys, "stdin", _Stream(True)):
            self.assertTrue(_login.stdin_is_terminal())

    def test_a_stream_that_is_not_a_terminal_is_not_one(self):
        with mock.patch.object(_login.sys, "stdin", _Stream(False)):
            self.assertFalse(_login.stdin_is_terminal())

    def test_no_stdin_at_all_is_not_a_terminal(self):
        with mock.patch.object(_login.sys, "stdin", None):
            self.assertFalse(_login.stdin_is_terminal())

    def test_a_closed_stream_is_not_a_terminal(self):
        with mock.patch.object(_login.sys, "stdin", _Stream(ValueError("closed"))):
            self.assertFalse(_login.stdin_is_terminal())


class RequireTerminalTests(unittest.TestCase):
    def test_a_terminal_is_fine(self):
        with mock.patch.object(_login, "stdin_is_terminal", return_value=True):
            _login.require_terminal()  # nothing to return, and nothing to raise

    def test_a_run_with_no_terminal_is_refused(self):
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False):
            with self.assertRaises(VaultError) as caught:
                _login.require_terminal()
        self.assertIn("no terminal", str(caught.exception))


class ReadWithoutEchoTests(unittest.TestCase):
    def test_the_line_is_returned_when_the_terminal_can_hide_it(self):
        with mock.patch.object(_login.getpass, "getpass", return_value=TOKEN):
            self.assertEqual(_login.read_without_echo("Token: "), TOKEN)

    def test_a_terminal_that_cannot_hide_the_token_is_refused(self):
        # getpass warns and then reads an *echoed* line. The warning is turned into a refusal
        # here, so the fallback never reads the token at all — which is the whole promise.
        def warns(prompt):
            warnings.warn("Can not control echo on the terminal.",
                          _login.getpass.GetPassWarning)
            return TOKEN

        with mock.patch.object(_login.getpass, "getpass", side_effect=warns):
            with self.assertRaises(VaultError) as caught:
                _login.read_without_echo("Token: ")
        self.assertIn("would be shown on screen", str(caught.exception))


class TokenShapeTests(unittest.TestCase):
    def test_a_token_is_recognised(self):
        self.assertTrue(_login.looks_like_a_token(TOKEN))
        self.assertTrue(_login.looks_like_a_token("hvs."))

    def test_something_else_is_not(self):
        for entered in ("", "vault-token", "HVS.upper", "hvs.with space", "hvs.with\ttab"):
            with self.subTest(entered=entered):
                self.assertFalse(_login.looks_like_a_token(entered))


class AskTests(unittest.TestCase):
    """The prompt: reads without echo, and asks again until it looks like a token."""

    def ask(self, answers):
        written = []
        read = _Answers(answers)
        return _login.ask_for_token(read, written.append), written, read

    def test_a_token_is_taken_as_it_is(self):
        token, written, _ = self.ask([TOKEN])
        self.assertEqual(token, TOKEN)
        self.assertEqual(written, [])

    def test_the_prompt_asks_for_a_token(self):
        _, _, read = self.ask([TOKEN])
        self.assertIn("token", read.prompts[0])

    def test_surrounding_whitespace_is_not_part_of_the_token(self):
        token, _, _ = self.ask(["  " + TOKEN + "\n"])
        self.assertEqual(token, TOKEN)

    def test_something_that_is_not_a_token_is_said_and_asked_again(self):
        token, written, read = self.ask(["not a token", TOKEN])
        self.assertEqual(token, TOKEN)
        self.assertEqual(len(read.prompts), 2)
        self.assertEqual(len(written), 1)
        self.assertIn("hvs.", written[0])
        self.assertNotIn("not a token", written[0])

    def test_the_end_of_input_is_a_refusal(self):
        with self.assertRaises(VaultError) as caught:
            self.ask([EOFError()])
        self.assertIn("no token was entered", str(caught.exception))

    def test_an_interrupt_is_a_refusal(self):
        with self.assertRaises(VaultError) as caught:
            self.ask([KeyboardInterrupt()])
        self.assertIn("no token was entered", str(caught.exception))


class ExpiryTextTests(unittest.TestCase):
    """The expiry Vault reported: which instant it names, and how it is written down."""

    def test_the_instant_vault_named_is_what_is_recorded(self):
        self.assertEqual(_login.reported_expiry({"expire_time": LATER}), CANONICAL)

    def test_any_way_of_naming_the_same_instant_renders_the_same_way(self):
        for reported in (LATER, "2026-11-14T21:00:00Z", "2026-11-14T23:00:00+02:00",
                         "2026-11-14T21:00:00", " 2026-11-14T21:00:00 "):
            with self.subTest(reported=reported):
                self.assertEqual(_login.reported_expiry({"expire_time": reported}), CANONICAL)

    def test_a_fraction_of_any_length_is_bounded(self):
        # fromisoformat takes it; a record of 5000 digits is not a record.
        reported = _login.reported_expiry(
            {"expire_time": "2026-11-14T21:00:00." + "9" * 5000 + "Z"})
        self.assertLess(len(reported), 40)
        self.assertTrue(reported.isascii())
        self.assertEqual(_login.parse_expiry(reported).microsecond, 999999)

    def test_a_separator_that_is_not_ascii_is_rendered_canonically(self):
        # fromisoformat accepts any character between the date and the time, including one the
        # ASCII record could not hold at all. Re-rendering is what keeps that out of the file.
        reported = _login.reported_expiry({"expire_time": "2026-11-14\u202f21:00:00"})
        self.assertEqual(reported, CANONICAL)
        self.assertTrue(reported.isascii())

    def test_no_expiry_is_no_expiry(self):
        for info in ({}, {"expire_time": None}, {"expire_time": ""}, {"expire_time": " "},
                     {"expire_time": 0}):
            with self.subTest(info=info):
                self.assertIsNone(_login.reported_expiry(info))

    def test_an_expiry_that_is_not_a_timestamp_is_not_recorded_or_shown(self):
        # The value goes into a plaintext file and onto stderr, so it is checked rather than
        # trusted: a response whose "expiry" is really the token must not put it in either.
        for reported in (TOKEN, "not a time", "2026-13-45T99:99:99Z", "hvs.synthetic"):
            with self.subTest(reported=reported):
                self.assertIsNone(_login.reported_expiry({"expire_time": reported}))

    def test_a_trailing_z_means_utc(self):
        self.assertEqual(_login.parse_expiry(LATER),
                         datetime(2026, 11, 14, 21, 0, tzinfo=timezone.utc))
        self.assertEqual(_login.parse_expiry("2026-11-14T21:00:00Z"),
                         datetime(2026, 11, 14, 21, 0, tzinfo=timezone.utc))

    def test_an_offset_is_honoured(self):
        self.assertEqual(_login.parse_expiry("2026-11-14T21:00:00+02:00"),
                         datetime(2026, 11, 14, 19, 0, tzinfo=timezone.utc))

    def test_nanoseconds_are_kept_to_the_microsecond(self):
        self.assertEqual(_login.parse_expiry("2026-11-14T21:00:00.123456789Z").microsecond,
                         123456)

    def test_a_timestamp_with_no_zone_is_taken_as_utc(self):
        self.assertEqual(_login.parse_expiry("2026-11-14T21:00:00").tzinfo, timezone.utc)

    def test_text_that_is_not_a_timestamp_is_no_record(self):
        for text in ("", "   ", "tomorrow", "2026-13-45T99:99:99Z"):
            with self.subTest(text=text):
                self.assertIsNone(_login.parse_expiry(text))


class StoreSealedTokenTests(LoginTestCase):
    def test_the_token_is_stored_sealed_at_mode_600(self):
        path = _login.store_sealed_token(TOKEN)
        self.assertEqual(path, self.token_path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(self.stored_token(), TOKEN)

    def test_a_named_path_is_used_instead_of_the_resolved_one(self):
        named = os.path.join(self.home, "somewhere", "token")
        self.assertEqual(_login.store_sealed_token(TOKEN, token_path=named), named)
        self.assertTrue(os.path.exists(named))


class VerifyTests(LoginTestCase):
    def test_a_good_token_is_described_by_vault(self):
        self.serve_lookup(id=TOKEN)
        info = _login.verify_token(_fakes.make_vault(self.fake), TOKEN)
        self.assertEqual(info["expire_time"], LATER)

    def test_a_token_reported_as_the_id_is_still_withheld(self):
        # The same lookup the library uses, so a caller cannot print the token by accident.
        self.serve_lookup(id=TOKEN)
        info = _login.verify_token(_fakes.make_vault(self.fake), TOKEN)
        self.assertEqual(info["id"], "(withheld: this is the token itself)")

    def test_hardening_is_applied_when_the_instance_asks_for_it(self):
        self.serve_lookup()
        vault = _fakes.make_vault(self.fake, harden=True)
        with mock.patch.object(_login, "harden_process") as harden:
            _login.verify_token(vault, TOKEN)
        harden.assert_called_once_with()

    def test_hardening_is_not_applied_when_the_instance_does_not_ask(self):
        self.serve_lookup()
        vault = _fakes.make_vault(self.fake, harden=False)
        with mock.patch.object(_login, "harden_process") as harden:
            _login.verify_token(vault, TOKEN)
        harden.assert_not_called()


class LogInTests(LoginTestCase):
    """The whole flow, with the person and the terminal injected."""

    def run_login(self, answers, **kwargs):
        written = []
        info = _login.log_in(read=_Answers(answers), write=written.append,
                             prefix="vault_login:", **kwargs)
        return info, written

    def test_a_token_is_verified_then_stored_sealed(self):
        self.serve_lookup()
        info, written = self.run_login([TOKEN])
        self.assertEqual(info["expire_time"], LATER)
        self.assertEqual(self.stored_token(), TOKEN)
        said = "\n".join(written)
        self.assertIn("expires at %s" % CANONICAL, said)
        self.assertNotIn(TOKEN, said)

    def test_the_address_shown_is_the_one_the_token_is_checked_against(self):
        self.serve_lookup()
        _, written = self.run_login([TOKEN])
        self.assertIn(self.fake.base_url + "/", written[0])

    def test_the_welcome_says_where_to_log_in_and_what_to_click(self):
        # The instruction is this command's user-facing contract: it names the page and the
        # button, so someone who has never seen the Vault web UI knows what to do. Pinned so a
        # later edit cannot quietly drop it.
        self.serve_lookup()
        _, written = self.run_login([TOKEN])
        self.assertIn("Fetch your token by logging into", written[0])
        self.assertIn("Copy token", written[0])
        self.assertIn("expiry date will be shown", written[0])
        self.assertIn("stored encrypted", written[0])

    def test_a_token_vault_refuses_is_not_stored_and_another_is_asked_for(self):
        self.serve_lookup()
        with mock.patch.object(_login, "verify_token",
                               side_effect=[VaultPermissionError("refused"),
                                            self.metadata()]) as verify:
            _, written = self.run_login([TOKEN, OTHER])
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(self.stored_token(), OTHER)
        self.assertIn("nothing was stored", "\n".join(written))

    def test_a_token_with_no_expiry_is_stored_and_said_to_have_none(self):
        self.serve_lookup(expire_time=None)
        _, written = self.run_login([TOKEN])
        self.assertEqual(self.stored_token(), TOKEN)
        self.assertIn("no usable expiry time", "\n".join(written))

    def test_an_unreachable_vault_ends_the_attempt(self):
        with mock.patch.object(_login, "verify_token",
                               side_effect=VaultUnavailableError("down")):
            with self.assertRaises(VaultUnavailableError):
                self.run_login([TOKEN])
        self.assertFalse(os.path.exists(self.token_path))

    def test_a_paste_that_is_not_a_token_and_then_no_more_input_stores_nothing(self):
        with self.assertRaises(VaultError) as caught:
            self.run_login(["not a token", EOFError()])
        self.assertIn("no token was entered", str(caught.exception))
        self.assertFalse(os.path.exists(self.token_path))

    def test_the_terminal_is_used_when_none_is_injected(self):
        # The default ``read`` is the terminal's own, which is what keeps the token off screen.
        self.serve_lookup()
        with mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login.getpass, "getpass", return_value=TOKEN) as getpass:
            with contextlib.redirect_stderr(io.StringIO()):
                _login.log_in(prefix="vault_login:")
        self.assertEqual(getpass.call_count, 1)
        self.assertEqual(self.stored_token(), TOKEN)

    def test_a_run_with_no_terminal_is_refused_rather_than_read_from_stdin(self):
        # Not "read whatever is on stdin": a run with nobody at the keyboard must not treat a
        # pipe as a paste.
        with mock.patch.object(_login, "stdin_is_terminal", return_value=False):
            with self.assertRaises(VaultError) as caught:
                _login.log_in(prefix="vault_login:", write=lambda _: None)
        self.assertIn("no terminal", str(caught.exception))
        self.assertFalse(os.path.exists(self.token_path))

    def test_a_configuration_that_cannot_be_read_is_a_vault_error(self):
        with _fakes.vault_environment(ECMWF_VAULT_ADDR="http://secrets.ecmwf.int",
                                      ECMWF_VAULT_HARDEN="0"):
            with self.assertRaises(VaultError):
                self.run_login([TOKEN])


class PerformTests(LoginTestCase):
    """``run_retrying_once_if_token_lookup_refused``: when it asks, and when it only says why."""

    def refusal(self):
        return VaultPermissionError("the Vault token cannot read this secret (403)")

    def run_it(self, operation):
        return _login.run_retrying_once_if_token_lookup_refused(operation, prefix="p:")

    def test_an_operation_that_works_is_returned_as_it_is(self):
        # Nothing is consulted before the operation: a lookup refusal is evidence about the
        # lookup, and a token that cannot look itself up may still be able to do the work.
        with mock.patch.object(_login, "token_lookup_refused") as lookup, \
                mock.patch.object(_login, "log_in") as log_in:
            self.assertEqual(self.run_it(lambda: "value"), "value")
        lookup.assert_not_called()
        log_in.assert_not_called()

    def test_a_refusal_with_no_terminal_says_to_run_the_command_where_there_is_one(self):
        def operation():
            raise self.refusal()

        with mock.patch.object(_login, "token_lookup_refused", return_value=True), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=False), \
                mock.patch.object(_login, "log_in") as log_in, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(VaultPermissionError):
                self.run_it(operation)
        log_in.assert_not_called()
        self.assertIn("no terminal", stderr.getvalue())

    def test_a_token_that_can_still_describe_itself_is_not_a_reason_to_ask(self):
        # The refusal alone does not say whether the token has gone, so a token that can still
        # describe itself gets no diagnostic at all: it was asked for something it may not read.
        def operation():
            raise self.refusal()

        with mock.patch.object(_login, "token_lookup_refused", return_value=False), \
                mock.patch.object(_login, "log_in") as log_in, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(VaultPermissionError):
                self.run_it(operation)
        log_in.assert_not_called()
        self.assertEqual(stderr.getvalue(), "")

    def test_a_token_that_cannot_be_looked_up_is_replaced_and_retried_once(self):
        attempts = []

        def operation():
            attempts.append(1)
            if len(attempts) == 1:
                raise self.refusal()
            return "value"

        with mock.patch.object(_login, "token_lookup_refused", return_value=True), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login, "log_in") as log_in:
            result = self.run_it(operation)
        self.assertEqual(result, "value")
        self.assertEqual(len(attempts), 2)
        log_in.assert_called_once_with(prefix="p:")

    def test_a_second_refusal_is_handed_back_rather_than_asked_about_again(self):
        attempts = []

        def operation():
            attempts.append(1)
            raise self.refusal()

        with mock.patch.object(_login, "token_lookup_refused", return_value=True), \
                mock.patch.object(_login, "stdin_is_terminal", return_value=True), \
                mock.patch.object(_login, "log_in") as log_in:
            with self.assertRaises(VaultPermissionError):
                self.run_it(operation)
        self.assertEqual(len(attempts), 2)
        log_in.assert_called_once_with(prefix="p:")

    def test_an_error_that_is_not_a_refusal_is_handed_back_untouched(self):
        def operation():
            raise VaultTokenMissingError("no Vault token")

        with mock.patch.object(_login, "token_lookup_refused") as lookup, \
                mock.patch.object(_login, "log_in") as log_in:
            with self.assertRaises(VaultTokenMissingError):
                self.run_it(operation)
        lookup.assert_not_called()
        log_in.assert_not_called()


class TokenLookupRefusedTests(LoginTestCase):
    def test_a_token_that_can_describe_itself_is_not_refused(self):
        self.serve_lookup()
        self.write_token()
        self.assertFalse(_login.token_lookup_refused())

    def test_a_token_that_cannot_be_looked_up_is_refused(self):
        self.write_token()
        self.fake.status = 403
        self.assertTrue(_login.token_lookup_refused())

    def test_a_vault_that_cannot_be_reached_is_no_evidence_about_the_token(self):
        with _fakes.vault_environment(token=TOKEN,
                                      ECMWF_VAULT_ADDR="https://127.0.0.1:1",
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            self.assertFalse(_login.token_lookup_refused())

    def test_a_configuration_that_cannot_be_read_is_no_evidence_either(self):
        with _fakes.vault_environment(ECMWF_VAULT_ADDR="http://secrets.ecmwf.int",
                                      ECMWF_VAULT_HARDEN="0"):
            self.assertFalse(_login.token_lookup_refused())


class PrintDiagnosticTests(unittest.TestCase):
    def test_a_diagnostic_is_prefixed_and_written_to_stderr(self):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            _login.print_diagnostic("vaultenv:", "something happened")
        self.assertEqual(stderr.getvalue(), "vaultenv: something happened\n")


if __name__ == "__main__":
    unittest.main()
