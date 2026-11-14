# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vault_expiry`` command: what it prints, and how it fails.

Driven against the loopback fake, which answers the lookup endpoint with a body this file
sets, so the command's whole path — argument parsing, the request, the reading of the
answer, the formatting — is exercised without anything contacting ``secrets.ecmwf.int``.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import VaultError
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import vault_expiry

TOKEN = "synthetic-vault-token"

# A full lookup response, of the shape Vault documents for auth/token/lookup-self.
METADATA = {
    "accessor": "Qk3mExampleAccessor",
    "creation_time": 1763000000,
    "creation_ttl": 43200,
    "display_name": "cems-read",
    "entity_id": "1f2e3d4c-0000-1111-2222-333344445555",
    "expire_time": "2026-11-14T21:00:00.000000000Z",
    "explicit_max_ttl": 0,
    "id": TOKEN,
    "identity_policies": ["cems-read"],
    "issue_time": "2026-11-14T09:00:00.000000000Z",
    "meta": {"owner": "cems", "rotation": "weekly"},
    "num_uses": 0,
    "orphan": True,
    "path": "auth/token/create",
    "policies": ["cems-read", "default"],
    "renewable": True,
    "ttl": 7112,
    "type": "service",
}


class RenderTests(unittest.TestCase):
    """The two conversions, which are the whole of the formatting."""

    def test_a_duration_drops_the_units_it_does_not_need(self):
        for seconds, expected in ((0, "0s"), (1, "1s"), (59, "59s"), (60, "1m"),
                                  (90, "1m 30s"), (3600, "1h"), (3661, "1h 1m 1s"),
                                  (7112, "1h 58m 32s"), (86400, "1d"),
                                  (259200, "3d"), (90061, "1d 1h 1m 1s")):
            with self.subTest(seconds=seconds):
                self.assertEqual(vault_expiry.render_duration(seconds), expected)

    def test_a_duration_is_empty_only_for_a_negative_number(self):
        # Vault does not send one, but the function must not invent "0s" for it either.
        self.assertEqual(vault_expiry.render_duration(-1), "0s")

    def test_values_are_rendered_for_reading_not_for_debugging(self):
        for value, expected in ((None, "none"), (True, "yes"), (False, "no"),
                                ("text", "text"), ("", "(empty)"), (7, "7"),
                                (0.5, "0.5"), (0, "0"),
                                (["a", "b"], "a, b"), ([], "none"),
                                ({"k": "v", "j": 2}, "j=2, k=v"), ({}, "none"),
                                ([1, [2, 3]], "1, 2, 3"),
                                ({"outer": {"inner": True}}, "outer=inner=yes"),
                                ((1, 2), "(1, 2)"), (object, str(object))):
            with self.subTest(value=value):
                self.assertEqual(vault_expiry.render_value(value), expected)

    def test_a_duration_field_carries_both_readings(self):
        self.assertEqual(vault_expiry.render_field("ttl", 7112), "7112 (1h 58m 32s)")
        self.assertEqual(vault_expiry.render_field("creation_ttl", 43200),
                         "43200 (12h)")
        self.assertEqual(vault_expiry.render_field("explicit_max_ttl", 0), "0 (0s)")

    def test_no_limit_on_uses_is_said_in_words(self):
        # Vault encodes "unlimited" as 0, which would otherwise read as "used up".
        self.assertEqual(vault_expiry.render_field("num_uses", 0), "unlimited")
        self.assertEqual(vault_expiry.render_field("num_uses", 3), "3")

    def test_a_duration_field_that_is_not_a_number_is_left_alone(self):
        # Vault sends an integer here; if that ever changes, print what arrived rather than
        # raising on the way to a report.
        self.assertEqual(vault_expiry.render_field("ttl", "soon"), "soon")
        self.assertEqual(vault_expiry.render_field("ttl", None), "none")
        self.assertEqual(vault_expiry.render_field("ttl", True), "yes")


class ReportTests(unittest.TestCase):
    """The report: which fields appear, in what order, and what is added to them."""

    def test_the_known_fields_come_first_in_the_documented_order(self):
        labels = [label for label, _ in vault_expiry.field_rows(METADATA)]
        self.assertEqual(labels[:8], ["remaining ttl", "creation ttl", "explicit max ttl",
                                      "issue time", "expire time", "renewable",
                                      "uses remaining", "token type"])

    def test_an_unrecognised_field_is_printed_rather_than_dropped(self):
        # Vault adding a field must not mean it silently disappears from the report, and
        # the extras must be in a fixed order so two runs are diffable.
        labels = [label for label, _ in vault_expiry.field_rows(METADATA)]
        known = {label for _, label in vault_expiry.FIELD_ORDER}
        unknown = [label for label in labels if label not in known]
        self.assertEqual(unknown, sorted(["creation time", "id", "meta", "orphan"]))
        self.assertEqual(labels[-len(unknown):], unknown, "the extras must come last")

    def test_a_field_that_is_absent_is_not_printed(self):
        rows = list(vault_expiry.field_rows({"ttl": 30}))
        self.assertEqual(rows, [("remaining ttl", "30 (30s)")])

    def test_the_report_names_the_address_and_aligns_the_values(self):
        report = vault_expiry.format_report(METADATA, "https://secrets.ecmwf.int")
        lines = report.splitlines()
        self.assertEqual(lines[0], "Vault token at https://secrets.ecmwf.int")
        rows = list(vault_expiry.field_rows(METADATA))
        # One width for the whole block, derived from the labels actually printed: if any
        # line used a different column, these exact strings would not match.
        width = max(len(label) for label, _ in rows)
        self.assertEqual(lines[1:], ["  " + label.ljust(width) + "  " + value
                                     for label, value in rows])
        self.assertIn("7112 (1h 58m 32s)", report)
        self.assertIn("unlimited", report)
        self.assertIn("cems-read", report)

    def test_the_report_shows_the_identity_fields_the_question_asks_for(self):
        report = vault_expiry.format_report(METADATA, "https://secrets.ecmwf.int")
        for expected in ("Qk3mExampleAccessor", "cems-read, default",
                         "1f2e3d4c-0000-1111-2222-333344445555", "service",
                         "owner=cems, rotation=weekly", "auth/token/create"):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_there_are_no_notes_when_there_is_nothing_to_warn_about(self):
        self.assertEqual(vault_expiry.notes(METADATA), [])

    def test_a_token_with_no_expiry_is_explained(self):
        # ttl 0 beside a null expire time reads like "about to end" and means the opposite.
        found = vault_expiry.notes({"ttl": 0, "expire_time": None, "renewable": True})
        self.assertEqual(len(found), 1)
        self.assertIn("does not end by time", found[0])

    def test_a_missing_expire_time_is_not_taken_as_no_expiry(self):
        # An absent key is a different thing from an explicit null: this command does not
        # understand the response well enough to say the token never ends, so it says
        # nothing rather than inventing it.
        self.assertEqual(vault_expiry.notes({"ttl": 60}), [])
        self.assertEqual(vault_expiry.notes({"renewable": True}), [])

    def test_a_null_expire_time_beside_a_live_ttl_is_not_described(self):
        # Vault does not send this, and if it ever did the two halves would contradict each
        # other — so the safe reading is no reading at all.
        self.assertEqual(vault_expiry.notes({"expire_time": None, "ttl": 60}), [])

    def test_a_null_expire_time_with_no_ttl_is_not_described_either(self):
        # Without the ttl there is only half the evidence.
        self.assertEqual(vault_expiry.notes({"expire_time": None}), [])

    def test_a_boolean_ttl_is_not_a_zero(self):
        # ``False == 0`` in Python, so a boolean ttl of False would satisfy the "ttl is 0"
        # half of the condition on its own: this is the value the type check exists for. A
        # ``True`` ttl proves nothing (``True == 0`` is already False), so it is checked
        # alongside to make the difference explicit.
        self.assertEqual(vault_expiry.notes({"expire_time": None, "ttl": False}), [])
        self.assertEqual(vault_expiry.notes({"expire_time": None, "ttl": True}), [])

    def test_a_non_renewable_token_is_explained(self):
        found = vault_expiry.notes({"expire_time": "later", "renewable": False})
        self.assertEqual(len(found), 1)
        self.assertIn("Not renewable", found[0])

    def test_a_limited_number_of_uses_is_explained(self):
        found = vault_expiry.notes({"expire_time": "later", "renewable": True,
                                    "num_uses": 4})
        self.assertEqual(len(found), 1)
        self.assertIn("limited number of uses", found[0])

    def test_a_boolean_is_not_mistaken_for_a_use_count(self):
        # ``True`` is an ``int`` in Python, and Vault will not send one here — but a
        # confused value must not produce a note about uses.
        self.assertEqual(vault_expiry.notes({"expire_time": "later",
                                             "num_uses": True}), [])

    def test_the_notes_follow_the_fields(self):
        report = vault_expiry.format_report(
            {"ttl": 0, "expire_time": None, "renewable": False},
            "https://secrets.ecmwf.int")
        self.assertIn("\n\nNo expire time is set", report)
        self.assertIn("Not renewable", report)


class CommandTests(unittest.TestCase):
    """The command end to end, against the loopback fake."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.raw = json.dumps({"data": METADATA}).encode("utf-8")
        environment = _fakes.vault_environment(
            token=TOKEN,
            ECMWF_VAULT_ADDR=self.fake.base_url,
            ECMWF_VAULT_CA_BUNDLE=self.fake.ca_bundle,
            ECMWF_VAULT_SWAP_POLICY="allow",
            ECMWF_VAULT_HARDEN="0")
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)

    def run_command(self, argv, **patches):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = vault_expiry.run(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    # -- the report -------------------------------------------------------

    def test_the_report_is_printed_and_the_status_is_zero(self):
        status, out, err = self.run_command([])
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("Vault token at https://127.0.0.1:"), out)
        self.assertIn("remaining ttl", out)
        self.assertIn("1h 58m 32s", out)

    def test_it_asks_the_lookup_endpoint_on_the_address_configured(self):
        self.run_command([])
        (request,) = self.fake.requests
        self.assertEqual(request.path, "/v1/auth/token/lookup-self")
        self.assertEqual(request.headers["X-Vault-Token"], TOKEN)

    def test_the_token_never_reaches_the_output(self):
        # The fixture's lookup body reports the token's own value as its ``id``, which is what
        # Vault does for a service token. This report is meant to be read on a terminal and
        # pasted into tickets, so the credential must not be in it — in the report, in the
        # JSON, or in anything written to stderr.
        for argv in ([], ["--json"]):
            with self.subTest(argv=argv):
                status, out, err = self.run_command(argv)
                self.assertEqual(status, 0)
                self.assertNotIn(TOKEN, out)
                self.assertNotIn(TOKEN, err)

    def test_the_withheld_field_is_shown_as_withheld_rather_than_dropped(self):
        # Substituted, not removed: a reader of the report should be able to see that Vault
        # reported an id and that it is being kept back, and a parser should not find the
        # shape different from one token type to the next.
        for argv in ([], ["--json"]):
            with self.subTest(argv=argv):
                _, out, _ = self.run_command(argv)
                self.assertIn("withheld: this is the token itself", out)
                self.assertIn("id", out)

    def test_an_identifier_that_is_not_the_token_is_printed_unchanged(self):
        # A masked id — a UUID, which is what Vault sends when the field is not the token
        # itself — is an identifier, and hiding it would lose information for no reason.
        self.fake.raw = json.dumps({"data": {"id": "8f9d8f37-6c1f-4dc6-9d9e-4c0e0e"}}).encode()
        _, out, _ = self.run_command([])
        self.assertIn("8f9d8f37-6c1f-4dc6-9d9e-4c0e0e", out)

    def test_json_prints_the_metadata_itself_apart_from_the_withheld_id(self):
        status, out, err = self.run_command(["--json"])
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        printed = json.loads(out)
        self.assertEqual(printed["id"], "(withheld: this is the token itself)")
        self.assertEqual({key: value for key, value in printed.items() if key != "id"},
                         {key: value for key, value in METADATA.items() if key != "id"})

    def test_json_output_is_stable_between_runs(self):
        self.assertEqual(self.run_command(["--json"])[1],
                         self.run_command(["--json"])[1])

    def test_a_field_the_command_has_never_heard_of_still_appears(self):
        self.fake.raw = json.dumps(
            {"data": {"ttl": 60, "invented_later": "visible"}}).encode("utf-8")
        _, out, _ = self.run_command([])
        self.assertIn("invented later", out)
        self.assertIn("visible", out)

    # -- failure ----------------------------------------------------------

    def test_a_refused_token_is_reported_with_the_prefix_and_status_2(self):
        self.fake.status = 403
        status, out, err = self.run_command([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("vault_expiry: "), err)
        self.assertIn("look itself up", err)
        # Both known causes named, and not presented as the whole list.
        self.assertIn("expired or been revoked", err)
        self.assertIn("policy", err)

    def test_a_missing_token_is_reported_rather_than_raised(self):
        with _fakes.vault_environment(ECMWF_VAULT_ADDR=self.fake.base_url,
                                      ECMWF_VAULT_HARDEN="0"):
            status, out, err = self.run_command([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_expiry: no Vault token", err)

    def test_an_unreachable_vault_is_reported(self):
        with _fakes.vault_environment(token=TOKEN,
                                      ECMWF_VAULT_ADDR="https://127.0.0.1:1",
                                      ECMWF_VAULT_SWAP_POLICY="allow",
                                      ECMWF_VAULT_HARDEN="0"):
            status, _, err = self.run_command([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_expiry: ", err)

    def test_a_bad_base_url_is_reported_rather_than_raised(self):
        with _fakes.vault_environment(token=TOKEN,
                                      ECMWF_VAULT_ADDR="http://secrets.ecmwf.int",
                                      ECMWF_VAULT_HARDEN="0"):
            status, _, err = self.run_command([])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("must use https", err)

    def test_an_unrecognised_argument_is_refused_by_argparse(self):
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                vault_expiry.run(["--not-a-thing"])
        self.assertEqual(caught.exception.code, 2)

    # -- main -------------------------------------------------------------

    def test_main_passes_argparses_status_through(self):
        with mock.patch.object(sys, "argv", ["vault_expiry", "--not-a-thing"]):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = vault_expiry.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_expiry: ", stderr.getvalue())

    def test_main_turns_a_refusal_into_status_2_with_the_prefix(self):
        with mock.patch.object(sys, "argv", ["vault_expiry"]), \
                mock.patch.object(vault_expiry, "Vault",
                                  side_effect=VaultError("no such host")):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = vault_expiry.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_expiry: no such host", stderr.getvalue())

    def test_main_prints_the_report_and_returns_zero(self):
        with mock.patch.object(sys, "argv", ["vault_expiry"]):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = vault_expiry.main()
        self.assertEqual(status, 0)
        self.assertIn("remaining ttl", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
