# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The parts both installed commands must do identically.

These tests live here rather than in one command's file because the behaviour is shared:
if a command's own tests owned it, a change made for one command could quietly change the
other. They test the helpers directly — no subprocess, no Vault — because that is what they
are: small decisions with exact answers.
"""
from __future__ import annotations

import contextlib
import io
import sys
import unittest
from unittest import mock

from ecmwf_vault.commands import _command_contract as contract

PREFIX = "a_command:"


class SplitAtSeparatorTests(unittest.TestCase):
    def test_arguments_split_at_the_first_separator(self):
        self.assertEqual(contract.split_at_separator(["a", "--", "b"]), (["a"], ["b"]))

    def test_everything_is_a_child_argument_when_there_is_no_separator(self):
        self.assertEqual(contract.split_at_separator(["a", "b"]), (["a", "b"], None))

    def test_a_separator_with_nothing_after_it_gives_an_empty_child_argv(self):
        self.assertEqual(contract.split_at_separator(["--secret", "p", "--"]),
                         (["--secret", "p"], []))


class ReportOwnErrorTests(unittest.TestCase):
    def test_a_failure_is_prefixed_and_written_to_stderr(self):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            contract.report_own_error(PREFIX, "something went wrong")
        self.assertEqual(stderr.getvalue(), "a_command: something went wrong\n")


class RunChildTests(unittest.TestCase):
    def test_the_childs_status_is_returned(self):
        with mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = 42
            status = contract.run_child(["cmd"], {"A": "1"}, message_prefix=PREFIX)
        self.assertEqual(status, 42)
        self.assertEqual(child.call.call_args.args[0], ["cmd"])
        self.assertEqual(child.call.call_args.kwargs["env"], {"A": "1"})
        self.assertNotIn("pass_fds", child.call.call_args.kwargs)

    def test_a_descriptor_is_inherited_when_one_is_given(self):
        with mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = 0
            contract.run_child(["cmd"], {}, message_prefix=PREFIX, descriptor=7)
        self.assertEqual(child.call.call_args.kwargs["pass_fds"], (7,))

    def test_a_child_that_does_not_exist_is_127(self):
        with mock.patch.object(contract, "subprocess") as child:
            child.call.side_effect = FileNotFoundError
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = contract.run_child(["/no/such/cmd"], {}, message_prefix=PREFIX)
        self.assertEqual(status, contract.EXIT_CHILD_NOT_FOUND)
        self.assertEqual(stderr.getvalue(),
                         "a_command: cannot run '/no/such/cmd': no such file\n")

    def test_a_child_that_cannot_be_started_is_reported_not_raised(self):
        # A file that exists but is not executable, a directory in its place, an argument
        # list too large for execve: all reachable, and a traceback would break the
        # exit-status contract both commands make.
        errors = (PermissionError(13, "Permission denied"),
                  IsADirectoryError(21, "Is a directory"),
                  OSError(7, "Argument list too long"))
        for error in errors:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(contract, "subprocess") as child:
                    child.call.side_effect = error
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        status = contract.run_child(["cmd"], {}, message_prefix=PREFIX)
                self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
                self.assertIn("a_command: cannot run 'cmd'", stderr.getvalue())


    def test_an_unencodable_environment_is_reported_without_the_value(self):
        # subprocess encodes the environment itself, and UnicodeEncodeError.object is the
        # text being encoded — so the exception's own message is never printed.
        canary = "before\ud800after"
        error = UnicodeEncodeError("utf-8", canary, 6, 7, "surrogates not allowed")
        with mock.patch.object(contract, "subprocess") as child:
            child.call.side_effect = error
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = contract.run_child(["cmd"], {"X": canary}, message_prefix=PREFIX)
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("cannot be encoded", stderr.getvalue())
        self.assertNotIn("before", stderr.getvalue())
        self.assertNotIn("surrogates not allowed", stderr.getvalue())


class FieldNamesTextTests(unittest.TestCase):
    def test_the_names_are_sorted_and_joined(self):
        self.assertEqual(contract.field_names_text({"b": 1, "a": 2}), "a, b")

    def test_no_fields_is_described_rather_than_left_blank(self):
        # Reachable: kubectl_vault refuses a secret with no fields, and says so.
        self.assertEqual(contract.field_names_text({}), "none")


class RunAsCommandTests(unittest.TestCase):
    def test_the_runners_status_is_returned_unchanged(self):
        self.assertEqual(contract.run_as_command(lambda argv: 7, message_prefix=PREFIX), 7)

    def test_the_arguments_come_from_sys_argv(self):
        seen = []

        def run(argv):
            seen.append(argv)
            return 0

        with mock.patch.object(sys, "argv", ["the-command", "--secret", "p", "--", "c"]):
            self.assertEqual(contract.run_as_command(run, message_prefix=PREFIX), 0)
        self.assertEqual(seen, [["--secret", "p", "--", "c"]])

    def test_a_string_refusal_becomes_our_status_with_the_prefix(self):
        def run(argv):
            raise SystemExit("that secret has no fields")

        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = contract.run_as_command(run, message_prefix=PREFIX)
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertEqual(stderr.getvalue(),
                         "a_command: that secret has no fields\n")

    def test_argparses_own_status_is_passed_through(self):
        # argparse exits with a number, so it must not be reported as our message.
        def run(argv):
            raise SystemExit(2)

        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = contract.run_as_command(run, message_prefix=PREFIX)
        self.assertEqual(status, 2)
        self.assertEqual(stderr.getvalue(), "")

    def test_an_argparse_status_that_is_not_two_is_also_passed_through(self):
        def run(argv):
            raise SystemExit(0)

        self.assertEqual(contract.run_as_command(run, message_prefix=PREFIX), 0)


if __name__ == "__main__":
    unittest.main()
