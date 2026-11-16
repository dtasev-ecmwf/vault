# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The vaultenv command: Vault fields as environment variables, for one command.

Two layers, on purpose. The bulk of the tests call the module's own functions, which is
where the refusals live and where an assertion can be exact — whether a particular refusal
revealed a value is checkable in process, by counting ``reveal()`` calls, and is not
checkable from outside. A second layer runs ``python -m ecmwf_vault.commands.vaultenv`` as a
subprocess against a loopback Vault, which is the only way to prove the things that are
about a real process: that a real program receives the values, that the Vault token is
absent, and that the exit status is the child's.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _fakes
import _loopback_guard
from ecmwf_vault import Secret, VaultError
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import vaultenv as cli

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(REPOSITORY, "pyproject.toml")
SOURCE = os.path.join(REPOSITORY, "src")
SECRET_PATH = "user_applications_and_services_team/cems_web/db"
TOKEN = "synthetic-vault-token"
FIELDS = {"PGHOST": "db.example.int", "PGUSER": "cems", "PGPASSWORD": "SYNTHETIC-PW"}
KUBE_TEXT = "apiVersion: v1\nkind: Config\n"
ENTRY_POINT = "ecmwf_vault.commands.vaultenv:main"

# Written out here rather than read from the module. A test that iterates the
# implementation's own list cannot fail when a name is *missing* from that list, which
# is exactly how GIT_SSH_COMMAND went unnoticed: the guard looked complete to a test
# that asked the guard what it guarded. This is the specification the module must meet;
# a separate test below also catches a name being *removed* from the module.
SPECIFICATION_HOOKS = (
    # The dynamic linker, and loaders that read code from a path.
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "GCONV_PATH", "LOCPATH",
    # Language runtimes that load code named by the environment.
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
    "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH",
    "NODE_OPTIONS", "NODE_PATH", "LUA_PATH", "LUA_CPATH",
    "CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    # Programs a tool runs on your behalf.
    "PATH", "SHELL", "IFS",
    "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR", "GIT_ASKPASS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "PAGER", "MANPAGER", "EDITOR", "VISUAL", "LESSOPEN", "LESSCLOSE", "SSH_ASKPASS",
    # Shell startup.
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS",
    # Trust anchors and key material.
    "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "AWS_CA_BUNDLE",
)
# Counter-enumerated families: a fixed list of names cannot express these.
SPECIFICATION_PREFIXED = ("GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_99")


def mapping(**fields):
    """A field mapping shaped the way the client returns one."""
    return {name: Secret(text) for name, text in fields.items()}


class Recording:
    """A stand-in for a Secret that counts how often its value is revealed."""

    def __init__(self, text):
        self.text = text
        self.reveals = 0

    def reveal(self):
        self.reveals += 1
        return self.text


class InProcessTests(unittest.TestCase):
    def setUp(self):
        # No ambient variable may change what these assert; see _fakes.isolate.
        _fakes.isolate(self)

    """The command's own functions: mapping, refusals, and the environment it builds."""

    def run_cli(self, argv, fields, status=0):
        """Run ``run()`` with a fake Vault and a fake child, and return both."""
        with mock.patch.object(cli, "value", return_value=fields), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = status
            returned = cli.run(argv)
            environment = None
            command = None
            if child.call.called:
                command = child.call.call_args.args[0]
                environment = child.call.call_args.kwargs["env"]
            return returned, command, environment

    def refusal(self, argv, fields):
        """The message a refused invocation refuses with."""
        with mock.patch.object(cli, "value", return_value=fields):
            with self.assertRaises(SystemExit) as caught:
                cli.run(argv)
        self.assertIsInstance(caught.exception.code, str)
        return str(caught.exception.code)

    # -- the environment it builds ---------------------------------------

    def test_every_field_becomes_a_variable_of_the_same_name(self):
        with _fakes.vault_environment():
            _, command, environment = self.run_cli(
                ["--secret", "p", "--", "cmd", "arg"], mapping(**FIELDS))
        self.assertEqual(command, ["cmd", "arg"])
        for name, text in FIELDS.items():
            self.assertEqual(environment[name], text)

    def test_the_rest_of_the_environment_is_kept(self):
        # The compared values are pinned, not read from the runner: HOME and PATH are what the
        # test says they are, so the assertion cannot change meaning on another host, and
        # cannot fail because the suite was started with one of them unset.
        with _fakes.vault_environment(), mock.patch.dict(
                os.environ, {"HOME": "/known/home", "PATH": "/known/path"}):
            _, _, environment = self.run_cli(
                ["--secret", "p", "--", "cmd"], mapping(PGUSER="cems"))
        self.assertEqual(environment["HOME"], "/known/home")
        self.assertEqual(environment["PATH"], "/known/path")

    def test_the_vault_token_is_not_handed_to_the_command(self):
        # Set by hand, not by the fixture: nothing here reads that name, and the point is that
        # a stale export from an older copy of this package does not travel into the child.
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": "hvs.a-legacy-export",
                                          "HOME": "/known/home"}):
            _, _, environment = self.run_cli(
                ["--secret", "p", "--", "cmd"], mapping(PGUSER="cems"))
        self.assertFalse("ECMWF_VAULT_TOKEN" in environment,
                         "the legacy token variable must not reach the child")
        self.assertEqual(environment["HOME"], "/known/home",
                         "everything else still travels to the child")

    def test_each_value_is_revealed_exactly_once(self):
        fields = {"PGUSER": Recording("cems"), "PGPASSWORD": Recording("pw")}
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(["--secret", "p", "--", "cmd"], fields)
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertEqual(environment["PGPASSWORD"], "pw")
        self.assertEqual([f.reveals for f in fields.values()], [1, 1])

    def test_the_return_value_is_the_childs_status(self):
        with _fakes.vault_environment():
            returned, _, _ = self.run_cli(["--secret", "p", "--", "cmd"],
                                          mapping(PGUSER="cems"), status=42)
        self.assertEqual(returned, 42)

    # -- choosing and renaming fields ------------------------------------

    def test_set_renames_a_field(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--set", "KUBECONFIG=k8s-cems-test", "--", "cmd"],
                mapping(**{"k8s-cems-test": "KUBECONFIG-TEXT"}))
        self.assertEqual(environment["KUBECONFIG"], "KUBECONFIG-TEXT")

    def test_set_selects_only_the_fields_it_names(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--set", "DBUSER=PGUSER", "--", "cmd"],
                mapping(PGUSER="cems", PGPASSWORD="pw"))
        self.assertEqual(environment["DBUSER"], "cems")
        self.assertFalse("PGPASSWORD" in environment,
                         "PGPASSWORD must not reach the child environment")

    def test_field_selects_one_field_under_its_own_name(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--", "cmd"],
                mapping(PGUSER="cems", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertFalse("PGPASSWORD" in environment,
                         "PGPASSWORD must not reach the child environment")

    def test_field_is_repeatable(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--field", "PGHOST", "--", "cmd"],
                mapping(PGUSER="cems", PGHOST="db", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertEqual(environment["PGHOST"], "db")
        self.assertFalse("PGPASSWORD" in environment,
                         "PGPASSWORD must not reach the child environment")

    def test_field_and_set_together_are_the_union(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--set", "DB=PGHOST", "--", "cmd"],
                mapping(PGUSER="cems", PGHOST="db", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertEqual(environment["DB"], "db")
        self.assertFalse("PGPASSWORD" in environment,
                         "PGPASSWORD must not reach the child environment")

    def test_field_naming_a_missing_field_lists_what_is_there(self):
        message = self.refusal(["--secret", "p", "--field", "nope", "--", "cmd"],
                              mapping(**FIELDS))
        self.assertIn("no field 'nope'", message)
        self.assertIn("PGHOST", message)

    def test_field_with_a_name_that_is_not_a_variable_name_points_at_set(self):
        # The case that makes --field useful for one field of a mixed secret, and the
        # one where it cannot help: the field's own name is unusable.
        message = self.refusal(["--secret", "p", "--field", "k8s-cems-test", "--", "cmd"],
                              mapping(**{"k8s-cems-test": "x"}))
        self.assertIn("not a valid environment variable name", message)
        self.assertIn("--set NAME=k8s-cems-test", message)

    def test_selecting_one_variable_twice_is_reported(self):
        for extra in (["--field", "PGUSER", "--field", "PGUSER"],
                      ["--field", "PGUSER", "--set", "PGUSER=PGHOST"],
                      ["--set", "A=PGUSER", "--set", "A=PGHOST"]):
            with self.subTest(extra=extra):
                message = self.refusal(["--secret", "p", *extra, "--", "cmd"],
                                      mapping(**FIELDS))
                self.assertIn("is selected twice", message)

    def test_a_field_name_that_is_not_a_variable_name_points_at_set(self):
        message = self.refusal(["--secret", "p", "--", "cmd"],
                              mapping(**{"k8s-cems-test": "x"}))
        self.assertIn("not a valid environment variable name", message)
        self.assertIn("--set NAME=k8s-cems-test", message)

    def test_set_naming_a_missing_field_lists_what_is_there(self):
        message = self.refusal(["--secret", "p", "--set", "THING=nope", "--", "cmd"],
                              mapping(**FIELDS))
        self.assertIn("no field 'nope'", message)
        self.assertIn("PGPASSWORD", message)

    def test_a_set_item_without_a_field_is_reported(self):
        for item in ("PGUSER", "=PGUSER", "PGUSER=", ""):
            with self.subTest(item=item):
                message = self.refusal(["--secret", "p", "--set", item, "--", "cmd"],
                                      mapping(**FIELDS))
                self.assertIn("--set takes NAME=FIELD", message)

    def test_a_set_variable_that_is_not_a_name_is_reported(self):
        message = self.refusal(["--secret", "p", "--set", "not-a-name=PGUSER",
                                "--", "cmd"], mapping(**FIELDS))
        self.assertIn("not a valid environment variable name", message)

    def test_a_secret_with_no_fields_is_reported(self):
        message = self.refusal(["--secret", "p", "--", "cmd"], {})
        self.assertIn("no fields", message)

    # -- refusals ---------------------------------------------------------

    def test_overwriting_an_inherited_variable_needs_force(self):
        with _fakes.vault_environment():
            message = self.refusal(["--secret", "p", "--", "cmd"],
                                  mapping(HOME="/somewhere/else"))
        self.assertIn("already set", message)
        self.assertIn("HOME", message)

    def test_force_allows_the_overwrite(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(["--secret", "p", "--force", "--", "cmd"],
                                             mapping(HOME="/somewhere/else"))
        self.assertEqual(environment["HOME"], "/somewhere/else")

    def test_a_name_already_set_by_the_secret_itself_is_not_a_clash(self):
        # The clash test is against the inherited environment, not against the
        # variables the secret is adding.
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(["--secret", "p", "--", "cmd"],
                                             mapping(PGUSER="cems"))
        self.assertEqual(environment["PGUSER"], "cems")

    def test_the_specification_hooks_are_all_refused(self):
        # The specification, not the implementation: this is the test that would have
        # failed when GIT_SSH_COMMAND was missing.
        for name in SPECIFICATION_HOOKS:
            with self.subTest(name=name):
                message = self.refusal(["--secret", "p", "--force", "--", "cmd"],
                                      mapping(**{name: "x"}))
                self.assertIn("refusing to set %s" % name, message)
                self.assertIn("no --force for that", message)

    def test_the_modules_list_covers_the_specification(self):
        # The direction that failed review: a name missing from the module's list. The
        # other direction is the test above, which asks the module to enforce all of it.
        self.assertLessEqual(set(SPECIFICATION_HOOKS), set(cli.FORBIDDEN_NAMES),
                             "a hook in the specification is not in the module's list")

    def test_counter_enumerated_name_families_are_refused(self):
        for name in SPECIFICATION_PREFIXED:
            with self.subTest(name=name):
                message = self.refusal(["--secret", "p", "--force", "--", "cmd"],
                                      mapping(**{name: "x"}))
                self.assertIn("refusing to set %s" % name, message)

    def test_every_name_in_the_modules_own_list_is_enforced(self):
        # A name present in the list but not actually refused would be the worst of
        # both worlds, so the list is exercised as it stands, contraband included.
        self.assertTrue(cli.FORBIDDEN_NAMES)
        for name in sorted(cli.FORBIDDEN_NAMES):
            with self.subTest(name=name):
                message = self.refusal(["--secret", "p", "--force", "--", "cmd"],
                                      mapping(**{name: "x"}))
                self.assertIn("refusing to set %s" % name, message)

    def test_a_credential_name_is_refused_as_a_variable(self):
        # VAULT_TOKEN is HashiCorp's own variable: a secret that sets it authenticates the
        # child somewhere the secret was never meant to reach.
        message = self.refusal(["--secret", "p", "--force", "--", "cmd"],
                              mapping(VAULT_TOKEN="another-token"))
        self.assertIn("refusing to set VAULT_TOKEN", message)
        self.assertIn("whose credential it holds", message)

    def test_the_legacy_token_name_is_refused_as_a_variable(self):
        # build_child_environment() strips this name from the child, so a field must not be
        # able to put it back — that is the whole value of stripping it.
        message = self.refusal(["--secret", "p", "--force", "--", "cmd"],
                              mapping(ECMWF_VAULT_TOKEN="another-token"))
        self.assertIn("refusing to set ECMWF_VAULT_TOKEN", message)
        self.assertIn("whose credential it holds", message)

    def test_a_renamed_field_cannot_become_the_legacy_token_name(self):
        # --set renames, so the refusal has to cover the chosen variable name and not only
        # whatever the Vault field happens to be called.
        message = self.refusal(["--secret", "p", "--set", "ECMWF_VAULT_TOKEN=anything",
                                "--force", "--", "cmd"], mapping(anything="x"))
        self.assertIn("refusing to set ECMWF_VAULT_TOKEN", message)

    def test_every_name_the_scrub_strips_is_refused_as_a_field(self):
        # The two lists are one rule stated twice, so they are compared rather than trusted to
        # stay aligned by hand.
        from ecmwf_vault import _environment
        self.assertIn(_environment.LEGACY_TOKEN_ENV, cli.FORBIDDEN_NAMES)

    def test_a_name_refusal_reveals_nothing(self):
        # The mapping/name/collision refusals run before the reveal() site, so they do
        # not produce any value at all. Counting reveals is precise in a way no
        # subprocess test is.
        canary = {"LD_PRELOAD": Recording("CANARY"), "PGUSER": Recording("CANARY")}
        message = self.refusal(["--secret", "p", "--force", "--", "cmd"], canary)
        self.assertEqual([field.reveals for field in canary.values()], [0, 0])
        self.assertNotIn("CANARY", message)

    def test_a_value_refusal_launches_no_child_but_does_reveal(self):
        # The narrower, true statement for the value refusals: a value can only be
        # judged by revealing it, so earlier fields in the same mapping *are* revealed
        # before a later one is refused. What holds is that no child is launched and no
        # partial environment is built — and this test pins the reveal counts so the
        # documentation cannot drift back to "a refused run never reveals".
        fields = {"PGUSER": Recording("cems"), "DEBUG": Recording(True)}
        with _fakes.vault_environment():
            with mock.patch.object(cli, "value", return_value=fields), \
                    mock.patch.object(contract, "subprocess") as child:
                with self.assertRaises(SystemExit) as caught:
                    cli.run(["--secret", "p", "--", "cmd"])
        self.assertIn("holds bool, not text", str(caught.exception.code))
        self.assertFalse(child.call.called, "a refused value must not start a child")
        self.assertEqual([field.reveals for field in fields.values()], [1, 1])

    def test_a_nul_refusal_also_launches_no_child(self):
        fields = {"PGUSER": Recording("cems"), "PGPASSWORD": Recording("a\0b")}
        with _fakes.vault_environment():
            with mock.patch.object(cli, "value", return_value=fields), \
                    mock.patch.object(contract, "subprocess") as child:
                with self.assertRaises(SystemExit) as caught:
                    cli.run(["--secret", "p", "--", "cmd"])
        self.assertIn("NUL byte", str(caught.exception.code))
        self.assertFalse(child.call.called)

    # -- values -----------------------------------------------------------

    def test_a_value_that_is_not_text_names_the_field_and_the_type(self):
        message = self.refusal(["--secret", "p", "--", "cmd"], mapping(PGPORT=5432))
        self.assertIn("field 'PGPORT' holds int, not text", message)

    def test_a_boolean_is_not_stringified_behind_the_users_back(self):
        message = self.refusal(["--secret", "p", "--", "cmd"], {"DEBUG": Secret(True)})
        self.assertIn("field 'DEBUG' holds bool, not text", message)

    def test_a_value_with_a_nul_byte_is_refused(self):
        message = self.refusal(["--secret", "p", "--", "cmd"],
                              mapping(PGPASSWORD="before\0after"))
        self.assertIn("NUL byte", message)

    def test_a_lone_surrogate_value_is_refused_without_leaking_it(self):
        # Vault JSON can carry a lone surrogate (\udXXX). subprocess encodes the
        # environment with os.fsencode, so before this was refused the failure was a
        # traceback — and UnicodeEncodeError.object is the value itself.
        canary = "before\ud800after"
        fields = {"PGUSER": Recording(canary)}
        with _fakes.vault_environment():
            with mock.patch.object(cli, "value", return_value=fields), \
                    mock.patch.object(contract, "subprocess") as child:
                with self.assertRaises(SystemExit) as caught:
                    cli.run(["--secret", "p", "--", "cmd"])
        message = str(caught.exception.code)
        self.assertIn("lone surrogate", message)
        self.assertIn("PGUSER", message)          # names the field, which is not the secret
        self.assertNotIn(canary, message)
        self.assertNotIn("before", message)
        self.assertFalse(child.call.called, "a refused value must not start a child")

    def test_an_empty_value_is_allowed(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(["--secret", "p", "--", "cmd"],
                                             mapping(PGOPTIONS=""))
        self.assertEqual(environment["PGOPTIONS"], "")

    def test_a_command_is_required(self):
        with _fakes.vault_environment():
            with mock.patch.object(cli, "value", return_value=mapping(PGUSER="cems")):
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    status = cli.run(["--secret", "p"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("no command given", stderr.getvalue())

    def test_a_vault_failure_is_reported_with_the_prefix(self):
        with mock.patch.object(cli, "value", side_effect=VaultError("no token here")):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = cli.run(["--secret", "p", "--", "cmd"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vaultenv: no token here", stderr.getvalue())

    def test_main_turns_a_refusal_into_status_2_with_the_prefix(self):
        # main() is what the console script calls, so its two SystemExit paths are
        # worth pinning: a refusal (a string code) and argparse's own status.
        with _fakes.vault_environment():
            with mock.patch.object(sys, "argv",
                                   ["vaultenv", "--secret", "p", "--", "cmd"]), \
                    mock.patch.object(cli, "value",
                                      return_value=mapping(LD_PRELOAD="/tmp/evil.so")):
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    status = cli.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vaultenv: refusing to set LD_PRELOAD", stderr.getvalue())

    def test_main_passes_argparses_status_through(self):
        with mock.patch.object(sys, "argv", ["vaultenv", "--", "cmd"]):
            with contextlib.redirect_stderr(io.StringIO()):
                status = cli.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)   # argparse exits 2 as well

    def test_main_returns_the_childs_status(self):
        with _fakes.vault_environment():
            with mock.patch.object(sys, "argv",
                                   ["vaultenv", "--secret", "p", "--", "cmd"]), \
                    mock.patch.object(cli, "value", return_value=mapping(PGUSER="cems")), \
                    mock.patch.object(contract, "subprocess") as child:
                child.call.return_value = 7
                self.assertEqual(cli.main(), 7)


class MemoryFileTests(unittest.TestCase):
    def setUp(self):
        # No ambient variable may change what these assert; see _fakes.isolate.
        _fakes.isolate(self)

    """``--mem-file`` and ``--mem-field``: the selection rules and what reaches the child."""

    def run_cli(self, argv, fields, status=0):
        """Run ``run()`` and report the spawn call, or None if the child never ran."""
        with mock.patch.object(cli, "value", return_value=fields), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = status
            returned = cli.run(argv)
            call = child.call.call_args if child.call.called else None
        return returned, call

    def refusal(self, argv, fields):
        with mock.patch.object(cli, "value", return_value=fields):
            with self.assertRaises(SystemExit) as caught:
                cli.run(argv)
        self.assertIsInstance(caught.exception.code, str)
        return str(caught.exception.code)

    # -- what the child receives -----------------------------------------

    def test_a_memory_field_is_not_also_a_variable(self):
        # The whole point of the descriptor. Exported as well, anything sharing this uid could
        # read it in /proc/<pid>/environ for the child's whole life, and the sealed file would
        # have bought nothing.
        _, call = self.run_cli(
            ["--secret", "p", "--field", "PGUSER", "--mem-field=PGPASSWORD:pw", "--", "cmd"],
            mapping(**FIELDS))
        self.assertEqual(call.kwargs["env"]["PGUSER"], FIELDS["PGUSER"])
        self.assertFalse("PGPASSWORD" in call.kwargs["env"],
                         "PGPASSWORD must not reach the child environment")

    def test_the_descriptor_is_the_only_extra_thing_inherited(self):
        _, call = self.run_cli(["--secret", "p", "--mem-field=PGPASSWORD:pw", "--",
                                "cmd", "{pw}"], mapping(**FIELDS))
        descriptors = call.kwargs["pass_fds"]
        self.assertEqual(len(descriptors), 1)
        # The number in argv is the number handed over, or /proc/self/fd/<n> names nothing.
        self.assertEqual(call.args[0][1], "/proc/self/fd/%d" % descriptors[0])

    def test_a_nickname_is_replaced_wherever_it_appears(self):
        _, call = self.run_cli(
            ["--secret", "p", "--mem-field=PGPASSWORD:pw", "--", "tool",
             "--password-file={pw}", "{pw}"], mapping(**FIELDS))
        glued, whole = call.args[0][1], call.args[0][2]
        path = glued.split("=", 1)[1]
        self.assertTrue(path.startswith("/proc/self/fd/"))
        self.assertEqual(whole, path, "the same nickname resolves the same way both places")

    def test_a_whole_mem_file_leaves_the_environment_untouched(self):
        with mock.patch.dict(os.environ, {"HOME": "/known/home"}):
            _, call = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--field", "PGPASSWORD",
                 "--mem-file=potatoes", "--", "cmd"], mapping(**FIELDS))
        for name in ("PGUSER", "PGPASSWORD"):
            self.assertFalse(name in call.kwargs["env"],
                             "%s must not reach the child environment" % (name,))
        self.assertEqual(call.kwargs["env"]["HOME"], "/known/home",
                         "the rest of the environment is kept")

    def test_the_mem_file_contents_are_the_serialised_selection(self):
        # Read *while the child runs*: run() closes every slot on the way out, so a descriptor
        # inspected afterwards is gone. That closing is the tested property, not an obstacle.
        seen = {}

        def spy(command, **keywords):
            descriptor, = keywords["pass_fds"]
            with open("/proc/self/fd/%d" % descriptor, "rb") as handle:
                seen["body"] = handle.read()
            seen["env_has"] = [name for name in ("PGUSER", "PGPASSWORD")
                               if name in keywords["env"]]
            return 0

        with mock.patch.object(cli, "value", return_value=mapping(PGUSER="cems",
                                                                 PGPASSWORD="SYNTHETIC-PW")), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.side_effect = spy
            cli.run(["--secret", "p", "--field", "PGUSER", "--field", "PGPASSWORD",
                     "--mem-file=potatoes", "--", "cmd"])
        self.assertEqual(seen["body"], b"PGPASSWORD=SYNTHETIC-PW\nPGUSER=cems\n")
        self.assertEqual(seen["env_has"], [])

    def test_the_slot_is_closed_once_the_command_returns(self):
        # Our end must not outlive the child: the file is anonymous, but a leaked descriptor is
        # still a handle on plaintext for the life of the process.
        kept = []

        def spy(command, **keywords):
            kept.append(keywords["pass_fds"][0])
            return 0

        with mock.patch.object(cli, "value", return_value=mapping(**FIELDS)), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.side_effect = spy
            cli.run(["--secret", "p", "--mem-field=PGPASSWORD:pw", "--", "cmd"])
        self.assertEqual(len(kept), 1)
        with self.assertRaises(OSError):
            os.fstat(kept[0])

    def test_a_secret_whose_only_field_is_held_in_a_descriptor_needs_no_variables(self):
        # The default mapping would refuse "kube-config" as a name. Nothing becomes a name
        # here.
        _, call = self.run_cli(["--secret", "p", "--mem-field=kube-config:kube", "--", "cmd"],
                               mapping(**{"kube-config": KUBE_TEXT}))
        self.assertFalse("kube-config" in call.kwargs["env"],
                         "the descriptor field must not be exported either")

    # -- refusals ---------------------------------------------------------

    def test_a_field_cannot_be_both_a_variable_and_a_descriptor(self):
        message = self.refusal(
            ["--secret", "p", "--field", "PGPASSWORD", "--mem-field=PGPASSWORD:pw",
             "--", "cmd"], mapping(**FIELDS))
        self.assertIn("asked for twice", message)
        self.assertIn("PGPASSWORD", message)

    def test_a_renamed_field_cannot_also_be_a_descriptor(self):
        message = self.refusal(
            ["--secret", "p", "--set", "SECRET=PGPASSWORD", "--mem-field=PGPASSWORD:pw",
             "--", "cmd"], mapping(**FIELDS))
        self.assertIn("asked for twice", message)

    def test_mem_file_refuses_a_value_spanning_lines(self):
        message = self.refusal(
            ["--secret", "p", "--field", "PGPASSWORD", "--mem-file=potatoes", "--", "cmd"],
            mapping(PGPASSWORD="line\nbreak"))
        self.assertIn("spanning lines", message)
        self.assertIn("--mem-field", message, "and it says what to do instead")
        self.assertNotIn("line\nbreak", message.replace("\\n", "<value>"))

    def test_a_forbidden_name_is_refused_as_a_nickname_too(self):
        for nickname in ("LD_PRELOAD", "PATH", "PYTHONPATH"):
            with self.subTest(nickname=nickname):
                message = self.refusal(
                    ["--secret", "p", "--field", "PGUSER", "--mem-file=" + nickname,
                     "--", "cmd"], mapping(**FIELDS))
                self.assertIn(nickname, message)

    def test_a_forbidden_field_name_still_reaches_a_descriptor(self):
        # The nickname is checked; a *field* named like a forbidden variable may legitimately
        # be handed over as bytes, because nothing about it becomes a variable name.
        #
        # The inherited PATH is pinned rather than read: with the valid setting PATH=/usr/bin
        # an assertion written as "not equal to /usr/bin" fails while the behaviour is correct.
        # The field's value is deliberately different from the sentinel, so an overwrite would
        # be visible.
        with mock.patch.dict(os.environ, {"PATH": "/known/sentinel/bin"}):
            _, call = self.run_cli(["--secret", "p", "--mem-field=PATH:pathy", "--", "cmd"],
                                   mapping(PATH="/usr/bin"))
        self.assertEqual(call.kwargs["env"]["PATH"], "/known/sentinel/bin",
                         "the inherited PATH survived; the field never became a variable")

    def test_a_malformed_mem_field_is_refused(self):
        for item in ("nocolon", ":noname", "nofield:"):
            with self.subTest(item=item):
                message = self.refusal(
                    ["--secret", "p", "--mem-field=" + item, "--", "cmd"], mapping(**FIELDS))
                self.assertIn("--mem-field takes NAME:NICKNAME", message)

    def test_an_unknown_field_in_a_mem_field_lists_what_exists(self):
        message = self.refusal(["--secret", "p", "--mem-field=nope:pw", "--", "cmd"],
                               mapping(**FIELDS))
        self.assertIn("no field 'nope'", message)
        self.assertIn("PGUSER", message)

    def test_two_slots_cannot_share_a_nickname(self):
        message = self.refusal(
            ["--secret", "p", "--mem-field=PGUSER:x", "--mem-field=PGPASSWORD:x", "--", "cmd"],
            mapping(**FIELDS))
        self.assertIn("two memory files named 'x'", message)

    def test_a_nickname_that_is_not_an_identifier_is_refused(self):
        message = self.refusal(
            ["--secret", "p", "--mem-field=PGUSER:2bad", "--", "cmd"], mapping(**FIELDS))
        self.assertIn("not usable as a memory-file name", message)

    def test_an_empty_mem_file_is_refused_rather_than_ignored(self):
        # ``--mem-file=`` was *given*. Reading it as absent exports the secret into the
        # environment with an exit status of 0 and no descriptor at all — the weaker behaviour,
        # chosen silently by a typo. So: refuse, do not spawn, do not export.
        for item in ("", "  "):
            with self.subTest(mem_file=repr(item)):
                with mock.patch.object(cli, "value", return_value=mapping(**FIELDS)), \
                        mock.patch.object(contract, "subprocess") as child:
                    argv = ["--secret", "p", "--field", "PGPASSWORD",
                            "--mem-file=" + item, "--", "cmd"]
                    with self.assertRaises(SystemExit) as caught:
                        cli.run(argv)
                    self.assertIsInstance(caught.exception.code, str)
                    self.assertIn("not usable as a memory-file name", caught.exception.code)
                    child.call.assert_not_called()
                    exported = [call.kwargs.get("env", {})
                                for call in child.call.call_args_list]
                    self.assertEqual(exported, [], "no child ran, so nothing was exported")

    def test_an_empty_mem_field_is_refused_rather_than_ignored(self):
        for item in ("", ":", "a:", ":b"):
            with self.subTest(item=repr(item)):
                message = self.refusal(
                    ["--secret", "p", "--mem-field=" + item, "--", "cmd"], mapping(**FIELDS))
                self.assertIn("--mem-field takes NAME:NICKNAME", message)

    def test_a_value_the_environment_could_carry_is_not_refused_by_a_descriptor(self):
        # A lone surrogate in the U+DC80-U+DCFF range is os.fsencode's way of carrying a byte
        # that was never valid UTF-8, so --field exports it today. Both descriptor flags must
        # accept the same value and produce the same bytes; refusing, or raising
        # UnicodeEncodeError (whose repr() holds the secret), is the bug.
        for flag, expected in (("--mem-field=PGPASSWORD:pw", b"hunter\x802"),
                               ("--mem-file=potatoes", b"PGPASSWORD=hunter\x802\n")):
            with self.subTest(flag=flag):
                fields = {"PGPASSWORD": Secret("hunter\udc802")}
                seen = {}

                def spy(command, **keywords):
                    descriptor, = keywords["pass_fds"]
                    with open("/proc/self/fd/%d" % descriptor, "rb") as handle:
                        seen["bytes"] = handle.read()
                    return 0

                # No --field: naming a field both as a variable and as a descriptor is a
                # refusal in its own right, tested elsewhere.
                argv = ["--secret", "p", flag, "--", "cmd"]
                with mock.patch.object(cli, "value", return_value=fields), \
                        mock.patch.object(contract, "subprocess") as child:
                    child.call.side_effect = spy
                    self.assertEqual(cli.run(argv), 0)
                self.assertEqual(seen["bytes"], expected)

    def test_a_clash_does_not_refuse_a_selection_that_goes_to_a_descriptor(self):
        # Nothing named by --mem-file reaches the environment, so an inherited name is not
        # being overwritten and the command must run.
        with mock.patch.dict(os.environ, {"PGUSER": "already-set"}), \
                mock.patch.object(cli, "value", return_value=mapping(**FIELDS)), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = 0
            status = cli.run(["--secret", "p", "--field", "PGUSER", "--field", "PGPASSWORD",
                              "--mem-file=potatoes", "--", "cmd"])
        self.assertEqual(status, 0)
        env = child.call.call_args.kwargs["env"]
        self.assertEqual(env["PGUSER"], "already-set", "the inherited value survived")
        self.assertFalse("PGPASSWORD" in env, "PGPASSWORD must not be exported")

    def test_a_clash_still_refuses_when_the_value_is_actually_exported(self):
        # The converse, so the skip above is not simply the check being gone.
        with mock.patch.dict(os.environ, {"PGUSER": "already-set"}):
            message = self.refusal(
                ["--secret", "p", "--field", "PGUSER", "--", "cmd"], mapping(**FIELDS))
        self.assertIn("already set", message)

    def test_a_clash_still_refuses_for_a_mem_field_alongside_exported_values(self):
        # --mem-field leaves some fields in the environment; those keep the clash check.
        with mock.patch.dict(os.environ, {"PGHOST": "db.internal"}):
            message = self.refusal(
                ["--secret", "p", "--field", "PGHOST", "--mem-field=PGPASSWORD:pw",
                 "--", "cmd"], mapping(**FIELDS))
        self.assertIn("already set", message)

    def test_a_memory_field_holds_to_the_same_value_rules_as_a_variable(self):
        # Not a parallel implementation of the checks: --mem-field goes through the same
        # variable_values, so a structure, a NUL or a lone surrogate is refused the same way.
        # Stated per case, because a mutation that reads the field directly would crash here
        # with an AttributeError instead of refusing, and nothing else in this file notices.
        for value, expected in (({"a": 1}, "holds dict"), (["x"], "holds list"),
                                ("nul\u0000inside", "NUL byte"),
                                ("before\ud800after", "lone surrogate")):
            with self.subTest(value=type(value).__name__ or repr(value)):
                message = self.refusal(
                    ["--secret", "p", "--mem-field=PGPASSWORD:pw", "--", "cmd"],
                    {"PGPASSWORD": Secret(value)})
                self.assertIn(expected, message)
                self.assertNotIn("Traceback", message)

    def test_the_descriptor_is_closed_even_when_the_command_raises(self):
        # Distinguishes the explicit close from one that merely happens when the frame is
        # collected: an in-flight exception keeps run()'s locals alive, so a slot released only
        # by garbage collection would still be open here.
        kept = []

        def spy(command, **keywords):
            kept.append(keywords["pass_fds"][0])
            raise RuntimeError("the child could not be started")

        with mock.patch.object(cli, "value", return_value=mapping(**FIELDS)), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.side_effect = spy
            raised = None
            try:
                cli.run(["--secret", "p", "--mem-field=PGPASSWORD:pw", "--", "cmd"])
            except RuntimeError as error:
                raised = error
        self.assertIsNotNone(raised, "the failure was swallowed")
        # Held on purpose: an exception keeps the frames in its traceback alive, and with them
        # every local in run(), including the slots. If the close were left to garbage
        # collection this descriptor would still be open right now.
        self.assertIsNotNone(raised.__traceback__)
        self.assertEqual(len(kept), 1)
        with self.assertRaises(OSError):
            os.fstat(kept[0])

    # -- parsing ----------------------------------------------------------

    def test_the_split_is_from_the_last_colon(self):
        # Vault field names may contain colons; nicknames may not, so the tail decides.
        self.assertEqual(cli.split_mem_field("a:b:c"), ("a:b", "c"))
        self.assertEqual(cli.split_mem_field("kube:kube"), ("kube", "kube"))

    def test_no_mem_flags_means_the_command_is_untouched(self):
        # The pass-through promise, restated for the feature that could have broken it.
        _, call = self.run_cli(["--secret", "p", "--field", "PGUSER", "--",
                                "cmd", "{braces}", "${HOME}"], mapping(**FIELDS))
        self.assertEqual(call.args[0], ["cmd", "{braces}", "${HOME}"])
        self.assertNotIn("pass_fds", call.kwargs)


class BlackBoxTests(unittest.TestCase):
    """The real thing: a subprocess command, a loopback Vault, a real environment."""

    STAND_IN = '''#!%s
"""Report the environment this process was handed, instead of doing anything."""
import json, os, subprocess, sys

wanted = os.environ.get("STAND_IN_NAMES", "").split()
print("ARGV " + json.dumps(sys.argv[1:]))
print("VARS " + json.dumps({name: os.environ.get(name) for name in wanted}))
print("ENV_HAS_TOKEN %%s" %% ("ECMWF_VAULT_TOKEN" in os.environ))
if sys.argv[1:2] == ["--grandchild"]:
    # What the command's own children inherit, printed by one of them.
    ran = subprocess.run(
        [sys.executable, "-c",
         "import os,sys;print('GRANDCHILD ' + repr(os.environ.get(sys.argv[1])))",
         sys.argv[2]], capture_output=True, text=True)
    print(ran.stdout.strip())
sys.exit(int(os.environ.get("STAND_IN_EXIT", "0")))
''' % sys.executable

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = dict(FIELDS)
        self.scratch = tempfile.mkdtemp(prefix="ecmwf-vault-env-")
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-env-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.stand_in = os.path.join(self.scratch, "stand-in-command")
        with open(self.stand_in, "w", encoding="utf-8") as handle:
            handle.write(self.STAND_IN)
        os.chmod(self.stand_in, stat.S_IRWXU)

    def child_environment(self, **overrides):
        """A deliberately small environment, so nothing is inherited by accident."""
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": _loopback_guard.child_python_path(SOURCE),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
            "HOME": self.home,
            "TMPDIR": self.scratch,
            "ECMWF_VAULT_TOKEN_FILE": _fakes.token_file(TOKEN),
            # A stale export of the name an older version of this package authenticated with:
            # the stand-in reports whether it arrived, so the strip is not taken on trust.
            "ECMWF_VAULT_TOKEN": "hvs.a-legacy-export",
            "ECMWF_VAULT_ADDR": self.fake.base_url,
            "ECMWF_VAULT_CA_BUNDLE": self.fake.ca_bundle,
        }
        environment.update(overrides)
        return environment

    def run_cli(self, *arguments, **overrides):
        """Run the module the way the console script does, as a subprocess."""
        return subprocess.run(
            [sys.executable, "-m", "ecmwf_vault.commands.vaultenv", *arguments],
            cwd=self.scratch, env=self.child_environment(**overrides),
            capture_output=True, text=True, timeout=60)

    def standard(self, *extra, **overrides):
        return self.run_cli("--secret", SECRET_PATH, "--", self.stand_in, *extra,
                            **overrides)

    def reported(self, result, kind):
        line = next(line for line in result.stdout.splitlines()
                    if line.startswith(kind + " "))
        return json.loads(line.split(" ", 1)[1])

    def variables(self, result):
        return self.reported(result, "VARS")

    # -- the point of the command ----------------------------------------

    def test_every_field_reaches_a_real_command(self):
        result = self.standard(STAND_IN_NAMES="PGHOST PGUSER PGPASSWORD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.variables(result), FIELDS)

    def test_a_real_command_receives_the_variables(self):
        # The stand-in is a Python script; this is a real program reading a real
        # environment, which is what the command is for.
        shell = shutil.which("sh")
        if shell is None:  # pragma: no cover - sh is present on the test host
            self.skipTest("no sh")
        result = self.run_cli("--secret", SECRET_PATH, "--", shell, "-c",
                              'printf "%s/%s" "$PGUSER" "$PGPASSWORD"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         "%s/%s" % (FIELDS["PGUSER"], FIELDS["PGPASSWORD"]))

    def test_nothing_is_left_behind_in_the_working_directory(self):
        result = self.standard()
        # Assert it ran first: otherwise this passes when the command never started,
        # which is how an equivalent test passed once inside a container image that
        # did not copy examples/ in.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARGV", result.stdout)
        self.assertEqual(os.listdir(self.scratch), ["stand-in-command"])

    def test_the_secret_is_read_from_the_mount_and_path_given(self):
        self.standard()
        self.assertEqual(self.fake.requests[-1].path,
                         "/v1/groups/data/%s" % SECRET_PATH)

    def test_a_different_mount_is_used_when_named(self):
        self.run_cli("--secret", SECRET_PATH, "--mount", "kv", "--", self.stand_in)
        self.assertEqual(self.fake.requests[-1].path,
                         "/v1/kv/data/%s" % SECRET_PATH)

    def test_the_vault_token_is_not_handed_to_the_command(self):
        # Reported by the child, from its own environment.
        result = self.standard()
        self.assertIn("ENV_HAS_TOKEN False", result.stdout)
        self.assertNotIn("hvs.a-legacy-export", result.stdout + result.stderr)

    def test_the_commands_own_children_inherit_the_variables(self):
        # Not a feature: an environment is inherited. Pinned as a fact because
        # "only for this command" is the wording people will reach for.
        result = self.standard("--grandchild", "PGPASSWORD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GRANDCHILD %r" % FIELDS["PGPASSWORD"], result.stdout)

    # -- arguments and exit status ---------------------------------------

    def test_command_arguments_are_passed_through_verbatim(self):
        result = self.standard("get", "--field-selector", "a=b", "-n", "efas")
        self.assertEqual(self.reported(result, "ARGV"),
                         ["get", "--field-selector", "a=b", "-n", "efas"])

    def test_arguments_are_passed_through_without_a_separator(self):
        result = self.run_cli("--secret", SECRET_PATH, self.stand_in, "status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.reported(result, "ARGV"), ["status"])

    def test_the_exit_status_is_the_commands_own(self):
        for status in ("42", "2", "1"):
            with self.subTest(status=status):
                result = self.standard(STAND_IN_EXIT=status)
                self.assertEqual(result.returncode, int(status))
                # The command's own 2 must not be mistaken for a failure of ours:
                # ours are the ones that print this prefix.
                self.assertNotIn("vaultenv:", result.stderr)

    def test_a_missing_command_is_reported_clearly(self):
        result = self.run_cli("--secret", SECRET_PATH, "--", "/nonexistent/thing")
        self.assertEqual(result.returncode, 127)
        self.assertIn("cannot run", result.stderr)

    def test_a_real_file_that_is_not_executable_is_reported_not_raised(self):
        # Not mocked: the OSError a real attempt produces, which review found reaching
        # the user as a traceback.
        path = os.path.join(self.scratch, "not-executable")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        result = self.run_cli("--secret", SECRET_PATH, "--", path)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("vaultenv: cannot run", result.stderr)
        self.assertIn("Permission denied", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_directory_in_place_of_a_command_is_reported_not_raised(self):
        result = self.run_cli("--secret", SECRET_PATH, "--", self.scratch)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("vaultenv: cannot run", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_help_works_without_a_token_or_a_secret(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("vaultenv", result.stdout)
        self.assertIn("--secret", result.stdout)

    # -- failure paths ----------------------------------------------------

    def test_a_refusal_reaches_the_user_with_the_prefix(self):
        self.fake.fields = {"LD_PRELOAD": "/tmp/evil.so"}
        result = self.run_cli("--secret", SECRET_PATH, "--force", "--", self.stand_in)
        self.assertEqual(result.returncode, 2)
        self.assertIn("vaultenv: refusing to set LD_PRELOAD", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_a_vault_failure_is_reported_without_running_the_command(self):
        result = self.standard(ECMWF_VAULT_TOKEN_FILE="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("vaultenv:", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_a_lone_surrogate_reaches_the_user_as_a_refusal_not_a_traceback(self):
        # The end-to-end version: a real response carrying \ud800, through the real
        # library, with nothing of the value in the output.
        self.fake.fields = {"PGPASSWORD": "before\ud800after"}
        result = self.run_cli("--secret", SECRET_PATH, "--field", "PGPASSWORD",
                              "--", self.stand_in)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("vaultenv: field 'PGPASSWORD' holds text", result.stderr)
        self.assertIn("lone surrogate", result.stderr)
        self.assertNotIn("before", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_an_unsupported_interpreter_is_reported_without_running_the_command(self):
        # Take memfd_create away from the interpreter that runs the command, the way
        # a conda-forge build lacks it, and check the diagnosis reaches the user.
        directory = _loopback_guard.sitecustomize_dir("import os\ndel os.memfd_create\n")
        result = self.standard(PYTHONPATH=os.pathsep.join((directory, SOURCE)))
        self.assertEqual(result.returncode, 2)
        self.assertIn("os.memfd_create", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    # -- the installed command -------------------------------------------

    def test_a_real_child_opens_the_descriptor_and_sees_no_variable(self):
        # The claim the in-process tests cannot make: that the number survives exec, and that
        # the child's own /proc/self/fd/<n> really is the sealed bytes. Everything else here is
        # about what was put in argv, which is a different fact.
        self.fake.fields = {"kubeconfig": KUBE_TEXT, "PGUSER": "cems"}
        # os.write, not a buffered file object: ``f.write(...)`` on a sealed memfd succeeds
        # into the buffer and only fails at close, so a probe that never closes reports a
        # writable file that is in fact sealed. Verified separately: the syscall returns EPERM
        # and the bytes are unchanged.
        reader = (
            "import os, sys\n"
            "path = sys.argv[1]\n"
            "print('FD ' + path)\n"
            "print('BODY ' + open(path).read().strip())\n"
            "descriptor = os.open(path, os.O_WRONLY)\n"
            "try:\n"
            "    os.write(descriptor, b'appended')\n"
            "    print('WRITABLE True')\n"
            "except OSError as error:\n"
            "    print('WRITABLE False ' + type(error).__name__)\n"
            "finally:\n"
            "    os.close(descriptor)\n"
            "print('VAR ' + repr(os.environ.get('kubeconfig')))\n")
        result = self.run_cli("--secret", SECRET_PATH, "--mem-field=kubeconfig:kube",
                              "--", sys.executable, "-c", reader, "{kube}")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = dict(line.split(" ", 1) for line in result.stdout.splitlines())
        self.assertTrue(lines["FD"].startswith("/proc/self/fd/"), lines["FD"])
        self.assertEqual(lines["BODY"], "apiVersion: v1")
        self.assertEqual(lines["VAR"], "None", "the field is not in the child's environment")
        # lines["WRITABLE"] is the value after the key was split off, so it reads
        # "False PermissionError".
        self.assertTrue(lines["WRITABLE"].startswith("False"),
                        "sealed: the child cannot edit what it was handed -> "
                        + lines["WRITABLE"])

    def test_a_real_child_reads_the_serialised_environment_file(self):
        self.fake.fields = {"PGUSER": "cems", "PGPASSWORD": "SYNTHETIC-PW"}
        reader = ("import os,sys;"
                  "print('BODY ' + open(sys.argv[1]).read().replace(chr(10), '|'));"
                  "print('PGUSER ' + repr(os.environ.get('PGUSER')))")
        result = self.run_cli("--secret", SECRET_PATH, "--field", "PGUSER",
                              "--field", "PGPASSWORD", "--mem-file=potatoes",
                              "--", sys.executable, "-c", reader, "{potatoes}")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = dict(line.split(" ", 1) for line in result.stdout.splitlines())
        self.assertEqual(lines["BODY"], "PGPASSWORD=SYNTHETIC-PW|PGUSER=cems|")
        self.assertEqual(lines["PGUSER"], "None")

    def test_two_nicks_reach_the_same_child_as_distinct_files(self):
        # If the numbers collided, or one slot were closed early, the child would read the
        # wrong secret rather than report anything useful.
        self.fake.fields = {"a": "first", "b": "second"}
        reader = ("import sys;"
                  "print('A ' + open(sys.argv[1]).read());"
                  "print('B ' + open(sys.argv[2]).read())")
        result = self.run_cli("--secret", SECRET_PATH, "--mem-field=a:one",
                              "--mem-field=b:two", "--", sys.executable, "-c", reader,
                              "{one}", "{two}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("A first", result.stdout)
        self.assertIn("B second", result.stdout)

    def test_a_descriptor_run_writes_nothing_to_disk(self):
        self.fake.fields = {"PGPASSWORD": "SYNTHETIC-PW"}
        before = sorted(os.listdir(self.scratch))
        result = self.run_cli("--secret", SECRET_PATH, "--mem-field=PGPASSWORD:pw", "--",
                              sys.executable, "-c", "import sys; open(sys.argv[1]).read()",
                              "{pw}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(os.listdir(self.scratch)), before)
        for root in (self.scratch, self.home):
            for directory, _, names in os.walk(root):
                for name in names:
                    with open(os.path.join(directory, name), "rb") as handle:
                        self.assertNotIn(b"SYNTHETIC-PW", handle.read(),
                                         os.path.join(directory, name))

    def test_pyproject_declares_the_console_script_and_it_resolves(self):
        # What makes this a command on PATH rather than a script in examples/.
        # pyproject is read as text because tomllib is not in Python 3.9.
        with open(PYPROJECT, encoding="utf-8") as handle:
            declared = re.search(r'^scripts\.vaultenv\s*=\s*"([^"]+)"',
                                 handle.read(), re.MULTILINE)
        self.assertIsNotNone(declared, "pyproject.toml declares no vaultenv script")
        self.assertEqual(declared.group(1), ENTRY_POINT)
        module_name, _, attribute = ENTRY_POINT.partition(":")
        import importlib

        target = getattr(importlib.import_module(module_name), attribute)
        self.assertTrue(callable(target))


if __name__ == "__main__":
    unittest.main()
