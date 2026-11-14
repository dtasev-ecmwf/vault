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
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--", "cmd"], mapping(PGUSER="cems"))
        self.assertIn("HOME", environment)
        self.assertIn("PATH", environment)

    def test_the_vault_token_is_not_handed_to_the_command(self):
        # Set by hand, not by the fixture: nothing here reads that name, and the point is that a
        # stale export from an older copy of this package does not travel into the child.
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": "hvs.a-legacy-export"}):
            _, _, environment = self.run_cli(
                ["--secret", "p", "--", "cmd"], mapping(PGUSER="cems"))
        self.assertNotIn("ECMWF_VAULT_TOKEN", environment)
        self.assertIn("HOME", environment)

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
        self.assertNotIn("PGPASSWORD", environment)

    def test_field_selects_one_field_under_its_own_name(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--", "cmd"],
                mapping(PGUSER="cems", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertNotIn("PGPASSWORD", environment)

    def test_field_is_repeatable(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--field", "PGHOST", "--", "cmd"],
                mapping(PGUSER="cems", PGHOST="db", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertEqual(environment["PGHOST"], "db")
        self.assertNotIn("PGPASSWORD", environment)

    def test_field_and_set_together_are_the_union(self):
        with _fakes.vault_environment():
            _, _, environment = self.run_cli(
                ["--secret", "p", "--field", "PGUSER", "--set", "DB=PGHOST", "--", "cmd"],
                mapping(PGUSER="cems", PGHOST="db", PGPASSWORD="pw"))
        self.assertEqual(environment["PGUSER"], "cems")
        self.assertEqual(environment["DB"], "db")
        self.assertNotIn("PGPASSWORD", environment)

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
