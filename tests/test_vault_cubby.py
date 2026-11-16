# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The vault_cubby command: cubbyhole fields as environment variables, for one command.

Two layers, as with ``vaultenv``. In process, where a refusal can be checked exactly —
whether naming a forbidden field revealed a value is countable there and not from outside. And
as a
real subprocess against a loopback Vault, which is the only way to prove that a real program
received the values, that the token did not, and that the exit status is the child's own.

What is specific to this command is *where the read goes*: ``/v1/cubbyhole/<path>``, with no
mount to choose and no ``data/`` layer. What is not specific — selection, refusals,
``--force``, the scrubbed child environment — is ``vaultenv``'s code, reused rather than
restated, and tested here only to prove the reuse is wired up.
"""
from __future__ import annotations

import contextlib
import importlib
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
from ecmwf_vault import InvalidSecretPathError, Secret, VaultError
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import vault_cubby as cli
from ecmwf_vault.commands import vaultenv

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(REPOSITORY, "pyproject.toml")
SOURCE = os.path.join(REPOSITORY, "src")
CUBBY_PATH = "madt/efas"
TOKEN = "synthetic-vault-token"
FIELDS = {"DB_USER": "cems", "DB_PASSWORD": "SYNTHETIC-CUBBY-VALUE"}
ENTRY_POINT = "ecmwf_vault.commands.vault_cubby:main"


class Recording:
    """A stand-in for a Secret that counts how often its value is revealed."""

    def __init__(self, text):
        self.text = text
        self.reveals = 0

    def reveal(self):
        self.reveals += 1
        return self.text


def mapping(**fields):
    """A field mapping shaped the way the client returns one."""
    return {name: Secret(text) for name, text in fields.items()}


class InProcessTests(unittest.TestCase):
    def setUp(self):
        # No ambient variable may change what these assert; see _fakes.isolate.
        _fakes.isolate(self)

    """The command's own functions: the read it makes, and what it hands the child."""

    def run_cli(self, argv, fields, status=0):
        with mock.patch.object(cli, "cubbyhole_read", return_value=fields), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = status
            returned = cli.run(argv)
            command = None
            environment = None
            if child.call.called:
                command = child.call.call_args.args[0]
                environment = child.call.call_args.kwargs["env"]
        return returned, command, environment

    def refusal(self, argv, fields):
        """The message a refused invocation refuses with."""
        with mock.patch.object(cli, "cubbyhole_read", return_value=fields):
            with self.assertRaises(SystemExit) as caught:
                cli.run(argv)
        self.assertIsInstance(caught.exception.code, str)
        return str(caught.exception.code)

    # -- the read ---------------------------------------------------------

    def test_the_path_is_read_from_the_cubbyhole(self):
        with mock.patch.object(cli, "cubbyhole_read",
                               return_value=mapping(**FIELDS)) as read:
            cli.run(["--path", CUBBY_PATH, "--", "cmd"])
        self.assertEqual(read.call_args.args, (CUBBY_PATH,))
        self.assertEqual(read.call_args.kwargs, {})

    def test_no_mount_is_ever_passed(self):
        # cubbyhole_read takes no mount at all, so this is a compile-level guarantee; what is
        # pinned here is that the command does not try to supply one.
        signature = __import__("inspect").signature(cli.cubbyhole_read)
        self.assertNotIn("mount", signature.parameters)

    def test_the_command_offers_no_mount_option(self):
        with self.assertRaises(SystemExit) as caught:
            cli.build_parser().parse_args(["--path", CUBBY_PATH, "--mount", "groups",
                                           "--", "cmd"])
        self.assertIsInstance(caught.exception.code, int)

    # -- what the child receives ------------------------------------------

    def test_every_field_becomes_a_variable_of_the_same_name(self):
        _, command, environment = self.run_cli(["--path", CUBBY_PATH, "--", "cmd", "arg"],
                                               mapping(**FIELDS))
        self.assertEqual(command, ["cmd", "arg"])
        for name, text in FIELDS.items():
            self.assertEqual(environment[name], text)

    def test_a_selection_names_the_variables_it_sets(self):
        _, _, environment = self.run_cli(
            ["--path", CUBBY_PATH, "--field", "DB_USER", "--", "cmd"], mapping(**FIELDS))
        self.assertEqual(environment["DB_USER"], FIELDS["DB_USER"])
        self.assertFalse("DB_PASSWORD" in environment,
                         "DB_PASSWORD must not reach the child environment")

    def test_a_renamed_field_arrives_under_the_chosen_name(self):
        _, _, environment = self.run_cli(
            ["--path", CUBBY_PATH, "--set", "SECRET=DB_PASSWORD", "--", "cmd"],
            mapping(**FIELDS))
        self.assertEqual(environment["SECRET"], FIELDS["DB_PASSWORD"])
        self.assertFalse("DB_PASSWORD" in environment,
                         "DB_PASSWORD must not reach the child environment")

    def test_the_rest_of_the_environment_is_kept(self):
        # Pinned values: comparing against what the runner happens to export would make the
        # assertion mean something different on another host, or fail where one is unset.
        with mock.patch.dict(os.environ, {"HOME": "/known/home", "PATH": "/known/path"}):
            _, _, environment = self.run_cli(["--path", CUBBY_PATH, "--", "cmd"],
                                             mapping(DB_USER="cems"))
        self.assertEqual(environment["HOME"], "/known/home")
        self.assertEqual(environment["PATH"], "/known/path")

    def test_the_vault_token_is_not_handed_to_the_command(self):
        # The scrub is vaultenv's, and this pins that vault_cubby goes through it rather than
        # through a copy that could drift.
        with mock.patch.dict(os.environ, {"ECMWF_VAULT_TOKEN": "hvs.a-legacy-export",
                                          "HOME": "/known/home"}):
            _, _, environment = self.run_cli(["--path", CUBBY_PATH, "--", "cmd"],
                                             mapping(DB_USER="cems"))
        self.assertFalse("ECMWF_VAULT_TOKEN" in environment,
                         "the legacy token variable must not reach the child")
        self.assertEqual(environment["HOME"], "/known/home",
                         "everything else still travels to the child")

    def test_the_childs_status_is_returned(self):
        returned, _, _ = self.run_cli(["--path", CUBBY_PATH, "--", "cmd"],
                                      mapping(**FIELDS), status=42)
        self.assertEqual(returned, 42)

    # -- refusals ---------------------------------------------------------

    def test_a_forbidden_name_is_refused_even_with_force(self):
        message = self.refusal(["--path", CUBBY_PATH, "--set", "LD_PRELOAD=DB_USER",
                                "--force", "--", "cmd"], mapping(**FIELDS))
        self.assertIn("refusing to set LD_PRELOAD", message)

    def test_a_credential_name_is_refused(self):
        for name in ("VAULT_TOKEN", "ECMWF_VAULT_TOKEN"):
            with self.subTest(name=name):
                message = self.refusal(["--path", CUBBY_PATH, "--force", "--", "cmd"],
                                       mapping(**{name: "another-token",
                                                  "DB_USER": "cems"}))
                self.assertIn("refusing to set %s" % name, message)

    def test_a_name_refusal_reveals_nothing(self):
        # Counted, not inferred: a refusal that happens after reveal() has run has already
        # produced the value in this process, which no subprocess test can see.
        canary = {"PATH": Recording("CANARY"), "DB_USER": Recording("CANARY")}
        message = self.refusal(["--path", CUBBY_PATH, "--force", "--", "cmd"], canary)
        self.assertEqual([field.reveals for field in canary.values()], [0, 0])
        self.assertNotIn("CANARY", message)

    def test_an_existing_variable_needs_force(self):
        with mock.patch.dict(os.environ, {"DB_USER": "already-set"}):
            message = self.refusal(["--path", CUBBY_PATH, "--", "cmd"], mapping(**FIELDS))
        self.assertIn("already set", message)
        self.assertIn("DB_USER", message)

    def test_a_field_that_is_not_text_is_refused_by_name(self):
        message = self.refusal(["--path", CUBBY_PATH, "--", "cmd"],
                               {**mapping(DB_USER="cems"), "DB_PASSWORD": Secret({"a": 1})})
        self.assertIn("holds dict, not text", message)
        self.assertNotIn("SYNTHETIC-CUBBY-VALUE", message)

    def test_a_lone_surrogate_is_refused_without_revealing_the_value(self):
        message = self.refusal(["--path", CUBBY_PATH, "--", "cmd"],
                               mapping(DB_USER="before\ud800after"))
        self.assertIn("lone surrogate", message)
        self.assertNotIn("before", message)

    def test_a_secret_with_no_fields_is_refused(self):
        message = self.refusal(["--path", CUBBY_PATH, "--", "cmd"], {})
        self.assertIn("no fields", message)

    def test_an_unusable_path_is_a_vault_failure_not_a_request(self):
        # Validation lives in the library, so what the command owes the user is the failure:
        # reported under its own prefix, with no child launched. The request path itself is
        # pinned against the fake server in BlackBoxTests.
        with mock.patch.object(cli, "cubbyhole_read",
                               side_effect=InvalidSecretPathError("bad path")), \
                mock.patch.object(contract, "subprocess") as child:
            status = cli.run(["--path", "../escape", "--", "cmd"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        child.call.assert_not_called()

    def test_a_vault_failure_is_reported_and_the_child_never_runs(self):
        with mock.patch.object(cli, "cubbyhole_read",
                               side_effect=VaultError("the secret was not found (404)")), \
                mock.patch.object(contract, "subprocess") as child:
            status = cli.run(["--path", CUBBY_PATH, "--", "cmd"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        child.call.assert_not_called()

    def test_no_command_is_a_failure_naming_the_separator(self):
        with mock.patch.object(cli, "cubbyhole_read", return_value=mapping(**FIELDS)):
            status = cli.run(["--path", CUBBY_PATH])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)

    # -- main -------------------------------------------------------------

    def test_main_returns_the_childs_status(self):
        argv = ["vault_cubby", "--path", CUBBY_PATH, "--", "cmd"]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(cli, "cubbyhole_read", return_value=mapping(**FIELDS)), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = 7
            self.assertEqual(cli.main(), 7)

    def test_main_prints_a_refusal_under_its_own_prefix(self):
        argv = ["vault_cubby", "--path", CUBBY_PATH, "--set", "PATH=DB_USER", "--", "c"]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(cli, "cubbyhole_read", return_value=mapping(**FIELDS)), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = cli.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_cubby: refusing to set PATH", stderr.getvalue())


class SharedBehaviourTests(unittest.TestCase):
    """The two commands must not drift apart where they mean to behave alike."""

    def test_the_rules_are_the_same_objects_not_copies(self):
        # Reusing vaultenv's functions is the design; a local reimplementation would pass the
        # tests above while letting the two commands diverge.
        self.assertIs(cli.refuse_forbidden_names, vaultenv.refuse_forbidden_names)
        self.assertIs(cli.variable_mapping, vaultenv.variable_mapping)
        self.assertIs(cli.variable_values, vaultenv.variable_values)
        self.assertIs(cli.build_child_environment, vaultenv.build_child_environment)

    def test_the_contract_helpers_are_shared(self):
        self.assertIs(cli.contract.split_at_separator, contract.split_at_separator)
        self.assertIs(cli.contract.run_child, contract.run_child)


STAND_IN = '''#!%s
"""Report what it was handed instead of doing anything."""
import json, os, sys

print("ARGV " + json.dumps(sys.argv[1:]))
print("VARS " + json.dumps({name: os.environ.get(name)
                            for name in os.environ.get("STAND_IN_NAMES", "").split()}))
print("ENV_HAS_TOKEN %%s" %% ("ECMWF_VAULT_TOKEN" in os.environ))
sys.exit(int(os.environ.get("STAND_IN_EXIT", "0")))
''' % sys.executable


class BlackBoxTests(unittest.TestCase):
    """The real thing: a subprocess command, a loopback Vault, a real environment."""

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = dict(FIELDS)
        self.scratch = tempfile.mkdtemp(prefix="ecmwf-vault-cubby-")
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-cubby-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.token_path = _fakes.token_file(TOKEN)
        self.stand_in = os.path.join(self.scratch, "stand-in-command")
        with open(self.stand_in, "w", encoding="utf-8") as handle:
            handle.write(STAND_IN)
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
            "ECMWF_VAULT_TOKEN_FILE": self.token_path,
            # A stale export of the name an older version of this package authenticated with:
            # the stand-in reports whether it arrived, so the strip is not taken on trust.
            "ECMWF_VAULT_TOKEN": "hvs.a-legacy-export",
            "ECMWF_VAULT_ADDR": self.fake.base_url,
            "ECMWF_VAULT_CA_BUNDLE": self.fake.ca_bundle,
        }
        environment.update(overrides)
        return environment

    def run_cli(self, *arguments, **overrides):
        return subprocess.run(
            [sys.executable, "-m", "ecmwf_vault.commands.vault_cubby", *arguments],
            cwd=self.scratch, env=self.child_environment(**overrides),
            capture_output=True, text=True, timeout=60)

    def standard(self, *extra, **overrides):
        return self.run_cli("--path", CUBBY_PATH, "--", self.stand_in, *extra, **overrides)

    def reported(self, result, kind):
        line = next(line for line in result.stdout.splitlines()
                    if line.startswith(kind + " "))
        return line.split(" ", 1)[1]

    # -- the point of the command -----------------------------------------

    def test_the_cubbyhole_path_is_what_is_requested(self):
        result = self.standard("DB_USER")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([request.path for request in self.fake.requests],
                         ["/v1/cubbyhole/" + CUBBY_PATH])

    def test_the_mount_and_the_data_layer_are_absent_from_the_request(self):
        # The old failure was building "/v1/cubbyhole/data/<path>", which no Vault has: the
        # read came back as "not found" rather than as a cubbyhole that cannot be reached.
        self.standard("DB_USER")
        path = self.fake.requests[0].path
        self.assertNotIn("/data/", path)
        self.assertTrue(path.startswith("/v1/cubbyhole/"), path)

    def test_the_values_reach_the_command(self):
        result = self.standard("DB_USER", STAND_IN_NAMES=" ".join(FIELDS))
        self.assertEqual(json.loads(self.reported(result, "VARS")), FIELDS)

    def test_the_vault_token_is_not_handed_to_the_command(self):
        result = self.standard("DB_USER")
        self.assertIn("ENV_HAS_TOKEN False", result.stdout)
        self.assertNotIn("hvs.a-legacy-export", result.stdout + result.stderr)

    def test_the_token_never_appears_in_the_output(self):
        result = self.standard("DB_USER")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertNotIn(self.token_path, result.stdout + result.stderr)

    def test_no_file_holds_a_cubbyhole_read(self):
        result = self.standard("DB_USER")
        self.assertEqual(result.returncode, 0, result.stderr)
        # gpg creates ~/.gnupg for its own use on a first run, so the claim is about the
        # secret, not about the absence of any file at all.
        for root in (self.scratch, self.home):
            for directory, _, names in os.walk(root):
                for name in names:
                    path = os.path.join(directory, name)
                    with open(path, "rb") as handle:
                        contents = handle.read()
                    self.assertNotIn(b"SYNTHETIC-CUBBY-VALUE", contents, path)

    def test_the_exit_status_is_the_childs_own(self):
        for status in ("1", "2", "42"):
            with self.subTest(status=status):
                result = self.standard("DB_USER", STAND_IN_EXIT=status)
                self.assertEqual(result.returncode, int(status))
                self.assertEqual(result.stderr, "")

    def test_the_commands_own_children_inherit_the_variables(self):
        # An environment cannot be scoped to one execve; this is stated behaviour, not a leak.
        result = self.run_cli("--path", CUBBY_PATH, "--", sys.executable, "-c",
                              "import subprocess,sys,os;print(subprocess.run("
                              "[sys.executable,'-c','import os;"
                              "print(os.environ[\"DB_USER\"])'],"
                              "capture_output=True,text=True).stdout.strip())")
        self.assertEqual(result.stdout.strip(), FIELDS["DB_USER"], result.stderr)

    # -- refusals, as a user meets them ------------------------------------

    def test_a_missing_path_is_argpars_failure(self):
        result = self.run_cli("--", "true")
        self.assertEqual(result.returncode, contract.EXIT_COMMAND_FAILED)
        self.assertIn("--path", result.stderr)
        self.assertIn("required", result.stderr)

    def test_a_forbidden_name_is_refused_by_the_real_command(self):
        self.fake.fields = {"SSLKEYLOGFILE": "/tmp/keys"}
        result = self.run_cli("--path", CUBBY_PATH, "--", self.stand_in)
        self.assertEqual(result.returncode, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_cubby: refusing to set SSLKEYLOGFILE", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_a_secret_that_is_absent_is_reported_without_a_traceback(self):
        self.fake.status = 404
        result = self.standard("DB_USER")
        self.assertEqual(result.returncode, contract.EXIT_COMMAND_FAILED)
        self.assertIn("vault_cubby: the secret was not found (404)", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_help_works_without_a_token(self):
        result = self.run_cli("--help", ECMWF_VAULT_TOKEN_FILE="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cubbyhole", result.stdout)
        self.assertNotIn(TOKEN, result.stdout)

    def test_a_command_that_cannot_be_run_is_reported_not_raised(self):
        result = self.run_cli("--path", CUBBY_PATH, "--", "/nonexistent/command")
        self.assertEqual(result.returncode, contract.EXIT_CHILD_NOT_FOUND)
        self.assertIn("vault_cubby: cannot run '/nonexistent/command': no such file",
                      result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    # -- the installed command --------------------------------------------

    def test_pyproject_declares_the_console_script_and_it_resolves(self):
        # pyproject is read as text because tomllib is not in Python 3.9.
        with open(PYPROJECT, encoding="utf-8") as handle:
            declared = re.search(r'^scripts\.vault_cubby\s*=\s*"([^"]+)"',
                                 handle.read(), re.MULTILINE)
        self.assertIsNotNone(declared, "pyproject.toml declares no vault_cubby script")
        self.assertEqual(declared.group(1), ENTRY_POINT)
        module_name, _, attribute = ENTRY_POINT.partition(":")
        self.assertTrue(callable(getattr(importlib.import_module(module_name), attribute)))


if __name__ == "__main__":
    unittest.main()
