# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The kubectl_vault command: a kubeconfig that reaches kubectl without being a file.

Two layers. The in-process layer calls the module's own functions, where an assertion can
be exact — which descriptor was passed, exactly what kubectl's argv would be — and where
coverage can see it, since the command now ships inside the package. The black-box layer
runs ``python -m ecmwf_vault.commands.kubectl_vault`` against a loopback Vault and a stand-in
kubectl, and one test uses the real kubectl, because "kubectl accepts
--kubeconfig=/proc/self/fd/<n>" is the assumption the whole command rests on.
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
from ecmwf_vault import Secret, VaultError
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands import kubectl_vault as kl

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(REPOSITORY, "pyproject.toml")
SOURCE = os.path.join(REPOSITORY, "src")
SECRET_PATH = "user_applications_and_services_team/cems_web"
FIELD = "k8s-cems-test"
TOKEN = "synthetic-vault-token"
SERVER = "https://k8s-cems-test-controller-00.ecmwf.int:6443"
ENTRY_POINT = "ecmwf_vault.commands.kubectl_vault:main"

KUBECONFIG = """apiVersion: v1
kind: Config
current-context: cems-test
clusters:
- name: cems-test
  cluster:
    server: %s
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClNZTlRIRVRJQw==
contexts:
- name: cems-test
  context: {cluster: cems-test, user: cems-test, namespace: efas-production}
users:
- name: cems-test
  user:
    token: SYNTHETIC-KUBECTL-TOKEN
""" % SERVER


def mapping(**fields):
    """A field mapping shaped the way the client returns one."""
    return {name: Secret(text) for name, text in fields.items()}


class InProcessTests(unittest.TestCase):
    """The command's own functions: field choice, the environment, and launching."""

    def run_cli(self, argv, fields=None, status=0):
        """Run ``run()`` with a fake Vault and a fake child, and report what it did."""
        if fields is None:
            fields = mapping(**{FIELD: KUBECONFIG})
        with mock.patch.object(kl, "value", return_value=fields), \
                mock.patch.object(contract, "subprocess") as child:
            child.call.return_value = status
            returned = kl.run(argv)
            call = child.call.call_args if child.call.called else None
        return returned, call

    def refusal(self, argv, fields=None):
        """The message a refused invocation refuses with."""
        if fields is None:
            fields = mapping(**{FIELD: KUBECONFIG})
        with mock.patch.object(kl, "value", return_value=fields):
            with self.assertRaises(SystemExit) as caught:
                kl.run(argv)
        self.assertIsInstance(caught.exception.code, str)
        return str(caught.exception.code)

    # -- what kubectl is handed -------------------------------------------

    def test_kubectl_is_pointed_at_the_descriptor_and_not_a_file(self):
        with _fakes.vault_environment():
            _, call = self.run_cli(["--secret", "p", "--", "version"])
        command = call.args[0]
        self.assertTrue(command[0].endswith("kubectl"))
        self.assertTrue(command[1].startswith("--kubeconfig=/proc/self/fd/"),
                        command[1])
        self.assertEqual(command[2:], ["version"])

    def test_the_descriptor_handed_over_is_the_sealed_one(self):
        with _fakes.vault_environment():
            _, call = self.run_cli(["--secret", "p", "--", "version"])
        descriptor = int(call.args[0][1].split("/")[-1])
        self.assertEqual(call.kwargs["pass_fds"], (descriptor,))

    def test_kubectl_does_not_inherit_the_vault_token(self):
        with _fakes.vault_environment(ECMWF_VAULT_TOKEN=TOKEN):
            _, call = self.run_cli(["--secret", "p", "--", "version"])
        self.assertNotIn("ECMWF_VAULT_TOKEN", call.kwargs["env"])
        self.assertIn("HOME", call.kwargs["env"])

    def test_the_command_arguments_are_appended_in_order(self):
        # The shape the user actually types: flags before the verb, no "--".
        with _fakes.vault_environment():
            _, call = self.run_cli(["--secret", "p", "--field", FIELD,
                                    "-n", "glofas-stage", "get", "pods"])
        self.assertEqual(call.args[0][2:], ["-n", "glofas-stage", "get", "pods"])

    def test_no_kubectl_cache_points_kubectl_at_dev_null(self):
        with _fakes.vault_environment():
            _, call = self.run_cli(["--secret", "p", "--no-kubectl-cache", "--", "v"])
        self.assertIn("--cache-dir=/dev/null", call.args[0])

    def test_the_return_value_is_kubectls_status(self):
        with _fakes.vault_environment():
            returned, _ = self.run_cli(["--secret", "p", "--", "v"], status=42)
        self.assertEqual(returned, 42)

    # -- choosing a field --------------------------------------------------

    def test_the_only_field_is_used_when_field_is_omitted(self):
        with _fakes.vault_environment():
            _, call = self.run_cli(["--secret", "p", "--", "v"])
        self.assertTrue(call.args[0][1].startswith("--kubeconfig="))

    def test_several_fields_require_one_to_be_named(self):
        message = self.refusal(["--secret", "p", "--", "v"],
                              mapping(**{FIELD: KUBECONFIG, "other": "x"}))
        self.assertIn("--field is required", message)
        self.assertIn(FIELD, message)
        self.assertIn("other", message)

    def test_an_unknown_field_lists_what_is_there(self):
        message = self.refusal(["--secret", "p", "--field", "nope", "--", "v"])
        self.assertIn("no field 'nope'", message)
        self.assertIn(FIELD, message)

    def test_a_field_that_is_not_text_is_reported(self):
        # A Vault field can hold JSON, so this is a real failure mode, not a
        # hypothetical one.
        message = self.refusal(["--secret", "p", "--", "v"], mapping(**{FIELD: {"a": "b"}}))
        self.assertIn("not kubeconfig text", message)

    def test_a_lone_surrogate_kubeconfig_is_refused_without_leaking_it(self):
        # The same exposure as vaultenv's: Vault JSON can carry a lone surrogate, which
        # no UTF-8 encoding accepts, and UnicodeEncodeError.object is the text.
        canary = "before\ud800after"
        message = self.refusal(["--secret", "p", "--", "v"], mapping(**{FIELD: canary}))
        self.assertIn("cannot be encoded as UTF-8", message)
        self.assertIn(FIELD, message)
        self.assertNotIn("before", message)

    def test_the_kubeconfig_is_encoded_as_utf8(self):
        encoded = kl.reveal_kubeconfig(mapping(**{FIELD: "k\u00e9y"}), FIELD)
        self.assertEqual(encoded, "k\u00e9y".encode("utf-8"))

    # -- launching ---------------------------------------------------------

    def test_a_vault_failure_is_reported_with_the_prefix(self):
        with mock.patch.object(kl, "value", side_effect=VaultError("no token here")):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = kl.run(["--secret", "p", "--", "v"])
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("kubectl_vault: no token here", stderr.getvalue())

    def test_main_turns_a_refusal_into_status_2_with_the_prefix(self):
        with _fakes.vault_environment():
            with mock.patch.object(sys, "argv", ["kubectl_vault", "--secret", "p"]), \
                    mock.patch.object(kl, "value",
                                      return_value=mapping(**{FIELD: KUBECONFIG, "x": "y"})):
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    status = kl.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)
        self.assertIn("kubectl_vault: that secret has 2 fields", stderr.getvalue())

    def test_main_passes_argparses_status_through(self):
        with mock.patch.object(sys, "argv", ["kubectl_vault", "--", "v"]):
            with contextlib.redirect_stderr(io.StringIO()):
                status = kl.main()
        self.assertEqual(status, contract.EXIT_COMMAND_FAILED)

    def test_main_returns_kubectls_status(self):
        with _fakes.vault_environment():
            with mock.patch.object(sys, "argv",
                                   ["kubectl_vault", "--secret", "p", "--", "v"]), \
                    mock.patch.object(kl, "value",
                                      return_value=mapping(**{FIELD: KUBECONFIG})), \
                    mock.patch.object(contract, "subprocess") as child:
                child.call.return_value = 7
                self.assertEqual(kl.main(), 7)


class BlackBoxTests(unittest.TestCase):
    """The real thing: a subprocess kubectl, a loopback Vault, a real descriptor."""

    STAND_IN_KUBECTL = '''#!%s
"""Report what the command handed over, instead of talking to a cluster."""
import json, os, sys

arguments = sys.argv[1:]
print("ARGV " + json.dumps(arguments))
print("ENV_HAS_TOKEN %%s" %% ("ECMWF_VAULT_TOKEN" in os.environ))
path = next(a.split("=", 1)[1] for a in arguments if a.startswith("--kubeconfig="))
with open(path) as handle:
    print("KUBECONFIG_START")
    print(handle.read(), end="")
    print("KUBECONFIG_END")
sys.exit(int(os.environ.get("STAND_IN_EXIT", "0")))
''' % sys.executable

    def setUp(self):
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {FIELD: KUBECONFIG}
        self.scratch = tempfile.mkdtemp(prefix="ecmwf-vault-kubectl-")
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.home = tempfile.mkdtemp(prefix="ecmwf-vault-kubectl-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.stand_in = os.path.join(self.scratch, "stand-in-kubectl")
        with open(self.stand_in, "w", encoding="utf-8") as handle:
            handle.write(self.STAND_IN_KUBECTL)
        os.chmod(self.stand_in, stat.S_IRWXU)

    def child_environment(self, **overrides):
        """A deliberately small environment, so nothing is inherited by accident."""
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": SOURCE,
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
            "HOME": self.home,
            "TMPDIR": self.scratch,
            "ECMWF_VAULT_TOKEN": TOKEN,
            "ECMWF_VAULT_ADDR": self.fake.base_url,
            "ECMWF_VAULT_CA_BUNDLE": self.fake.ca_bundle,
        }
        environment.update(overrides)
        return environment

    def run_cli(self, *arguments, **overrides):
        """Run the module the way the console script does, as a subprocess."""
        return subprocess.run(
            [sys.executable, "-m", "ecmwf_vault.commands.kubectl_vault", *arguments],
            cwd=self.scratch, env=self.child_environment(**overrides),
            capture_output=True, text=True, timeout=60)

    def standard(self, *extra, **overrides):
        return self.run_cli("--secret", SECRET_PATH, "--field", FIELD,
                            "--kubectl", self.stand_in, *extra, **overrides)

    def handed_over(self, result):
        """The argv the stand-in kubectl reported receiving."""
        first = next(line for line in result.stdout.splitlines()
                     if line.startswith("ARGV "))
        return json.loads(first.split(" ", 1)[1])

    # -- the point of the command ----------------------------------------

    def test_the_kubeconfig_reaches_kubectl_through_a_descriptor(self):
        result = self.standard("--", "version")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.handed_over(result)
        self.assertTrue(arguments[0].startswith("--kubeconfig=/proc/self/fd/"),
                        arguments[0])
        contents = result.stdout.split("KUBECONFIG_START\n", 1)[1]
        self.assertEqual(contents.split("\nKUBECONFIG_END", 1)[0] + "\n", KUBECONFIG)

    def test_kubectl_does_not_inherit_the_vault_token(self):
        result = self.standard("--", "version")
        self.assertIn("ENV_HAS_TOKEN False", result.stdout)

    def test_nothing_is_left_behind_in_the_working_directory(self):
        result = self.standard("--", "version")
        # Assert it ran first: otherwise this passes when the command never started.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KUBECONFIG_START", result.stdout)
        self.assertEqual(os.listdir(self.scratch), ["stand-in-kubectl"])

    def test_the_real_kubectl_accepts_the_descriptor(self):
        # The one assumption that matters: kubectl must open /proc/self/fd/<n>.
        real = shutil.which("kubectl")
        if real is None:  # pragma: no cover - kubectl is present on the test host
            self.skipTest("kubectl is not installed")
        result = self.run_cli(
            "--secret", SECRET_PATH, "--field", FIELD, "--kubectl", real,
            "--", "config", "view", "--minify", "-o", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = json.loads(result.stdout)
        self.assertEqual(shown["clusters"][0]["cluster"]["server"], SERVER)
        self.assertEqual(shown["contexts"][0]["context"]["namespace"],
                         "efas-production")
        # kubectl redacts the credential it read from our descriptor.
        self.assertNotIn("SYNTHETIC-KUBECTL-TOKEN", result.stdout)

    def test_the_users_flag_order_works_without_a_separator(self):
        # -n before the verb, and no "--": the shape people actually type.
        result = self.run_cli("--secret", SECRET_PATH, "--field", FIELD,
                              "--kubectl", self.stand_in,
                              "-n", "glofas-stage", "get", "pods")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.handed_over(result)[1:],
                         ["-n", "glofas-stage", "get", "pods"])

    def test_kubectl_arguments_are_passed_through_verbatim(self):
        result = self.standard("get", "pods", "--field-selector",
                               "status.phase=Running", "-n", "efas-production")
        self.assertEqual(self.handed_over(result)[1:],
                         ["get", "pods", "--field-selector",
                          "status.phase=Running", "-n", "efas-production"])

    # -- exit status -------------------------------------------------------

    def test_the_exit_status_is_kubectls_own(self):
        for status in ("42", "2", "1"):
            with self.subTest(status=status):
                result = self.standard("--", "version", STAND_IN_EXIT=status)
                self.assertEqual(result.returncode, int(status))
                # kubectl's own 2 must not be mistaken for a failure of ours: ours
                # are the ones that print this prefix.
                self.assertNotIn("kubectl_vault:", result.stderr)

    def test_help_works_without_a_token_or_a_secret(self):
        result = self.run_cli("--help", ECMWF_VAULT_TOKEN="")
        self.assertEqual(result.returncode, 0)
        self.assertIn("kubectl_vault", result.stdout)
        self.assertIn("--secret", result.stdout)

    # -- failure paths -----------------------------------------------------

    def test_a_missing_kubectl_is_reported_clearly(self):
        result = self.run_cli("--secret", SECRET_PATH, "--field", FIELD,
                              "--kubectl", "/nonexistent/kubectl", "--", "version")
        self.assertEqual(result.returncode, 127)
        self.assertIn("cannot run", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_kubectl_that_is_not_executable_is_reported_not_raised(self):
        # Not mocked: the OSError a real attempt produces.
        path = os.path.join(self.scratch, "not-executable")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        result = self.run_cli("--secret", SECRET_PATH, "--field", FIELD,
                              "--kubectl", path, "--", "version")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("kubectl_vault: cannot run", result.stderr)
        self.assertIn("Permission denied", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_directory_in_place_of_kubectl_is_reported_not_raised(self):
        result = self.run_cli("--secret", SECRET_PATH, "--field", FIELD,
                              "--kubectl", self.scratch, "--", "version")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("kubectl_vault: cannot run", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_several_fields_require_one_to_be_named(self):
        self.fake.fields = {FIELD: KUBECONFIG, "other": "x"}
        result = self.run_cli("--secret", SECRET_PATH, "--kubectl", self.stand_in,
                              "--", "version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--field is required", result.stderr)
        self.assertNotIn("ARGV", result.stdout)      # kubectl never ran

    def test_a_lone_surrogate_reaches_the_user_as_a_refusal_not_a_traceback(self):
        self.fake.fields = {FIELD: "before\ud800after"}
        result = self.standard("--", "version")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("kubectl_vault: the field", result.stderr)
        self.assertIn("cannot be encoded as UTF-8", result.stderr)
        self.assertNotIn("before", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_a_vault_failure_is_reported_without_running_kubectl(self):
        result = self.standard("--", "version", ECMWF_VAULT_TOKEN="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("kubectl_vault:", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_an_unsupported_interpreter_is_reported_without_running_kubectl(self):
        # Take memfd_create away from the interpreter that runs the command, the way
        # a conda-forge build lacks it, and check the diagnosis reaches the user.
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-nosupport-")
        self.addCleanup(shutil.rmtree, directory, True)
        with open(os.path.join(directory, "sitecustomize.py"), "w",
                  encoding="utf-8") as handle:
            handle.write("import os\ndel os.memfd_create\n")
        result = self.standard("--", "version",
                               PYTHONPATH="%s:%s" % (directory, SOURCE))
        self.assertEqual(result.returncode, 2)
        self.assertIn("os.memfd_create", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    # -- the installed command --------------------------------------------

    def test_pyproject_declares_the_console_script_and_it_resolves(self):
        # What makes this a command on PATH rather than a script in examples/.
        # pyproject is read as text because tomllib is not in Python 3.9.
        with open(PYPROJECT, encoding="utf-8") as handle:
            declared = re.search(r'^scripts\.kubectl_vault\s*=\s*"([^"]+)"',
                                 handle.read(), re.MULTILINE)
        self.assertIsNotNone(declared, "pyproject.toml declares no kubectl_vault script")
        self.assertEqual(declared.group(1), ENTRY_POINT)
        module_name, _, attribute = ENTRY_POINT.partition(":")
        self.assertTrue(callable(getattr(importlib.import_module(module_name), attribute)))


if __name__ == "__main__":
    unittest.main()
