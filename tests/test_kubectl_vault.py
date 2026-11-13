"""The kubectl wrapper: a kubeconfig that reaches kubectl without being a file.

The wrapper runs as a subprocess, the way a user runs it, against a loopback Vault and
a stand-in kubectl that reports what it was handed. One test uses the real kubectl,
because "kubectl accepts --kubeconfig=/proc/self/fd/<n>" is the assumption the whole
wrapper rests on.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import _fakes

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER = os.path.join(REPOSITORY, "examples", "kubectl_vault.py")
SOURCE = os.path.join(REPOSITORY, "src")
SECRET_PATH = "user_applications_and_services_team/cems_web"
FIELD = "k8s-cems-test"
TOKEN = "synthetic-vault-token"
SERVER = "https://k8s-cems-test-controller-00.ecmwf.int:6443"

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

STAND_IN_KUBECTL = '''#!%s
"""Report what the wrapper handed over, instead of talking to a cluster."""
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


class KubectlWrapperTests(unittest.TestCase):
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
            handle.write(STAND_IN_KUBECTL)
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

    def run_wrapper(self, *arguments, **overrides):
        return subprocess.run(
            [sys.executable, WRAPPER, *arguments],
            cwd=self.scratch, env=self.child_environment(**overrides),
            capture_output=True, text=True, timeout=60)

    def standard(self, *extra, **overrides):
        return self.run_wrapper("--secret", SECRET_PATH, "--field", FIELD,
                                "--kubectl", self.stand_in, *extra, **overrides)

    def handed_over(self, result):
        """The argv the stand-in kubectl reported receiving."""
        first = next(line for line in result.stdout.splitlines()
                     if line.startswith("ARGV "))
        return json.loads(first.split(" ", 1)[1])

    # -- the point of the wrapper ----------------------------------------

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

    def test_nothing_is_left_behind_in_the_working_or_temporary_directory(self):
        result = self.standard("--", "version")
        # Assert it ran first: otherwise this passes when the wrapper never started,
        # which is exactly how it passed inside a container image that lacked the file.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KUBECONFIG_START", result.stdout)
        self.assertEqual(os.listdir(self.scratch), ["stand-in-kubectl"])

    def test_the_real_kubectl_accepts_the_descriptor(self):
        # The one assumption that matters: kubectl must open /proc/self/fd/<n>.
        real = shutil.which("kubectl")
        if real is None:  # pragma: no cover - kubectl is present on the test host
            self.skipTest("kubectl is not installed")
        result = self.run_wrapper(
            "--secret", SECRET_PATH, "--field", FIELD, "--kubectl", real,
            "--", "config", "view", "--minify", "-o", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = json.loads(result.stdout)
        self.assertEqual(shown["clusters"][0]["cluster"]["server"], SERVER)
        self.assertEqual(shown["contexts"][0]["context"]["namespace"],
                         "efas-production")
        # kubectl redacts the credential it read from our descriptor.
        self.assertNotIn("SYNTHETIC-KUBECTL-TOKEN", result.stdout)

    # -- choosing a field -------------------------------------------------

    def test_the_only_field_is_used_when_field_is_omitted(self):
        result = self.run_wrapper("--secret", SECRET_PATH,
                                  "--kubectl", self.stand_in, "--", "version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KUBECONFIG_START", result.stdout)

    def test_several_fields_require_one_to_be_named(self):
        self.fake.fields = {FIELD: KUBECONFIG, "other": "x"}
        result = self.run_wrapper("--secret", SECRET_PATH,
                                  "--kubectl", self.stand_in, "--", "version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--field is required", result.stderr)
        self.assertIn(FIELD, result.stderr)
        self.assertIn("other", result.stderr)
        self.assertNotIn("ARGV", result.stdout)      # kubectl never ran

    def test_an_unknown_field_lists_what_is_there(self):
        result = self.run_wrapper("--secret", SECRET_PATH, "--field", "nope",
                                  "--kubectl", self.stand_in, "--", "version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no field 'nope'", result.stderr)
        self.assertIn(FIELD, result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_a_field_that_is_not_text_is_reported(self):
        # A Vault field can hold JSON, so this is a real failure mode, not a
        # hypothetical one.
        self.fake.fields = {FIELD: {"a": "b"}}
        result = self.standard("--", "version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not kubeconfig text", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_missing_required_arguments_exit_with_usage(self):
        result = self.run_wrapper("--kubectl", self.stand_in, "--", "version")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--secret", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_help_works_without_a_token_or_a_secret(self):
        result = self.run_wrapper("--help", ECMWF_VAULT_TOKEN="")
        self.assertEqual(result.returncode, 0)
        self.assertIn("kubectl-vault", result.stdout)
        self.assertIn("--secret", result.stdout)

    # -- arguments and exit status ---------------------------------------

    def test_kubectl_arguments_are_passed_through_verbatim(self):
        result = self.standard("get", "pods", "--field-selector",
                               "status.phase=Running", "-n", "efas-production")
        self.assertEqual(self.handed_over(result)[1:],
                         ["get", "pods", "--field-selector",
                          "status.phase=Running", "-n", "efas-production"])

    def test_the_exit_status_is_kubectls_own(self):
        for status in ("42", "2", "1"):
            with self.subTest(status=status):
                result = self.standard("--", "version", STAND_IN_EXIT=status)
                self.assertEqual(result.returncode, int(status))
                # kubectl's own 2 must not be mistaken for a wrapper failure: the
                # wrapper's failures are the ones that print this prefix.
                self.assertNotIn("kubectl-vault:", result.stderr)

    def test_a_missing_kubectl_is_reported_clearly(self):
        result = self.run_wrapper("--secret", SECRET_PATH, "--field", FIELD,
                                  "--kubectl", "/nonexistent/kubectl", "--",
                                  "version")
        self.assertEqual(result.returncode, 127)
        self.assertIn("cannot run", result.stderr)

    def test_no_kubectl_cache_points_kubectl_at_dev_null(self):
        result = self.standard("--no-kubectl-cache", "--", "version")
        self.assertIn("--cache-dir=/dev/null", self.handed_over(result))

    # -- failure paths ----------------------------------------------------

    def test_a_vault_failure_is_reported_without_running_kubectl(self):
        result = self.standard("--", "version", ECMWF_VAULT_TOKEN="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("kubectl-vault:", result.stderr)
        self.assertNotIn("ARGV", result.stdout)

    def test_an_unsupported_interpreter_is_reported_without_running_kubectl(self):
        # Take memfd_create away from the interpreter that runs the wrapper, the way
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


if __name__ == "__main__":
    unittest.main()
