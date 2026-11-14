# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The two token sources: the environment, then a private config file.

The token choice is a security control, so these tests pin precedence, the
absence of silent fall-through, and every refusal the file can provoke.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import _fakes
from ecmwf_vault import (
    VaultConfigFileError,
    VaultTokenInvalidError,
    VaultTokenMissingError,
)
from ecmwf_vault import _config, _policy

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"
TOKEN = "synthetic-env-token"
FILE_TOKEN = "synthetic-file-token"


class ConfigTestCase(unittest.TestCase):
    """Common environment handling: inherit nothing from whoever runs the suite."""

    def setUp(self):
        # enterContext() is 3.11+, so call the pair explicitly to stay 3.9-clean.
        environment = _fakes.vault_environment()
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)


class TokenSourceTests(ConfigTestCase):
    def setUp(self):
        super().setUp()
        self.fake = _fakes.FakeVault()
        self.addCleanup(self.fake.stop)
        self.fake.fields = {"password": "synthetic-value"}
        self.vault = _fakes.make_vault(self.fake)
        self.addCleanup(self.vault.close)

    def sent_token(self):
        return self.fake.requests[0].headers["X-Vault-Token"]

    def test_the_environment_wins_over_the_config_file(self):
        os.environ[_config.TOKEN_KEY] = TOKEN
        os.environ[_config.CONFIG_ENV] = _fakes.write_config(
            "%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), TOKEN)

    def test_the_config_file_is_used_when_the_environment_is_unset(self):
        os.environ[_config.CONFIG_ENV] = _fakes.write_config(
            "# a comment\n\n%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_a_blank_environment_value_falls_through_to_the_file(self):
        os.environ[_config.TOKEN_KEY] = "   "
        os.environ[_config.CONFIG_ENV] = _fakes.write_config(
            "%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_a_malformed_environment_value_never_falls_through(self):
        # A supplied value that cannot be a token is an error, not a reason to
        # quietly use a different credential from the file.
        os.environ[_config.TOKEN_KEY] = "bad\ntoken"
        os.environ[_config.CONFIG_ENV] = _fakes.write_config(
            "%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        with self.assertRaises(VaultTokenInvalidError):
            self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.fake.requests, [])

    def test_the_file_is_re_read_on_every_call(self):
        path = _fakes.write_config("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        os.environ[_config.CONFIG_ENV] = path
        self.vault.value(EXAMPLE, cache=False)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (_config.TOKEN_KEY, "rotated-file-token"))
        self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.fake.requests[1].headers["X-Vault-Token"],
                         "rotated-file-token")

    def test_no_token_anywhere_is_an_error_before_any_request(self):
        with self.assertRaises(VaultTokenMissingError):
            self.vault.value(EXAMPLE)
        self.assertEqual(self.fake.requests, [])

    def test_the_default_path_is_used_when_the_environment_does_not_name_one(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ.pop(_config.CONFIG_ENV, None)
            with mock.patch.dict(os.environ, {"HOME": home}):
                directory = os.path.join(home, ".ecmwf-vault")
                os.makedirs(directory, 0o700)
                _fakes.write_config("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN),
                                    directory=directory)
                self.vault.value(EXAMPLE, cache=False)
        self.assertEqual(self.sent_token(), FILE_TOKEN)

    def test_an_explicitly_named_missing_file_is_an_error(self):
        os.environ[_config.CONFIG_ENV] = _fakes.absent_config_path()
        with self.assertRaises(VaultConfigFileError) as caught:
            self.vault.value(EXAMPLE)
        self.assertIn("does not exist", str(caught.exception))

    def test_the_token_never_appears_in_a_raised_message(self):
        for content in ("# only a comment\n",
                        "%s\n" % FILE_TOKEN,
                        'ECMWF_VAULT_TOKEN="%s"\n' % FILE_TOKEN,
                        "OTHER=1\n"):
            with self.subTest(content=content):
                os.environ[_config.CONFIG_ENV] = _fakes.write_config(content)
                try:
                    _config.resolve_token()
                except (VaultConfigFileError, VaultTokenMissingError) as error:
                    self.assertNotIn(FILE_TOKEN, str(error))
                    self.assertNotIn(FILE_TOKEN, repr(error))
                else:
                    self.fail("expected a failure for %r" % content)


class ConfigPathTests(ConfigTestCase):
    def test_a_named_path_is_used_and_reported_as_named(self):
        os.environ[_config.CONFIG_ENV] = "  /tmp/somewhere/config  "
        self.assertEqual(_config.config_path(), ("/tmp/somewhere/config", True))

    def test_the_default_is_expanded_and_not_reported_as_named(self):
        os.environ.pop(_config.CONFIG_ENV, None)
        with mock.patch.dict(os.environ, {"HOME": "/home/example"}):
            self.assertEqual(_config.config_path(),
                             ("/home/example/.ecmwf-vault/config", False))

    def test_a_blank_override_falls_back_to_the_default(self):
        os.environ[_config.CONFIG_ENV] = "   "
        self.assertEqual(_config.config_path()[1], False)

    def test_an_unknown_policy_is_rejected(self):
        for value in ("sometimes", "", "REFUSE", 7, ["refuse"]):
            with self.subTest(value=value):
                with self.assertRaises(VaultConfigFileError):
                    _config.resolve_policy(value)

    def test_the_policy_defaults_to_refuse_and_reads_the_environment(self):
        self.assertEqual(_config.resolve_policy(), _config.POLICY_REFUSE)
        os.environ[_config.POLICY_ENV] = "warn"
        self.assertEqual(_config.resolve_policy(), _config.POLICY_WARN)


class ConfigParseTests(unittest.TestCase):
    def parse(self, text):
        return _config.parse(text)

    def test_comments_blank_lines_and_whitespace(self):
        self.assertEqual(
            self.parse("# comment\n\n\t\n  %s = value  \n" % _config.TOKEN_KEY),
            {_config.TOKEN_KEY: "value"})

    def test_crlf_line_endings_are_accepted(self):
        self.assertEqual(
            self.parse("%s=value\r\n" % _config.TOKEN_KEY),
            {_config.TOKEN_KEY: "value"})

    def test_a_trailing_comment_marker_is_part_of_the_value(self):
        # Comments are whole lines only: a token could contain '#'.
        self.assertEqual(self.parse("%s=a#b\n" % _config.TOKEN_KEY),
                         {_config.TOKEN_KEY: "a#b"})

    def test_an_empty_file_yields_no_entries(self):
        self.assertEqual(self.parse(""), {})

    def test_rejections_are_attributed_to_a_line_without_echoing_it(self):
        cases = (
            ("no equals sign here", "malformed"),
            ("OTHER_KEY=value", "unsupported"),
            ("%s=one\n%s=two\n" % (_config.TOKEN_KEY, _config.TOKEN_KEY), "twice"),
            ('%s="quoted"\n' % _config.TOKEN_KEY, "quote"),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                with self.assertRaises(VaultConfigFileError) as caught:
                    self.parse(text)
                self.assertIn(expected, str(caught.exception))
                self.assertIn("line", str(caught.exception))

    def test_a_malformed_line_does_not_echo_the_line(self):
        # A file can accidentally put a secret in the key position, so a parse
        # error must name the line, never its content.
        with self.assertRaises(VaultConfigFileError) as caught:
            self.parse("hvs.synthetic-secret-value\n")
        self.assertNotIn("synthetic-secret-value", str(caught.exception))

    def test_an_empty_value_is_accepted_by_the_parser(self):
        self.assertEqual(self.parse("%s=\n" % _config.TOKEN_KEY),
                         {_config.TOKEN_KEY: ""})


class ConfigFileSafetyTests(ConfigTestCase):
    def write(self, text, **kwargs):
        return _fakes.write_config(text, **kwargs)

    def token_in(self, path, policy=None):
        os.environ[_config.CONFIG_ENV] = path
        if policy is not None:
            os.environ[_config.POLICY_ENV] = policy
        return _config.resolve_token()

    def test_a_0600_file_owned_by_us_is_read(self):
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        self.assertEqual(oct(stat.S_IMODE(os.stat(path).st_mode)), "0o600")
        self.assertEqual(self.token_in(path), FILE_TOKEN)

    def test_group_or_other_access_is_refused_by_default(self):
        for mode in (0o640, 0o604, 0o660, 0o644, 0o666, 0o607):
            with self.subTest(mode=oct(mode)):
                path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN),
                                  mode=mode)
                with self.assertRaises(VaultConfigFileError) as caught:
                    self.token_in(path)
                self.assertIn("600", str(caught.exception))
                self.assertNotIn(FILE_TOKEN, str(caught.exception))

    def test_a_0644_file_is_accepted_by_either_relaxed_policy_and_warns(self):
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN), mode=0o644)
        for policy in ("warn", "allow"):
            with self.subTest(policy=policy):
                _policy._warned.clear()  # warn_once is once per process
                with mock.patch("sys.stderr") as stderr:
                    self.assertEqual(self.token_in(path, policy=policy), FILE_TOKEN)
                written = "".join(str(call) for call in stderr.write.call_args_list)
                self.assertIn("600", written)
                self.assertIn(policy, written)

    def test_a_file_owned_by_another_user_is_refused(self):
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(VaultConfigFileError) as caught:
                self.token_in(path)
        self.assertIn("owned", str(caught.exception))

    def test_another_user_s_ownership_can_be_allowed_explicitly(self):
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        _policy._warned.clear()
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with mock.patch("sys.stderr") as stderr:
                self.assertEqual(self.token_in(path, policy="allow"), FILE_TOKEN)
        written = "".join(str(call) for call in stderr.write.call_args_list)
        self.assertIn("owned", written)

    def test_a_symlink_is_refused_whatever_the_policy_says(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-symlink-")
        real = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN),
                          directory=directory, name="real")
        link = os.path.join(directory, "config")
        os.symlink(real, link)
        for policy in (None, "warn", "allow"):
            with self.subTest(policy=policy):
                with self.assertRaises(VaultConfigFileError) as caught:
                    self.token_in(link, policy=policy)
                self.assertIn("symlink", str(caught.exception))

    def test_a_directory_is_refused(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-dir-")
        with self.assertRaises(VaultConfigFileError) as caught:
            self.token_in(directory, policy="allow")
        self.assertIn("regular file", str(caught.exception))

    def test_a_fifo_is_refused_without_blocking(self):
        # Opening a FIFO read-only blocks unless O_NONBLOCK is used, so this test
        # would hang rather than fail if that flag were dropped.
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-fifo-")
        path = os.path.join(directory, "config")
        os.mkfifo(path, 0o600)
        with self.assertRaises(VaultConfigFileError) as caught:
            self.token_in(path, policy="allow")
        self.assertIn("regular file", str(caught.exception))

    def test_an_oversized_file_is_refused(self):
        path = self.write("# padding\n" + ("#" * _config.MAX_CONFIG_BYTES) + "\n")
        with self.assertRaises(VaultConfigFileError) as caught:
            self.token_in(path, policy="allow")
        self.assertIn("too large", str(caught.exception))

    def test_a_file_that_grows_past_the_limit_during_the_read_is_refused(self):
        # The size check must happen while reading too, not only on the stat: a
        # file can grow between the two.
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        reported = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_size=0,
                             st_uid=os.geteuid())
        with mock.patch("os.fstat", return_value=reported), \
                mock.patch("os.read",
                           side_effect=[b"#" * (_config.MAX_CONFIG_BYTES + 1)]):
            with self.assertRaises(VaultConfigFileError) as caught:
                self.token_in(path)
        self.assertIn("too large", str(caught.exception))

    def test_a_non_utf8_file_is_refused(self):
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-bytes-")
        path = os.path.join(directory, "config")
        with open(path, "wb") as handle:
            handle.write(b"ECMWF_VAULT_TOKEN=\xff\xfe\n")
        os.chmod(path, 0o600)
        with self.assertRaises(VaultConfigFileError) as caught:
            self.token_in(path)
        self.assertIn("UTF-8", str(caught.exception))

    def test_modes_without_group_or_other_access_are_accepted(self):
        # The rule is "not reachable by group or other", the same one OpenSSH
        # applies to a private key: refusing the strictly safer 0400 in the name of
        # a literal 0600 would push a careful user to loosen their file.
        for mode in (0o600, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN),
                                  mode=mode)
                self.assertEqual(self.token_in(path), FILE_TOKEN)

    # -- and the directory holding it, to the same rule ---------------------

    def directory(self, mode):
        """A config directory with an explicit mode, and the file in it."""
        directory = tempfile.mkdtemp(prefix="ecmwf-vault-dir-mode-")
        self.addCleanup(shutil.rmtree, directory, True)
        # Registered after the rmtree, so it runs first: a directory without write
        # permission cannot have its contents removed.
        self.addCleanup(os.chmod, directory, 0o700)
        path = os.path.join(directory, "config")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        os.chmod(path, 0o600)
        # Last, so that a mode without owner-write still has the file to hold.
        os.chmod(directory, mode)
        return directory, path

    def test_a_private_directory_is_read(self):
        for mode in (0o700, 0o500, 0o300):
            with self.subTest(mode=oct(mode)):
                _, path = self.directory(mode)
                self.assertEqual(self.token_in(path), FILE_TOKEN)

    def test_a_directory_reachable_by_another_user_is_refused(self):
        # The file is 0600, so only the directory is wrong: another user could list
        # it, replace the file, or add one beside it.
        for mode in (0o755, 0o770, 0o750, 0o705):
            with self.subTest(mode=oct(mode)):
                _, path = self.directory(mode)
                with self.assertRaises(VaultConfigFileError) as caught:
                    self.token_in(path)
                self.assertIn("directory", str(caught.exception))
                self.assertIn("700", str(caught.exception))
                self.assertNotIn(FILE_TOKEN, str(caught.exception))

    def test_a_reachable_directory_is_accepted_by_either_relaxed_policy(self):
        _, path = self.directory(0o755)
        for policy in ("warn", "allow"):
            with self.subTest(policy=policy):
                _policy._warned.clear()      # warn_once is once per process
                with mock.patch("sys.stderr") as stderr:
                    self.assertEqual(self.token_in(path, policy=policy), FILE_TOKEN)
                written = "".join(str(call) for call in stderr.write.call_args_list)
                self.assertIn("directory", written)
                self.assertIn("700", written)
                self.assertIn(policy, written)

    def test_a_directory_owned_by_another_user_is_refused(self):
        # Checked directly: mocking geteuid would trip the file's ownership check
        # first, so the directory's own branch is exercised on its own here.
        directory, path = self.directory(0o700)
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(VaultConfigFileError) as caught:
                _config.check_directory_permissions(path, _config.POLICY_REFUSE)
        self.assertIn("directory", str(caught.exception))
        self.assertIn("owned", str(caught.exception))
        self.assertNotIn(directory, str(caught.exception))

    def test_a_directory_owned_by_another_user_can_be_allowed_explicitly(self):
        _, path = self.directory(0o700)
        _policy._warned.clear()
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with mock.patch("sys.stderr") as stderr:
                _config.check_directory_permissions(path, _config.POLICY_ALLOW)
        written = "".join(str(call) for call in stderr.write.call_args_list)
        self.assertIn("owned", written)

    def test_a_directory_that_disappears_is_not_itself_an_error(self):
        # A race between opening the file and looking at its directory. The file
        # was openable, so the read is judged on the file's own merits.
        _, path = self.directory(0o700)
        with mock.patch.object(os, "stat", side_effect=FileNotFoundError):
            self.assertEqual(self.token_in(path), FILE_TOKEN)

    def test_a_symlinked_directory_is_judged_where_the_file_really_is(self):
        # A permissive-looking path to a directory that is in fact private: the
        # mode that matters is the real one, and it is where an attacker would
        # have to reach.
        private, _ = self.directory(0o700)
        exposed, _ = self.directory(0o700)
        link = os.path.join(exposed, "link")
        os.symlink(private, link)
        os.chmod(exposed, 0o755)
        self.assertEqual(self.token_in(os.path.join(link, "config")), FILE_TOKEN)

    def test_a_private_path_to_an_exposed_directory_is_still_refused(self):
        exposed, _ = self.directory(0o755)
        private, _ = self.directory(0o700)
        link = os.path.join(private, "link")
        os.symlink(exposed, link)
        with self.assertRaises(VaultConfigFileError) as caught:
            self.token_in(os.path.join(link, "config"))
        self.assertIn("directory", str(caught.exception))

    def test_a_file_that_cannot_be_read_is_a_fixed_error(self):
        path = self.write("%s=%s\n" % (_config.TOKEN_KEY, FILE_TOKEN))
        with mock.patch("os.open", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(VaultConfigFileError) as caught:
                self.token_in(path)
        self.assertIn("could not be read", str(caught.exception))
        self.assertNotIn(path, str(caught.exception))

    def test_a_file_without_a_token_entry_reports_a_missing_token(self):
        path = self.write("# nothing here\n")
        with self.assertRaises(VaultTokenMissingError):
            self.token_in(path)

    def test_a_file_with_a_blank_token_reports_a_missing_token(self):
        path = self.write("%s=   \n" % _config.TOKEN_KEY)
        with self.assertRaises(VaultTokenMissingError):
            self.token_in(path)

    def test_a_file_token_must_still_be_refused_if_not_header_safe(self):
        # A newline cannot even be represented in this format (it splits the
        # line), so the refusal below is a config error rather than a token
        # error; either way the value is never used.
        for token in ("bad token", "tok\u00e9n", "bad\ntoken", "sp ace"):
            with self.subTest(token=token):
                path = self.write("%s=%s\n" % (_config.TOKEN_KEY, token))
                with self.assertRaises((VaultTokenInvalidError,
                                        VaultConfigFileError)):
                    self.token_in(path)


if __name__ == "__main__":
    unittest.main()
