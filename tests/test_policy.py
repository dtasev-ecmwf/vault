# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Host policy: swap refusal, the relaxed modes, and one-time hardening."""
from __future__ import annotations

import ctypes
import os
import resource
import unittest
from unittest import mock

from ecmwf_vault import SwapPolicyError, VaultError
from ecmwf_vault import _policy

NO_SWAP = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
WITH_SWAP = NO_SWAP + "/swapfile\tfile\t1024\t0\t-2\n"


def swap_file(read_data):
    return mock.patch("builtins.open", mock.mock_open(read_data=read_data))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            name: os.environ.pop(name, None)
            for name in ("ECMWF_VAULT_SWAP_POLICY", "ECMWF_VAULT_HARDEN")
        }
        _policy._hardened = False
        _policy._warned.clear()

    def tearDown(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    # -- swap detection ---------------------------------------------------

    def test_proc_swaps_with_only_its_header_means_no_swap(self):
        with swap_file(NO_SWAP):
            self.assertFalse(_policy.swap_is_active())

    def test_a_swap_area_is_detected(self):
        with swap_file(WITH_SWAP):
            self.assertTrue(_policy.swap_is_active())

    def test_unreadable_proc_swaps_fails_closed(self):
        with mock.patch("builtins.open", side_effect=OSError(2, "no such file")):
            self.assertTrue(_policy.swap_is_active())

    # -- policy resolution ------------------------------------------------

    def test_default_policy_is_refuse(self):
        self.assertEqual(_policy.resolve_policy(), _policy.SWAP_REFUSE)

    def test_policy_comes_from_the_environment(self):
        os.environ["ECMWF_VAULT_SWAP_POLICY"] = "warn"
        self.assertEqual(_policy.resolve_policy(), _policy.SWAP_WARN)

    def test_an_explicit_policy_beats_the_environment(self):
        os.environ["ECMWF_VAULT_SWAP_POLICY"] = "warn"
        self.assertEqual(_policy.resolve_policy("allow"), _policy.SWAP_ALLOW)

    def test_an_unknown_policy_is_rejected(self):
        for value in ("sometimes", "", "REFUSE"):
            with self.assertRaises(SwapPolicyError):
                _policy.resolve_policy(value)

    # -- enforcement ------------------------------------------------------

    def test_refuse_raises_when_swap_is_active(self):
        with swap_file(WITH_SWAP):
            with self.assertRaises(SwapPolicyError):
                _policy.enforce(_policy.SWAP_REFUSE, harden=False)

    def test_refuse_does_not_touch_the_process(self):
        with swap_file(WITH_SWAP), \
                mock.patch("ecmwf_vault._policy.harden_process") as harden:
            with self.assertRaises(SwapPolicyError):
                _policy.enforce(_policy.SWAP_REFUSE, harden=True)
        self.assertFalse(harden.called)

    def test_refuse_is_quiet_when_there_is_no_swap(self):
        with swap_file(NO_SWAP):
            with mock.patch("sys.stderr") as stderr:
                _policy.enforce(_policy.SWAP_REFUSE, harden=False)
        self.assertFalse(stderr.write.called)

    def test_warn_and_allow_proceed_but_warn_once(self):
        for policy in (_policy.SWAP_WARN, _policy.SWAP_ALLOW):
            _policy._warned.clear()
            with swap_file(WITH_SWAP), \
                    mock.patch("sys.stderr") as stderr:
                _policy.enforce(policy, harden=False)
                _policy.enforce(policy, harden=False)
            written = "".join(str(call) for call in stderr.write.call_args_list)
            self.assertEqual(written.count("the secret may be written to swap"), 1)

    def test_enforce_runs_hardening_only_when_it_is_enabled(self):
        with swap_file(NO_SWAP), \
                mock.patch("ecmwf_vault._policy.harden_process") as harden:
            _policy.enforce(_policy.SWAP_REFUSE, harden=True)
            _policy.enforce(_policy.SWAP_REFUSE, harden=False)
        self.assertEqual(harden.call_count, 1)

    # -- hardening --------------------------------------------------------

    def test_harden_disables_core_dumps_and_dumpability(self):
        libc = mock.MagicMock()
        libc.prctl.return_value = 0
        with mock.patch("resource.setrlimit") as setrlimit, \
                mock.patch("ctypes.CDLL", return_value=libc):
            _policy.harden_now()
        setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))
        libc.prctl.assert_called_once_with(4, 0, 0, 0, 0)

    def test_hardening_runs_once(self):
        libc = mock.MagicMock()
        libc.prctl.return_value = 0
        with mock.patch("resource.setrlimit") as setrlimit, \
                mock.patch("ctypes.CDLL", return_value=libc):
            _policy.harden_process()
            _policy.harden_process()
        setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

    def test_hardening_checks_again_after_acquiring_the_lock(self):
        class Winner:
            def __enter__(self_inner):
                _policy._hardened = True
                return self_inner

            def __exit__(self_inner, *exception):
                return False

        with mock.patch.object(_policy, "_hardening_lock", Winner()), \
                mock.patch("ecmwf_vault._policy.harden_now") as harden_now:
            _policy.harden_process()
        self.assertFalse(harden_now.called)
        self.assertTrue(_policy._hardened)

    def test_hardening_raises_when_core_dumps_cannot_be_disabled(self):
        with mock.patch("resource.setrlimit", side_effect=ValueError("nope")):
            with self.assertRaises(VaultError):
                _policy.harden_now()

    def test_hardening_raises_when_dumpability_cannot_be_disabled(self):
        libc = mock.MagicMock()
        libc.prctl.return_value = -1
        with mock.patch("resource.setrlimit"), \
                mock.patch("ctypes.CDLL", return_value=libc):
            with self.assertRaises(VaultError):
                _policy.harden_now()

    def test_harden_resolution(self):
        self.assertTrue(_policy.resolve_harden())
        self.assertTrue(_policy.resolve_harden(True))
        self.assertFalse(_policy.resolve_harden(False))
        for value in ("0", "no", "off", "false"):
            os.environ["ECMWF_VAULT_HARDEN"] = value
            self.assertFalse(_policy.resolve_harden())
        os.environ["ECMWF_VAULT_HARDEN"] = "maybe"
        with self.assertRaises(VaultError):
            _policy.resolve_harden()
        with self.assertRaises(VaultError):
            _policy.resolve_harden("yes")  # type: ignore[arg-type]

    def test_hardening_really_applies_to_this_process(self):
        libc = ctypes.CDLL(None, use_errno=True)
        _policy.harden_now()  # PR_GET_DUMPABLE is 3
        self.assertEqual(libc.prctl(3, 0, 0, 0, 0), 0)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE), (0, 0))


if __name__ == "__main__":
    unittest.main()
