# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Path, mount and base URL validation, and request-target construction."""
from __future__ import annotations

import unittest

from ecmwf_vault import InvalidSecretPathError, VaultError
from ecmwf_vault import _paths
from ecmwf_vault._paths import (
    MAX_MOUNT,
    MAX_PATH_BYTES,
    build_cubbyhole_target,
    build_target,
    split_base_url,
    validate_mount,
    validate_path,
)

EXAMPLE = "user_applications_and_services_team/cems_web/k8s-cems-test"


class PathTests(unittest.TestCase):
    def test_the_requested_example_path_is_accepted(self):
        segments = validate_path(EXAMPLE)
        self.assertEqual(segments, ("user_applications_and_services_team",
                                    "cems_web", "k8s-cems-test"))
        self.assertEqual(
            build_target("groups", segments),
            "/v1/groups/data/" + EXAMPLE)

    def test_rejected_paths(self):
        for path in (
            "", "/leading", "trailing/", "double//slash", "..", "a/../b",
            "a/./b", "a/%2e%2e/b", "..%2fetc", "with space", "with\nnewline",
            "with\ttab", "question?mark", "hash#fragment", "unicode/\u00e9",
            "back\\slash", "plus+is/fine-but-not-in-mount?", "a" * (MAX_PATH_BYTES + 1),
        ):
            with self.assertRaises(InvalidSecretPathError, msg=repr(path)):
                validate_path(path)

    def test_paths_that_are_not_strings_are_rejected(self):
        for path in (None, 12, b"bytes", ["a"], {"a": 1}):
            with self.assertRaises(InvalidSecretPathError):
                validate_path(path)  # type: ignore[arg-type]

    def test_the_length_limit_counts_characters_not_bytes(self):
        longest = "a" * MAX_PATH_BYTES
        self.assertEqual(validate_path(longest), (longest,))
        with self.assertRaises(InvalidSecretPathError):
            validate_path("a" * (MAX_PATH_BYTES + 1))

    def test_a_non_ascii_path_is_rejected_without_an_encoding_error(self):
        for path in ("\ud800", "\u4e2d\u6587", "team/caf\u00e9",
                     "a" * 300 + "\u4e2d", "a" * 600 + "\ud800"):
            with self.subTest(path=path):
                with self.assertRaises(InvalidSecretPathError):
                    validate_path(path)

    def test_mounts(self):
        self.assertEqual(validate_mount("groups"), "groups")
        self.assertEqual(validate_mount("kv-2.v1_x+y@z"), "kv-2.v1_x+y@z")
        for mount in ("", "a/b", ".", "..", "a" * (MAX_MOUNT + 1), None, 7,
                      "with space", "pct%2f"):
            with self.assertRaises(InvalidSecretPathError, msg=repr(mount)):
                validate_mount(mount)

    def test_the_cubbyhole_target_has_no_mount_choice_and_no_data_layer(self):
        segments = validate_path(EXAMPLE)
        self.assertEqual(build_cubbyhole_target(segments), "/v1/cubbyhole/" + EXAMPLE)
        self.assertNotIn("/data/", build_cubbyhole_target(segments))

    def test_the_cubbyhole_name_is_not_treated_as_a_mount(self):
        # cubbyhole_read takes no mount, so the only way a caller reaches this engine is
        # the dedicated builder. build_target with mount="cubbyhole" is the mistake to avoid:
        # produces a path that exists on no Vault.
        self.assertEqual(_paths.CUBBYHOLE, "cubbyhole")
        self.assertNotEqual(build_target("cubbyhole", ("a",)),
                            build_cubbyhole_target(("a",)))

    def test_a_cubbyhole_path_is_validated_by_the_same_rules(self):
        for path in ("", "..", "a/../b", "with space", "a/%2e%2e/b", "\ud800"):
            with self.subTest(path=path):
                with self.assertRaises(InvalidSecretPathError):
                    validate_path(path)

    def test_permitted_punctuation_is_quoted_in_the_target(self):
        segments = validate_path("team/a+b@c.d-e_f")
        self.assertEqual(build_target("groups", segments),
                         "/v1/groups/data/team/a%2Bb%40c.d-e_f")

    def test_base_url(self):
        self.assertEqual(split_base_url("https://secrets.ecmwf.int"),
                         ("secrets.ecmwf.int", 443))
        self.assertEqual(split_base_url("https://127.0.0.1:8443"),
                         ("127.0.0.1", 8443))
        self.assertEqual(split_base_url("https://secrets.ecmwf.int/"),
                         ("secrets.ecmwf.int", 443))

    def test_rejected_base_urls(self):
        for url in ("http://secrets.ecmwf.int", "secrets.ecmwf.int",
                    "https://user:pw@secrets.ecmwf.int", "https://host/path",
                    "https://host?query=1", "https://host#frag", "",
                    "https://127.0.0.1:99999", "https://caf\u00e9.example",
                    "https://\u4e2d\u6587.example:8443", None, 5):
            with self.assertRaises(VaultError, msg=repr(url)):
                split_base_url(url)


if __name__ == "__main__":
    unittest.main()
