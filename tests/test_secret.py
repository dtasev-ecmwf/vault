"""The opaque wrapper: the accident this package refuses to be part of.

``value()`` returns a :class:`Secret`, never a ``str``, so every string-shaped
route to disk — file writes, logging, f-strings, JSON, environment variables,
child process arguments — is refused or masked instead of quietly carrying the
plaintext.
"""
from __future__ import annotations

import copy
import json
import os
import pickle
import subprocess
import sys
import tempfile
import unittest

from ecmwf_vault import Secret, VaultError

MASK = "<Secret>"
VALUE = "synthetic-value"


class SecretTests(unittest.TestCase):
    def test_the_value_is_available_only_by_asking(self):
        secret = Secret(VALUE)
        self.assertEqual(secret.reveal(), VALUE)
        with secret.revealed() as value:
            self.assertEqual(value, VALUE)

    def test_nothing_renders_the_value(self):
        secret = Secret(VALUE)
        for render in (str(secret), repr(secret), "%s" % (secret,),
                       "{}".format(secret), f"{secret}", "{:>20}".format(secret),
                       "%r" % (secret,)):
            self.assertEqual(render, MASK)
            self.assertNotIn(VALUE, render)

    def test_a_collection_of_secrets_also_renders_masked(self):
        rendered = repr({"password": Secret(VALUE), "user": Secret("cems")})
        self.assertNotIn(VALUE, rendered)
        self.assertIn(MASK, rendered)

    def test_it_is_not_a_string(self):
        secret = Secret(VALUE)
        self.assertNotIsInstance(secret, (str, bytes, bytearray))

    def test_the_routes_a_secret_normally_reaches_disk_are_refused(self):
        secret = Secret(VALUE)
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "out")
            with open(target, "w", encoding="utf-8") as handle:
                with self.assertRaises(TypeError):
                    handle.write(secret)
            with open(target, "wb") as handle:
                with self.assertRaises(TypeError):
                    handle.write(secret)
            with open(target, "a", encoding="utf-8") as handle:
                with self.assertRaises(TypeError):
                    handle.writelines([secret])
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "")

    def test_serialising_refuses(self):
        secret = Secret(VALUE)
        with self.assertRaises(TypeError):
            json.dumps(secret)
        with self.assertRaises(TypeError):
            json.dumps({"password": secret})
        with self.assertRaises(VaultError):
            pickle.dumps(secret)
        with self.assertRaises(VaultError):
            copy.copy(secret)
        with self.assertRaises(VaultError):
            copy.deepcopy(secret)

    def test_putting_it_in_the_environment_or_a_child_process_refuses(self):
        secret = Secret(VALUE)
        with self.assertRaises(TypeError):
            os.environ["ECMWF_SYNTHETIC"] = secret
        with self.assertRaises(TypeError):
            subprocess.run([sys.executable, "-c", "pass", secret])
        with self.assertRaises(TypeError):
            subprocess.run([sys.executable, "-c", "pass"],
                           env={"ECMWF_SYNTHETIC": secret})

    def test_string_operations_refuse(self):
        secret = Secret(VALUE)
        with self.assertRaises(TypeError):
            len(secret)
        with self.assertRaises(TypeError):
            "prefix" + secret
        with self.assertRaises(TypeError):
            "".join([secret])
        with self.assertRaises(TypeError):
            secret + "suffix"
        with self.assertRaises(AttributeError):
            secret.split("-")  # no string method is forwarded

    def test_encode_explains_itself(self):
        # encode() is the one string method callers reach for often enough that a
        # bare AttributeError would teach nothing.
        secret = Secret(VALUE)
        with self.assertRaises(VaultError) as caught:
            secret.encode()
        self.assertIn("reveal()", str(caught.exception))
        self.assertNotIn(VALUE, str(caught.exception))

    def test_comparison_is_by_value_without_rendering(self):
        secret = Secret(VALUE)
        self.assertTrue(secret == VALUE)
        self.assertFalse(secret == "other")
        self.assertTrue(secret != "other")
        self.assertTrue(Secret(VALUE) == Secret(VALUE))
        self.assertFalse(Secret(VALUE) == Secret("other"))
        self.assertNotIn(VALUE, repr(secret))

    def test_it_is_hashable_like_the_value_it_wraps(self):
        import hashlib
        self.assertEqual(hash(Secret(VALUE)), hash(VALUE))
        self.assertEqual({Secret("a"), Secret("a")}, {Secret("a")})
        self.assertEqual(
            hashlib.sha256(Secret(VALUE).reveal().encode()).hexdigest(),
            hashlib.sha256(VALUE.encode()).hexdigest())

    def test_truthiness_follows_the_value(self):
        self.assertTrue(bool(Secret(VALUE)))
        self.assertFalse(bool(Secret("")))
        self.assertFalse(bool(Secret(None)))
        self.assertTrue(bool(Secret(7)))

    def test_any_json_payload_is_wrapped_and_masked(self):
        for payload in (VALUE, 7, 0, True, None, [1, 2], {"key": VALUE}):
            with self.subTest(payload=payload):
                secret = Secret(payload)
                self.assertEqual(secret.reveal(), payload)
                self.assertEqual(repr(secret), MASK)
                self.assertNotIn(VALUE, str(secret) + repr(secret))


if __name__ == "__main__":
    unittest.main()
