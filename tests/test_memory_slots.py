# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Memory slots: nicknamed sealed descriptors, and the argument rewriting that refers to them.

The unit layer here checks the rules — what a nickname may be, what a placeholder resolves to,
what a refusal says. Whether a *child* can actually open the path is a different claim and is
tested against a real spawned process in ``test_vaultenv``; nothing in this file assumes the
two are the same question.
"""
from __future__ import annotations

import os
import unittest

from ecmwf_vault import _memory
from ecmwf_vault.commands import _command_contract as contract
from ecmwf_vault.commands._memory_slots import MemorySlots, environment_file_text

TEXT = b"apiVersion: v1\nkind: Config\n"


class NicknameTests(unittest.TestCase):
    def setUp(self):
        self.slots = MemorySlots()
        self.addCleanup(self.slots.close)

    def test_a_slot_starts_empty(self):
        self.assertFalse(self.slots)
        self.assertEqual(self.slots.descriptors(), ())
        self.assertEqual(self.slots.names(), ())

    def test_adding_holds_a_sealed_memory_file(self):
        self.slots.add("kube", TEXT)
        self.assertTrue(self.slots)
        self.assertEqual(self.slots.names(), ("kube",))
        descriptor, = self.slots.descriptors()
        self.assertEqual(self.slots.path("kube").rsplit("/", 1)[-1], str(descriptor),
                         "the advertised path names the descriptor we hold")
        with open("/proc/self/fd/%d" % descriptor, "rb") as handle:
            self.assertEqual(handle.read(), TEXT)
        # Sealed: this process cannot write its own slot either, which is the point.
        with self.assertRaises(OSError):
            os.write(descriptor, b"appended")

    def test_the_path_is_relative_to_the_reader(self):
        # "/proc/self/" and not a pid: the child resolves it against its own table, so the
        # string is correct in both processes and says nothing about either.
        self.slots.add("kube", TEXT)
        self.assertEqual(self.slots.path("kube"),
                         "/proc/self/fd/%d" % self.slots.descriptors()[0])
        self.assertNotIn(str(os.getpid()), self.slots.path("kube"))

    def test_the_kernel_label_is_the_package_constant_not_the_nickname(self):
        # Deliberate: a field name or nickname chosen by someone else must not land in text an
        # operator reads while debugging.
        self.slots.add("kube", TEXT)
        descriptor = self.slots.descriptors()[0]
        label = os.readlink("/proc/self/fd/%d" % descriptor)
        self.assertIn(_memory.MEMFD_NAME, label)
        self.assertNotIn("kube", label)

    def test_a_nickname_must_be_an_identifier(self):
        for bad in ("", "2bad", "with space", "dash-name", "a/b", "{braced}"):
            with self.subTest(nickname=bad):
                with self.assertRaises(SystemExit) as caught:
                    self.slots.add(bad, TEXT)
                self.assertIsInstance(caught.exception.code, str)
                self.assertIn(repr(bad), str(caught.exception.code))

    def test_valid_nicknames_are_accepted(self):
        for good in ("kube", "_k", "K8S", "kubeconfig2", "a_b_c"):
            with self.subTest(nickname=good):
                slots = MemorySlots()
                self.addCleanup(slots.close)
                slots.add(good, TEXT)
                self.assertEqual(slots.names(), (good,))

    def test_two_slots_cannot_share_a_nickname(self):
        # Ambiguity resolved by refusing: silently replacing the first would hand the child
        # whichever of the two secrets happened to be added last.
        self.slots.add("kube", TEXT)
        with self.assertRaises(SystemExit) as caught:
            self.slots.add("kube", b"other")
        self.assertIn("two memory files named 'kube'", str(caught.exception.code))
        self.assertEqual(self.slots.names(), ("kube",), "and the first slot survives")

    def test_the_context_manager_closes_on_exit(self):
        with MemorySlots() as slots:
            slots.add("kube", TEXT)
            descriptor = slots.descriptors()[0]
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_close_releases_every_slot(self):
        self.slots.add("one", TEXT)
        self.slots.add("two", TEXT)
        descriptors = self.slots.descriptors()
        self.slots.close()
        self.assertFalse(self.slots)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_closing_twice_is_harmless(self):
        self.slots.add("kube", TEXT)
        self.slots.close()
        self.slots.close()


class SubstituteTests(unittest.TestCase):
    def setUp(self):
        self.slots = MemorySlots()
        self.addCleanup(self.slots.close)

    def test_with_no_slots_the_command_passes_through_unchanged(self):
        # This is the pass-through promise, and it holds by default rather than by exception:
        # a command that never asked for a descriptor gets its argv byte for byte.
        command = ["tool", "{anything}", "--x={other}", "{}", "{"]
        self.assertEqual(self.slots.substitute(command), command)

    def test_a_whole_argument_becomes_the_descriptor_path(self):
        self.slots.add("kube", TEXT)
        self.assertEqual(self.slots.substitute(["cat", "{kube}"]),
                         ["cat", self.slots.path("kube")])

    def test_a_placeholder_embedded_in_an_argument_is_replaced_in_place(self):
        self.slots.add("kube", TEXT)
        self.assertEqual(self.slots.substitute(["kubectl", "--kubeconfig={kube}", "get"]),
                         ["kubectl", "--kubeconfig=" + self.slots.path("kube"), "get"])

    def test_several_slots_are_each_replaced(self):
        self.slots.add("kube", TEXT)
        self.slots.add("cert", b"pem")
        substituted = self.slots.substitute(["tool", "{kube}", "{cert}", "{kube}"])
        self.assertEqual(substituted[1:3],
                         [self.slots.path("kube"), self.slots.path("cert")])
        self.assertEqual(substituted[3], self.slots.path("kube"))

    def test_an_unknown_placeholder_is_refused_once_slots_exist(self):
        # Without this, a typo reaches the child as a literal "{aples}" and fails as
        # "no such file or directory", which reads as a broken descriptor rather than a typo.
        self.slots.add("kube", TEXT)
        with self.assertRaises(SystemExit) as caught:
            self.slots.substitute(["cat", "{aples}"])
        message = str(caught.exception.code)
        self.assertIn("{aples} is not a memory file", message)
        self.assertIn("{kube}", message, "and the refusal says what is available")

    def test_the_refusal_never_shares_a_path_with_a_subpath(self):
        # "kubeconfig" starts with "kube" but is a different name, and substring matching here
        # would either resolve or refuse it wrongly.
        self.slots.add("kube", TEXT)
        with self.assertRaises(SystemExit):
            self.slots.substitute(["cat", "{kubeconfig}"])

    def test_ordinary_braces_in_a_command_are_left_alone(self):
        # Only identifier-shaped braces are placeholders. JSON, awk and brace expansion syntax
        # must survive, or the flag would make this command unusable for them.
        self.slots.add("kube", TEXT)
        for argument in ('{"json": 1}', "{a,b}", "{}", "${shell}", "{{nested}}", "{9}"):
            with self.subTest(argument=argument):
                self.assertEqual(self.slots.substitute(["tool", argument]),
                                 ["tool", argument])

    def test_a_shell_variable_reference_survives_a_matching_nickname(self):
        # The reason for the lookbehind: {OUT} inside ${OUT} is shell syntax for a variable the
        # *caller* owns, and it is indistinguishable from our placeholder by shape alone. A
        # nickname that happens to match must not rewrite it, or the flag would make ordinary
        # shell strings impossible to pass.
        self.slots.add("out", TEXT)
        command = ["sh", "-c", 'cp "{out}" "${out}"']
        substituted = self.slots.substitute(command)
        self.assertIn(self.slots.path("out"), substituted[2], "our token was replaced")
        self.assertIn("${out}", substituted[2], "and the shell's was not")
        self.assertNotIn("${" + self.slots.path("out") + "}", substituted[2])

    def test_an_unknown_placeholder_embedded_in_an_argument_passes_through(self):
        # Accepted asymmetry, stated: an unknown *whole* argument is refused as a likely typo,
        # but an unknown embedded one cannot be told apart from shell syntax, so it is left
        # exactly as typed. A typo inside --flag={aples} therefore reaches the child.
        self.slots.add("kube", TEXT)
        command = ["tool", "--x={aples}"]
        self.assertEqual(self.slots.substitute(command), ["tool", "--x={aples}"])

    def test_a_known_nickname_is_replaced_wherever_it_is_not_a_shell_reference(self):
        self.slots.add("kube", TEXT)
        substituted = self.slots.substitute(
            ["t", "pre{kube}post", "{kube}", "/{kube}/"])
        self.assertEqual(substituted[1:],
                         ["pre" + self.slots.path("kube") + "post",
                          self.slots.path("kube"), "/" + self.slots.path("kube") + "/"])

    def test_the_original_list_is_not_modified(self):
        self.slots.add("kube", TEXT)
        command = ["cat", "{kube}"]
        self.slots.substitute(command)
        self.assertEqual(command, ["cat", "{kube}"])


class EnvironmentFileTests(unittest.TestCase):
    def test_the_format_is_one_assignment_per_line(self):
        text = environment_file_text({"B": "two", "A": "one"})
        self.assertEqual(text, b"A=one\nB=two\n")

    def test_the_order_is_stable(self):
        # Sorted, so two runs on the same secret produce the same bytes: a file that is only
        # ever read can still be compared, and a diff cannot leak a value by ordering it.
        first = environment_file_text({"Z": "1", "A": "2", "M": "3"})
        second = environment_file_text({"A": "2", "M": "3", "Z": "1"})
        self.assertEqual(first, second)

    def test_an_empty_selection_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            environment_file_text({})
        self.assertIn("no variables", str(caught.exception.code))

    def test_a_value_spanning_lines_is_refused_rather_than_quoted(self):
        # Every environment-file dialect quotes slightly differently, and a wrong guess yields
        # a value that looks right and is not.
        for value in ("line\nbreak", "carriage\rreturn", "a\r\nb"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(SystemExit) as caught:
                    environment_file_text({"KEY": value})
                self.assertIn("KEY", str(caught.exception.code))
                self.assertIn("--mem-field", str(caught.exception.code))

    def test_a_multi_line_value_names_the_field_not_the_value(self):
        with self.assertRaises(SystemExit) as caught:
            environment_file_text({"SECRET": "first\nsecond"})
        message = str(caught.exception.code)
        self.assertIn("SECRET", message)
        self.assertNotIn("first", message)
        self.assertNotIn("second", message)

    def test_other_characters_pass_through_unquoted(self):
        # Spaces, equals signs and quotes are legal in a value; the format's own rules about
        # them are the reader's business, and we do not invent an escaping scheme of our own.
        self.assertEqual(environment_file_text({"K": 'a b="c"'}), b'K=a b="c"\n')


class RoundTripsLikeTheEnvironmentTests(unittest.TestCase):
    """Text the environment route can carry, the descriptor route must carry identically.

    A lone surrogate in the U+DC80-U+DCFF range is how ``os.fsencode`` round-trips a byte that
    was never valid UTF-8. ``str.encode("utf-8")`` refuses exactly those values with a
    ``UnicodeEncodeError`` whose *object* is the text — so getting this wrong does not merely
    fail, it raises an exception that ``repr()`` renders with the secret in it, on a value the
    rest of this package would have exported without complaint.
    """

    SURROGATE = "hunter\udc802"

    def test_the_serialised_file_encodes_what_os_fsencode_would_export(self):
        self.assertEqual(environment_file_text({"K": self.SURROGATE}),
                         b"K=hunter\x802\n")
        self.assertEqual(environment_file_text({"K": self.SURROGATE}),
                         b"K=" + os.fsencode(self.SURROGATE) + b"\n")

    def test_an_ordinary_value_is_unaffected_by_the_encoding_choice(self):
        # Guards against the fix quietly changing normal bytes: for valid text, fsencode and
        # utf-8 agree, and this says so rather than assuming it.
        for value in ("plain", "h\u00e9llo", "\u4e2d\u6587", "tab\there"):
            with self.subTest(value=repr(value)):
                self.assertEqual(environment_file_text({"K": value}),
                                 ("K=" + value + "\n").encode("utf-8"))

    def test_no_exception_is_raised_for_a_value_the_environment_accepts(self):
        # The failure this replaces: an uncaught UnicodeEncodeError escaping the command.
        try:
            environment_file_text({"K": self.SURROGATE})
        except UnicodeEncodeError as error:
            self.fail("UnicodeEncodeError escaped, and repr() held the secret: %r"
                      % (error,))


class PlaceholderSharedDefinitionTests(unittest.TestCase):
    def test_one_definition_backs_both_uses(self):
        # A nickname valid for --mem-file but not for {nickname} — or the reverse — would be a
        # bug no test notices until someone typed it, so both come from one body string. The
        # vaultenv variable-name check is the third user of the same rule.
        self.assertEqual(contract.PLACEHOLDER.pattern,
                         "\\{(" + contract.IDENTIFIER_BODY + ")\\}")
        self.assertEqual(contract.IDENTIFIER.pattern, contract.IDENTIFIER_BODY + "\\Z")
        from ecmwf_vault.commands import vaultenv
        self.assertIs(vaultenv.NAME_PATTERN, contract.IDENTIFIER)

    def test_a_nickname_accepted_by_add_is_addressable_by_placeholder(self):
        # The round trip the two definitions must agree on, stated as behaviour rather than as
        # a comparison of patterns.
        for name in ("kube", "_a1", "K8S", "a_b_c"):
            with self.subTest(name=name):
                slots = MemorySlots()
                self.addCleanup(slots.close)
                slots.add(name, TEXT)
                self.assertEqual(slots.substitute(["{", "{%s}" % name]),
                                 ["{", slots.path(name)])

    def test_the_placeholder_matches_exactly_what_an_identifier_is(self):
        for token, matches in (("{kube}", True), ("{_a1}", True), ("{2bad}", False),
                               ("{a b}", False), ("{a-b}", False), ("{}", False)):
            with self.subTest(token=token):
                self.assertEqual(bool(contract.PLACEHOLDER.fullmatch(token)), matches)


if __name__ == "__main__":
    unittest.main()
