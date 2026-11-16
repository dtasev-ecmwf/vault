# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Rules the test suite must keep obeying, checked against its own source.

**Kept — assertions that print an environment.** An assertion handed a whole environment
renders every value in its failure text, which is every credential the runner happens to
export, and reviewers have watched it happen. This is decidable from the source alone: it is a
property of how an assertion is *written*, not of anything in force while it runs.

**Kept — the fixture isolates and restores.** Checked by running the fixture and looking at
the environment afterwards, including on a failure inside it.

**Dropped twice — which tests may mutate ``os.environ``.** Two attempts were written, reviewed
and removed. The reasons are kept here so a third is not attempted without them. The first
treated any guard inside a ``setUp`` as protecting the methods that follow, but a ``with
mock.patch.dict(...)`` in ``setUp`` has already exited by the time a test runs, so it excused
precisely the mutations it existed to catch. The second narrowed itself to removals and
required the enter-without-exit shape, and was still wrong twice: it accepted any ``start()``
as establishing a guard without checking that a teardown was registered for the same object,
and it credited a base class's guard to a subclass that overrides ``setUp`` without calling it.

Both had the same root. Whether a guard is in force at a given statement depends on what has
been entered and not yet exited — runtime information the syntax does not hold — so every
repair moved the rule closer to being an interpreter. The gap is closed two ways instead: the
fixture's own restoration is tested below, and the whole suite is run with the invoking
environment snapshotted and compared. That last check is in the README as a command to run,
because it is the one that caught the real defects here; what is *not* mechanically checked is
a test that mutates ``os.environ`` outside any fixture, which is a code-review matter. Said
plainly so nobody reads this file as a guarantee it does not give.
"""
from __future__ import annotations

import ast
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import _fakes

TESTS = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
FAKES = TESTS / "_fakes.py"

# Assertions that render their arguments into the failure text when they do not hold.
RENDERING_ASSERTIONS = frozenset({
    "assertIn", "assertNotIn", "assertEqual", "assertNotEqual", "assertListEqual",
    "assertDictEqual", "assertSetEqual", "assertCountEqual", "assertSame", "assertIsNot",
    "assertLess", "assertGreater",
})

BARE_ENVIRONMENT_NAMES = frozenset({"env", "environment", "environ", "os.environ"})


def is_environment_mapping(expression: str) -> bool:
    """Whether this rendered argument *is* an entire environment.

    Copy forms count as much as the original: ``os.environ.copy()`` and ``dict(os.environ)``
    produce the same dictionary and render the same way. The alias case is handled per scope,
    below.
    """
    stripped = expression.strip()
    if stripped in BARE_ENVIRONMENT_NAMES:
        return True
    if stripped.endswith(".environ") or ".environ.copy(" in stripped:
        return True
    if stripped.startswith("dict(os.environ"):
        return True
    return (stripped.endswith(".env") or stripped.endswith('["env"]')
            or stripped.endswith("['env']"))


def parent_map(tree):
    """Child -> parent for every node, so containment can be asked of one node."""
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _without_nested_scopes(node):
    """Yield the nodes of one scope, stopping at a nested function, class or lambda."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                  ast.Lambda)):
                continue
            stack.append(child)


def aliases_by_scope(tree):
    """Scope node id -> names *that scope* binds to a whole environment.

    Per scope rather than module-wide: ``snapshot = os.environ.copy()`` in one test must not
    make an unrelated local also called ``snapshot`` somewhere else look like an offender. A
    rule that invents failures in code that is fine gets switched off.
    """
    found = {}
    for scope in ast.walk(tree):
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                  ast.Module)):
            continue
        names = set()
        for node in _without_nested_scopes(scope):
            if isinstance(node, ast.Assign) \
                    and is_environment_mapping(ast.unparse(node.value)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        found[id(scope)] = names
    return found


def visible_aliases(node, parents, by_scope):
    """Aliases in force where this node is written: its scope and those enclosing it."""
    visible = set()
    current = node
    while current is not None:
        visible |= by_scope.get(id(current), set())
        current = parents.get(current)
    return visible


def rendered_environment_assertions(source: str, filename: str = "<source>"):
    """Assertions in ``source`` that would print a whole environment if they failed."""
    tree = ast.parse(source)
    parents = parent_map(tree)
    by_scope = aliases_by_scope(tree)
    offenders = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in RENDERING_ASSERTIONS):
            continue
        for position, argument in enumerate(node.args):
            expression = ast.unparse(argument)
            if is_environment_mapping(expression) \
                    or expression in visible_aliases(argument, parents, by_scope):
                offenders.append((filename, node.lineno, node.func.attr, position, expression))
    return offenders


def assignment_keys(source: str, function: str):
    """Names assigned as keys in any dict literal inside a function."""
    tree = ast.parse(source)
    target = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef) and node.name == function)
    keys = set()
    for node in ast.walk(target):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.add(key.value)
    return keys


def module_constant(source: str, name: str):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == name:
            return {element.value for element in node.value.elts}
    raise AssertionError("%s is not a tuple or set constant" % name)


class ScannerIsSoundTests(unittest.TestCase):
    """A source-scanning rule is worthless if it can silently match nothing."""

    def test_it_finds_membership_assertions_on_an_environment(self):
        bad = ("import os\n"
               "class T:\n"
               "    def m(self):\n"
               '        self.assertNotIn("SECRET", os.environ)\n'
               '        self.assertIn("HOME", call.kwargs["env"])\n'
               '        self.assertNotIn("X", environment)\n')
        found = rendered_environment_assertions(bad, "bad.py")
        self.assertEqual({line for _, line, _, _, _ in found}, {4, 5, 6}, found)

    def test_it_finds_equality_assertions_on_an_environment(self):
        bad = ("import os\n"
               "class T:\n"
               "    def m(self):\n"
               "        self.assertEqual(os.environ, {})\n"
               "        self.assertNotEqual(env, self.expected)\n"
               "        self.assertDictEqual(call.kwargs['env'], {})\n")
        found = rendered_environment_assertions(bad, "bad.py")
        self.assertEqual({line for _, line, _, _, _ in found}, {4, 5, 6}, found)

    def test_it_finds_copied_environments(self):
        bad = ("import os\n"
               "class T:\n"
               "    def m(self):\n"
               "        self.assertEqual(os.environ.copy(), {})\n"
               "        self.assertNotEqual(dict(os.environ), self.expected)\n")
        found = rendered_environment_assertions(bad, "bad.py")
        self.assertEqual({line for _, line, _, _, _ in found}, {4, 5}, found)

    def test_it_finds_an_environment_held_in_a_variable(self):
        bad = ("import os\n"
               "class T:\n"
               "    def m(self):\n"
               "        snapshot = os.environ.copy()\n"
               "        self.assertEqual(snapshot, {})\n")
        found = rendered_environment_assertions(bad, "bad.py")
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0][4], "snapshot")

    def test_it_checks_either_argument(self):
        bad = ("import os\n"
               "class T:\n"
               "    def m(self):\n"
               "        self.assertEqual(self.expected, os.environ)\n")
        found = rendered_environment_assertions(bad, "bad.py")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][3], 1, "the environment was the second argument")

    def test_an_alias_does_not_leak_between_scopes(self):
        # The false positive this replaced: an alias in one test must not condemn an unrelated
        # local of the same name in another.
        fine = ("import os\n"
                "class T:\n"
                "    def first(self):\n"
                "        snapshot = os.environ.copy()\n"
                "        self.assertEqual(snapshot['HOME'], '/x')\n"
                "    def second(self):\n"
                "        snapshot = self.fake.fields\n"
                "        self.assertEqual(snapshot, {})\n")
        offenders = rendered_environment_assertions(fine, "fine.py")
        self.assertEqual(offenders, [], "second's `snapshot` is not an environment")

    def test_it_allows_one_value_out_of_an_environment(self):
        fine = ("class T:\n"
                "    def m(self):\n"
                '        self.assertEqual(env["HOME"], "/known/home")\n'
                '        self.assertEqual(os.environ.get("PATH"), "/bin")\n'
                '        self.assertIn("a", self.fake.fields)\n'
                '        self.assertNotIn("PATH", str(error))\n')
        self.assertEqual(rendered_environment_assertions(fine, "fine.py"), [])


class SuiteComplianceTests(unittest.TestCase):
    def test_the_suite_has_no_assertion_that_prints_an_environment(self):
        offenders = []
        for path in sorted(TESTS.glob("test_*.py")):
            offenders.extend(rendered_environment_assertions(path.read_text(), path.name))
        self.assertEqual(
            offenders, [],
            "an assertion handed a whole environment prints every credential the runner "
            "exports when it fails; name the key instead: assertFalse(name in env, msg)")

    def test_no_message_that_protects_against_dumping_is_a_format_string(self):
        # unittest builds the text as ``msg % standardMsg``, so a message containing a bare %
        # spec can pull the standard message — and the container inside it — back in.
        offenders = []
        for path in sorted(TESTS.glob("test_*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr in ("assertFalse", "assertTrue") \
                        and len(node.args) >= 2:
                    message = node.args[1]
                    if isinstance(message, ast.Constant) and isinstance(message.value, str) \
                            and "%" in message.value:
                        offenders.append((path.name, node.lineno))
        self.assertEqual(offenders, [], "a % in an assertion message can re-include the value")


class FixtureIsolationTests(unittest.TestCase):
    """The fixture must isolate, and must give back exactly what it borrowed."""

    # The outer guard is spelled mock.patch.dict(os.environ, ...) in every test below, and not
    # wrapped in a private helper: the rule about removals can only see a guard written in that
    # form, and a file that tests restoration should be the first to state it plainly.

    def test_the_fixture_restores_a_pre_existing_value(self):
        # The property the dropped scanner only appeared to check, tested on the fixture rather
        # than on mock.patch.dict directly: the fixture is what every other test leans on, and
        # one that stopped restoring would otherwise pass its own suite unnoticed.
        name = "VE_FIXTURE_PROBE"
        with mock.patch.dict(os.environ, {name: "original"}, clear=False):
            with _fakes.vault_environment():
                self.assertFalse(name in os.environ, "isolated: not inherited")
                os.environ[name] = "written by the test"
            self.assertEqual(os.environ[name], "original",
                             "the runner's value came back, not the test's")

    def test_a_fixture_restores_absence_and_not_only_values(self):
        # Restoration has two directions, and a check written only on values misses this one:
        # a name that was absent when the fixture started must be absent when it ends, even
        # though the test wrote it inside. The outer patch.dict is not part of the claim — it
        # is there so the pop below cannot destroy anything the runner had. Note that
        # patch.dict removes keys it introduced when it exits, so it could not have put a
        # "runner-had-it" value back here, and an earlier version of this test assumed it
        # would; the assertion is about the fixture alone.
        name = "VE_FIXTURE_WAS_ABSENT"
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(name, None)
            with _fakes.vault_environment():
                os.environ[name] = "written inside"
            self.assertFalse(name in os.environ,
                             "the fixture gave back the absence it was handed")

    def test_the_fixture_takes_away_what_a_test_added(self):
        name = "VE_FIXTURE_ADDED"
        with mock.patch.dict(os.environ, {name: "runner-had-it"}, clear=False):
            os.environ.pop(name)
            with _fakes.vault_environment():
                os.environ[name] = "temp"
                self.assertTrue(name in os.environ, "visible inside the fixture")
            self.assertFalse(name in os.environ, "a name introduced inside must not escape")

    def test_the_fixture_restores_values_it_overrides(self):
        # Overrides supply a token file or address; they must not outlive the test. This one is
        # ECMWF_VAULT_ADDR, a name a real runner genuinely has set, so overwriting it in place
        # would leak a fake address into every later test.
        name = "ECMWF_VAULT_ADDR"
        with mock.patch.dict(os.environ, {name: "https://the-runner-has-this"},
                             clear=False):
            with _fakes.vault_environment(**{name: "https://the-fixture-set"}):
                self.assertEqual(os.environ[name], "https://the-fixture-set")
            self.assertEqual(os.environ[name], "https://the-runner-has-this")

    def test_the_fixture_restores_after_a_failure_inside_it(self):
        # The unhappy path matters more than the happy one: a failing test is exactly when the
        # rest of the run begins inheriting strange state.
        name = "VE_FIXTURE_AFTER_ERROR"
        with mock.patch.dict(os.environ, {name: "original"}, clear=False):
            with self.assertRaises(RuntimeError):
                with _fakes.vault_environment():
                    os.environ[name] = "changed"
                    raise RuntimeError("mid-test failure")
            self.assertEqual(os.environ[name], "original")

    def test_the_fixture_inherits_nothing_but_path_and_home(self):
        # Behaviour, not source: with hostile names exported, an isolated test must not see
        # them. This is what every denylist missed — a field name is whatever the next test
        # invents, so PGOPTIONS was in no list anywhere.
        injected = {name: "injected-value" for name in _fakes.ISOLATION_PROBE_NAMES}
        with mock.patch.dict(os.environ, injected, clear=False):
            with _fakes.vault_environment():
                extra = sorted(set(os.environ) - {"PATH", "HOME"})
        self.assertEqual(extra, [], "the fixture starts from nothing, not from the runner")

    def test_the_fixture_still_passes_the_real_path_through(self):
        with _fakes.vault_environment():
            self.assertEqual(os.environ["PATH"], _real_path)
        self.assertNotIn(
            "PATH", assignment_keys(FAKES.read_text(), "vault_environment"),
            "PATH is inherited, never rewritten: tests run gpg and kubectl for real, and "
            "os.defpath does not include /usr/local/bin where gpg often lives")

    def test_the_base_allowlist_is_only_path_and_home(self):
        self.assertEqual(module_constant(FAKES.read_text(), "BASE_ENVIRONMENT"),
                         {"PATH", "HOME"})

    def test_an_invented_field_name_cannot_be_pre_set_by_the_runner(self):
        # The regression that started all of this.
        from ecmwf_vault import Secret
        from ecmwf_vault.commands import vaultenv as cli
        with mock.patch.dict(os.environ, {"PGOPTIONS": "host=from-the-runner"}, clear=False):
            with _fakes.vault_environment(), \
                    mock.patch.object(cli, "value", return_value={"PGOPTIONS": Secret("")}), \
                    mock.patch.object(cli.contract, "subprocess") as child:
                child.call.return_value = 0
                status = cli.run(["--secret", "p", "--", "cmd"])
        self.assertEqual(status, 0)
        self.assertEqual(child.call.call_args.kwargs["env"]["PGOPTIONS"], "")

    def test_sealing_is_independent_of_the_host_gnupg_home(self):
        # The product deliberately honours GNUPGHOME, so the fixture must not inherit it: a
        # host with an unusable one used to fail every token fixture before one assertion ran.
        bad_home = tempfile.mkdtemp(prefix="ecmwf-vault-unusable-")
        os.chmod(bad_home, 0o500)
        try:
            with mock.patch.dict(os.environ, {"GNUPGHOME": bad_home}, clear=False):
                path = _fakes.token_file("hvs.probe-token")
                self.assertTrue(os.path.exists(path))
        finally:
            os.chmod(bad_home, 0o700)
            shutil.rmtree(bad_home, ignore_errors=True)


_real_path = os.environ.get("PATH", "")

if __name__ == "__main__":
    unittest.main()
