# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The decisions the installed commands must make identically.

Where this command's arguments stop and the child's begin, how a launch failure becomes an
exit status rather than a traceback, how a refusal is worded, and how a diagnostic lists
field names. Nothing else is shared: each command parses its own arguments and does its own
work.

:mod:`ecmwf_vault` imports nothing from here. Anything only one command needs stays in that
command's module.
"""
from __future__ import annotations

import re
import subprocess
import sys

EXIT_COMMAND_FAILED = 2
EXIT_CHILD_NOT_FOUND = 127

# One identifier rule, used for a variable name, a memory-file nickname, and the placeholder
# that refers to one. Defined once because a nickname valid for `--mem-file` but not for the
# `{nickname}` token — or the reverse — would be a bug no test would notice until someone hit
# it.
IDENTIFIER_BODY = r"[A-Za-z_][A-Za-z0-9_]*"
IDENTIFIER = re.compile(IDENTIFIER_BODY + r"\Z")
PLACEHOLDER = re.compile(r"\{(" + IDENTIFIER_BODY + r")\}")
# The same token, but not when a ``$`` precedes it: ``${OUT}`` is a shell variable reference
# and appears in ordinary arguments, while ``{OUT}`` is ours. Without the lookbehind, a
# nickname would collide with every shell string that expands a variable of the same name.
SUBSTITUTABLE = re.compile(r"(?<!\$)" + PLACEHOLDER.pattern)


def split_at_separator(argv):
    """Split this command's arguments from the child's at the first ``--``, if there is one."""
    if "--" in argv:
        cut = argv.index("--")
        return argv[:cut], argv[cut + 1:]
    return argv, None


def report_own_error(message_prefix, message) -> None:
    """Report a command's own failure, prefixed so it can be told from a child's.

    Both commands pass a child's exit status through unchanged, including the ``2`` that also
    means "this command failed". The prefix is what tells them apart.
    """
    print("%s %s" % (message_prefix, message), file=sys.stderr)


def field_names_text(fields) -> str:
    """The field names, for an error message that has to list them."""
    return ", ".join(sorted(fields)) or "none"


def run_child(command, environment, *, message_prefix, descriptors=()) -> int:
    """Run the child, returning its status or turning a launch failure into one of ours.

    A file that exists but is not executable, a directory in its place, and an argument list
    too large for ``execve`` are as reachable as "no such file", so all three are reported the
    same way rather than escaping as a traceback. The descriptors, when given, are the only
    extra thing the child inherits: ``pass_fds`` keeps each one open in the child *under the
    same number*, which is what makes ``/proc/self/fd/<n>`` mean the same file to both.

    Nothing here prints a secret. The caller supplied the command, and an ``OSError`` carries
    an errno and that path. A ``UnicodeEncodeError`` is the exception that proves the rule: its
    message names one character, but its *object* is the text that failed to encode, so its
    text is never printed either.
    """
    passing = {} if not descriptors else {"pass_fds": tuple(descriptors)}
    try:
        return subprocess.call(command, env=environment, **passing)
    except FileNotFoundError:
        report_own_error(message_prefix, "cannot run %r: no such file" % command[0])
        return EXIT_CHILD_NOT_FOUND
    except UnicodeEncodeError:
        report_own_error(message_prefix, "cannot run %r: its environment or arguments "
                                         "cannot be encoded" % command[0])
        return EXIT_COMMAND_FAILED
    except OSError as error:
        report_own_error(message_prefix, "cannot run %r: %s" % (command[0], error))
        return EXIT_COMMAND_FAILED


def run_as_command(run, *, message_prefix) -> int:
    """What every ``main`` is: run, and turn a ``SystemExit`` into the documented status.

    A command refuses by raising ``SystemExit`` with a *string* that explains itself; argparse
    raises it with a *number*. The string becomes this command's failure status, printed with
    the prefix; the number passes through unchanged.
    """
    try:
        return run(sys.argv[1:])
    except SystemExit as error:
        if isinstance(error.code, str):
            report_own_error(message_prefix, error.code)
            return EXIT_COMMAND_FAILED
        return int(error.code)
