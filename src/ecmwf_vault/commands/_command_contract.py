# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The handful of decisions the installed commands must make identically.

Each command is otherwise its own program: different arguments, a different secret, and
something different done with it. What they share is only the shape of being a command —
where this command's arguments stop and the child's begin, what the child's environment must
never contain, how a child that will not start is reported, and how a refusal becomes an
exit status instead of a traceback.

This is not a layer between the commands and the library: :mod:`ecmwf_vault` imports nothing
from here, and anything only one command needs stays in that command's module.
"""
from __future__ import annotations

import os
import subprocess
import sys

EXIT_COMMAND_FAILED = 2
EXIT_CHILD_NOT_FOUND = 127
TOKEN_VARIABLE = "ECMWF_VAULT_TOKEN"


def split_at_separator(argv):
    """Split this command's arguments from the child's at the first ``--``, if there is one."""
    if "--" in argv:
        cut = argv.index("--")
        return argv[:cut], argv[cut + 1:]
    return argv, None


def environment_without_token():
    """This process's environment, minus the Vault token.

    Neither command's child needs the token, and a child inherits whatever it is handed —
    so neither hands it on. (One of them adds more to this; that is its own business.)
    """
    environment = dict(os.environ)
    environment.pop(TOKEN_VARIABLE, None)
    return environment


def report_own_error(message_prefix, message) -> None:
    """Report a command's own failure, prefixed so it can be told from a child's.

    The prefix is the discriminator a caller greps for: both commands pass a child's exit
    status through unchanged, including the ``2`` that also means "this command failed".
    """
    print("%s %s" % (message_prefix, message), file=sys.stderr)


def field_names_text(fields) -> str:
    """The field names, for an error message that has to list them."""
    return ", ".join(sorted(fields)) or "none"


def run_child(command, environment, *, message_prefix, descriptor=None) -> int:
    """Run the child, returning its status or turning a launch failure into one of ours.

    ``PermissionError`` for a file that exists but is not executable, or a directory in its
    place, and ``E2BIG`` for an argument list too large for ``execve``, are as reachable as
    "no such file". Letting one through as a traceback would break the exit-status contract
    each command's docstring makes, so they are reported like any other refusal. The
    descriptor, when given, is inherited by the child and nothing else is.

    Nothing printed here can contain a secret: it is the caller's own command, and an
    ``OSError`` message carries an errno and that path. The one exception is a
    ``UnicodeEncodeError``, whose message names only the character — but whose *object* is the
    text that could not be encoded. That is why its text is never printed either.
    """
    passing = {} if descriptor is None else {"pass_fds": (descriptor,)}
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

    Both commands refuse by raising ``SystemExit`` with a *string* — a message that explains
    itself — while argparse raises it with a *number*. The string becomes this command's
    failure status, printed with the prefix; the number is passed through unchanged.
    """
    try:
        return run(sys.argv[1:])
    except SystemExit as error:
        if isinstance(error.code, str):
            report_own_error(message_prefix, error.code)
            return EXIT_COMMAND_FAILED
        return int(error.code)
