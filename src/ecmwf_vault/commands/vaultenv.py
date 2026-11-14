# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vaultenv`` command: run a command with environment variables read from Vault.

Installed as a console script by ``pip install ecmwf-vault`` (``pyproject.toml`` maps
``vaultenv`` to :func:`main`); this module is private, and the command is the public
artefact. Run it from a checkout with ``python -m ecmwf_vault.commands.vaultenv``.

    vaultenv --secret user_applications_and_services_team/cems_web/db -- psql

With no selection, every field of the secret becomes an environment variable of the same
name. ``--field NAME`` uses only that field, under its own name, and is the way to take one
value out of a secret whose other fields are not valid variable names (Vault field names may
contain ``-`` or ``.``); ``--set NAME=FIELD`` uses only the fields you list, renaming them.
Both options are repeatable, and both select, so mixing them is simply the union.
Nothing is written to disk and no file is created: the variables exist only in the command
this runs and in anything that command runs in turn.

Read this next part, because this command is weaker than the ``kubectl_vault`` one
and the difference is not a detail. An environment variable *is* plaintext in the child's
memory, so there is no sealed descriptor to hand over:

* Any process running as the same user can read ``/proc/<child-pid>/environ`` for as long
  as the child lives, whether or not the child cooperates.
* The child's children inherit the variables — that is the point of an environment — and
  so does every program the child execs. There is no way to scope them to one ``execve``.
* ``exec`` resets ``PR_SET_DUMPABLE``, so the child is dumpable again, and where the kernel
  pipes core dumps to a collector it ignores ``RLIMIT_CORE``. A child that crashes can
  therefore put its environment — these values — into a collected core.
* The child can print them (``env``, ``printenv``, ``/proc/self/environ``) and anything
  that logs its environment will.

So the guarantee is "this never creates a file and never writes a secret to disk", which
is what the library promises, and **not** "the value is confined to the process that
needs it". The library's :class:`~ecmwf_vault.Secret` refuses environment assignment to
stop a caller doing this by accident; this command does it on purpose, which is why it
exists as a separate, named command rather than as an API. If the distinction matters, use
the ``kubectl_vault`` command and its descriptor handover, keep the child's lifetime short,
and isolate the invocation (a container with a read-only root filesystem, or a separate
account).

Two refusals, both deliberate. A field whose name would overwrite a variable the child
already has is an error unless you pass ``--force``. A name **on a fixed list of known hooks**
is refused outright, with no override, and the Vault token itself is refused with it. The list
covers four risks rather than one, because a secret should decide none of them: what the child
**runs** (``PATH``, ``GIT_SSH_COMMAND``, the pagers and editors), which code it **loads**
(``LD_PRELOAD``, ``PYTHONPATH``, the Java/Node/Ruby/Lua startup paths), what it **trusts**
(the trust-store variables), and where it **writes key material** (``SSLKEYLOGFILE`` — not code
at all, and here because a secret that names that file undoes this package's central promise).

That list is a set of known hooks, not a classification of all of them: no client can
enumerate every variable that some program will interpret as an instruction, because the
program is the caller's choice. Names beyond it are the caller's judgement — which is one
reason ``--force`` is deliberate, and the reason the README says a secret's field names have
to be as trusted as its values.

The name refusals run before any value is revealed, so they reveal nothing. That is not a
claim that no plaintext exists in this process: ``value()`` has already fetched and decoded
the secret by then. The value refusals — a field that is not text, or holds a NUL — can only
be discovered by revealing, and they stop before a partial environment is handed over; a
field's *text* is never printed, only its name and type.

Exit status is the child's own, so this drops into scripts and pipelines; a failure of the
command itself — bad arguments, a refused name, a secret that could not be read, or a
command that could not be started at all — is ``2`` (``127`` when there is no such
command), printed to stderr with a ``vaultenv:`` prefix so it can be told from a child that
also exits ``2``. Anything after ``--`` goes to the command verbatim; without ``--``, any
argument this command does not recognise is passed through.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from ecmwf_vault import VaultError, value

from . import _command_contract as contract

MESSAGE_PREFIX = "vaultenv:"
# POSIX names only: a Vault field may be called "k8s-cems-test", an environment
# variable may not.
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Names through which a secret would decide something about the child that a secret should
# not. Refused outright — --force does not cover these — and there are four distinct risks
# here, which the refusal message names:
#
#   1. what the child RUNS   — PATH, SHELL, IFS, and the programs a tool runs for you
#                              (GIT_SSH_COMMAND, GIT_ASKPASS, the pagers and editors);
#   2. which code it LOADS   — the dynamic linker, GCONV_PATH/LOCPATH, and the startup paths
#                              of Python, Perl, Ruby, Node, Lua and the JVM;
#   3. what it TRUSTS        — the trust-anchor variables: SSL_CERT_FILE, SSL_CERT_DIR,
#                              REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO,
#                              NODE_EXTRA_CA_CERTS, AWS_CA_BUNDLE;
#   4. where it WRITES       — SSLKEYLOGFILE, which is not code and not trust at all: it
#                              names the file a TLS library writes session keys to.
#
# (4) is here because this package's whole promise is that a secret does not reach a disk,
# and a secret that can name that file can undo it. It was review that made the distinction:
# the first version of this comment, and the message beside it, called every entry a way to
# "run code the secret chose", which was never true of the trust anchors or SSLKEYLOGFILE.
#
# The list is finite and cannot be complete. The program the child runs is the caller's
# choice, and any program may invent an environment variable that names a command — Git's
# GIT_SSH_COMMAND was found in review by doing exactly that. So the real boundary is not this
# list: it is that the *field names* of a secret used with the default mapping become
# variable names, which means whoever can write the secret chooses them. The list removes the
# famous hooks; trusting the Vault path is what covers the rest, and the README and §28.1
# say so.
FORBIDDEN_NAMES = frozenset({
    # The dynamic linker, and the loaders that read code from a path.
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "GCONV_PATH", "LOCPATH",
    # Language runtimes that load code named by the environment at startup.
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
    "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH",
    "NODE_OPTIONS", "NODE_PATH", "LUA_PATH", "LUA_CPATH",
    "CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    # Programs that a tool will run on your behalf.
    "PATH", "SHELL", "IFS",
    "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR", "GIT_ASKPASS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "PAGER", "MANPAGER", "EDITOR", "VISUAL", "LESSOPEN", "LESSCLOSE", "SSH_ASKPASS",
    # Shell startup, and exported shell functions.
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS",
    # Trust anchors and key material: not code, but they redirect what the child trusts
    # and can make a library write key material somewhere.
    "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "AWS_CA_BUNDLE",
})

# Families that are enumerated by a counter, so no fixed list of names can cover them:
# Git reads GIT_CONFIG_COUNT together with GIT_CONFIG_KEY_<n>/VALUE_<n> pairs as
# configuration, so both of these can set core.sshCommand without ever naming it.
# (Bash's exported functions, ``BASH_FUNC_name%%``, need no rule here: the ``%%`` makes
# the name fail name validation before this check is reached.)
FORBIDDEN_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultenv",
        description="Run a command with environment variables read from Vault.",
        # Without this, a command flag that happens to prefix one of ours would be
        # swallowed as an abbreviation of it.
        allow_abbrev=False,
    )
    parser.add_argument("--secret", required=True,
                        help="Vault path whose fields become environment variables")
    parser.add_argument("--mount", default=None,
                        help="Vault mount, if not the default 'groups'")
    parser.add_argument("--field", action="append", default=[], metavar="NAME",
                        help="use only this field, under its own name; repeatable")
    parser.add_argument("--set", action="append", default=[], metavar="NAME=FIELD",
                        help="use exactly these fields, renaming them; repeatable")
    parser.add_argument("--force", action="store_true",
                        help="overwrite variables the command already has")
    return parser


def require_name(name: str) -> None:
    if not NAME_PATTERN.match(name):
        raise SystemExit(
            "field %r is not a valid environment variable name; rename it with "
            "--set NAME=%s" % (name, name))


def refuse_forbidden_names(wanted) -> None:
    """Refuse the names through which a secret would decide what the child runs or trusts.

    Runs before any value is revealed, so this refusal reveals nothing. Note what it does
    *not* claim: the secret has already been fetched and decoded by the time it runs, the
    list is finite so it cannot be a complete boundary, and a listed name is not necessarily
    *code* — the trust-anchor names change what the child believes, and ``SSLKEYLOGFILE``
    names a file it writes key material to. See the comment on :data:`FORBIDDEN_NAMES`.
    """
    for variable in wanted:
        if variable == contract.TOKEN_VARIABLE:
            raise SystemExit(
                "refusing to put %s in a command's environment: that is the credential "
                "this package exists to keep out of one" % contract.TOKEN_VARIABLE)
        if variable in FORBIDDEN_NAMES or variable.startswith(FORBIDDEN_PREFIXES):
            raise SystemExit(
                "refusing to set %s from a Vault field: a command that honours it decides "
                "which program runs, which code that program loads, what it trusts, or where "
                "it writes key material — and there is no --force for that. If you really "
                "need it, set it in your own wrapper rather than from a secret." % variable)


def require_field(field_name, fields) -> None:
    if field_name not in fields:
        raise SystemExit("no field %r in that secret; it has: %s"
                         % (field_name, contract.field_names_text(fields)))


def map_variable(wanted, variable, field_name) -> None:
    if variable in wanted:
        raise SystemExit(
            "%s is selected twice; --field and --set both select, and a variable can "
            "only be set once" % variable)
    wanted[variable] = field_name


def variable_mapping(selected, renamed, fields):
    """The variable-to-field mapping to use, or explain what is wrong with it.

    ``selected`` is ``--field``: use this field, under its own name. ``renamed`` is
    ``--set NAME=FIELD``: use this field, renamed. Both select, so mixing them is the
    union; with neither, every field of the secret is used as it is.
    """
    if not fields:
        raise SystemExit("that secret has no fields, so there is nothing to set")
    wanted = {}
    for field_name in selected:
        require_name(field_name)
        require_field(field_name, fields)
        map_variable(wanted, field_name, field_name)
    for item in renamed:
        variable, separator, field_name = item.partition("=")
        if not separator or not variable or not field_name:
            raise SystemExit("--set takes NAME=FIELD, not %r" % item)
        require_name(variable)
        require_field(field_name, fields)
        map_variable(wanted, variable, field_name)
    if wanted:
        return wanted
    for field_name in fields:
        require_name(field_name)
        map_variable(wanted, field_name, field_name)
    return wanted


def build_child_environment(wanted, force):
    """Our environment without the Vault token, once the overwrites are agreed to."""
    environment = contract.environment_without_token()
    clashes = sorted(name for name in wanted if name in environment)
    if clashes and not force:
        raise SystemExit(
            "these variables are already set, and the secret would overwrite them: %s\n"
            "pass --force if overwriting them for this command is what you want"
            % ", ".join(clashes))
    return environment


def variable_values(fields, wanted):
    """The text of each requested variable. This is the only place a value is revealed."""
    values = {}
    for variable, field_name in wanted.items():
        revealed = fields[field_name].reveal()
        if not isinstance(revealed, str):
            # A Vault KV v2 field can hold JSON, so this is reachable rather than
            # defensive: stringifying it here would silently turn True into "True"
            # and send the command something it did not ask for.
            raise SystemExit(
                "field %r holds %s, not text; store it as a string in Vault"
                % (field_name, type(revealed).__name__))
        if "\0" in revealed:
            raise SystemExit("field %r holds a NUL byte, which no environment variable "
                             "can carry" % field_name)
        try:
            os.fsencode(revealed)
        except UnicodeEncodeError:
            # Vault JSON can carry a lone surrogate (\udXXX). ``subprocess`` encodes the
            # environment with ``os.fsencode``, so this would otherwise raise there as a
            # traceback — and the exception's *object* is the value. Refused here, naming
            # the field, which is not the secret.
            raise SystemExit("field %r holds text that cannot be passed in an environment "
                             "(it contains a lone surrogate)" % field_name)
        values[variable] = revealed
    return values


def run(argv) -> int:
    ours, command = contract.split_at_separator(argv)
    parser = build_parser()
    if command is None:
        options, command = parser.parse_known_args(ours)
    else:
        options = parser.parse_args(ours)

    if not command:
        contract.report_own_error(MESSAGE_PREFIX, "no command given; put it after --")
        return contract.EXIT_COMMAND_FAILED

    try:
        fields = value(options.secret, mount=options.mount)
    except VaultError as error:
        contract.report_own_error(MESSAGE_PREFIX, str(error))
        return contract.EXIT_COMMAND_FAILED

    wanted = variable_mapping(options.field, options.set, fields)
    refuse_forbidden_names(wanted)
    environment = build_child_environment(wanted, options.force)
    # variable_values returns a complete mapping or raises, so a refusal here
    # cannot leave a half-built environment behind.
    environment.update(variable_values(fields, wanted))
    return contract.run_child(command, environment, message_prefix=MESSAGE_PREFIX)


def main() -> int:
    # The refusals explain themselves; argparse sends usage errors to stderr separately.
    return contract.run_as_command(run, message_prefix=MESSAGE_PREFIX)


if __name__ == "__main__":  # pragma: no cover - coverage's defaults do not exclude this
    sys.exit(main())
