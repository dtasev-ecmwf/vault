# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vault_cubby`` command: run a command with variables read from the cubbyhole.

Same shape as ``vaultenv``, different place: the fields come from ``/v1/cubbyhole/<path>``
rather than from a KV v2 mount. There is no ``--mount``, because a cubbyhole has no mount to
choose.

**A cubbyhole belongs to a token, not to a person.** Only the token that made the request can
read it, no policy widens it, and its contents are deleted when that token expires or is
revoked. So a value stored here is reachable by exactly one credential — the one in
``~/.ecmwf-vault/token`` — and by nothing else: not another token of the same account, not a
colleague, not a ``cron`` job holding a different token. It is a store for one login's own
use, which is also what makes it short-lived: re-login empties it.

Merging this into ``vaultenv`` changes one externally visible string: the stderr prefix
below is what an operator greps for, and it becomes the merged command's.

Everything else is ``vaultenv``'s behaviour, reused rather than restated: the same field
selection (``--field``, ``--set``), the same refusal of names a secret must not decide, the
same ``--force`` rule for variables the command already has, the same treatment of a value that
is not text or cannot be encoded, and the same expiry retry.

Exit status is the command's own. ``2`` means this command failed — a refusal, or a Vault
error printed to stderr under the ``vault_cubby:`` prefix.
"""
from __future__ import annotations

import argparse
import sys

from ecmwf_vault import VaultError, _login, cubbyhole_read

from . import _command_contract as contract
from .vaultenv import (
    build_child_environment,
    refuse_forbidden_names,
    variable_mapping,
    variable_values,
)

MESSAGE_PREFIX = "vault_cubby:"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_cubby",
        description="Run a command with environment variables read from the Vault cubbyhole.",
        # Without this, a command flag that happens to prefix one of ours would be
        # swallowed as an abbreviation of it.
        allow_abbrev=False,
    )
    parser.add_argument("--path", required=True, metavar="PATH",
                        help="cubbyhole path whose fields become environment variables")
    parser.add_argument("--field", action="append", default=[], metavar="NAME",
                        help="use only this field, under its own name; repeatable")
    parser.add_argument("--set", action="append", default=[], metavar="NAME=FIELD",
                        help="use exactly these fields, renaming them; repeatable")
    parser.add_argument("--force", action="store_true",
                        help="overwrite variables the command already has")
    return parser


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
        # A token that has run out is replaced and the read tried once more; anything the
        # read refuses for another reason is reported unchanged.
        fields = _login.run_retrying_once_if_token_lookup_refused(
            lambda: cubbyhole_read(options.path), prefix=MESSAGE_PREFIX)
    except VaultError as error:
        contract.report_own_error(MESSAGE_PREFIX, str(error))
        return contract.EXIT_COMMAND_FAILED

    wanted = variable_mapping(options.field, options.set, fields)
    refuse_forbidden_names(wanted)
    environment = build_child_environment(wanted, options.force)
    environment.update(variable_values(fields, wanted))
    return contract.run_child(command, environment, message_prefix=MESSAGE_PREFIX)


def main() -> int:
    return contract.run_as_command(run, message_prefix=MESSAGE_PREFIX)


if __name__ == "__main__":  # pragma: no cover - coverage's defaults do not exclude this
    sys.exit(main())
