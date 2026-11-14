# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vault_expiry`` command: report the Vault token's own metadata.

Installed as a console script by ``pip install ecmwf-vault`` (``pyproject.toml`` maps
``vault_expiry`` to :func:`main`); this module is private, and the command is the public
artefact. Run it from a checkout with ``python -m ecmwf_vault.commands.vault_expiry``.

    vault_expiry
    vault_expiry --json

It reads ``auth/token/lookup-self`` — Vault's own endpoint for a token's details — and
prints how long the token lasts (``ttl``, ``creation_ttl``, ``issue_time``,
``expire_time``), what it may do (``renewable``, ``num_uses``, ``policies``) and what it
identifies (``display_name``, ``accessor``, ``entity_id``, ``type``, ``meta``). Any field
Vault returns that this command has never heard of is printed too, under its own name, so
nothing is silently dropped.

With one substitution: for some token types the ``id`` field Vault reports **is the token's
value**, and the library replaces it with a fixed note rather than passing it on — so this
command cannot print a credential even by accident, which is what its output is for reading.

Where the token comes from is the library's business, not this command's: the sealed
``~/.ecmwf-vault/token``, filled by ``vault_login``. There is deliberately no ``--token``
option — a token on a command line is a token in the process list.

Two things are worth knowing about a 403 from this endpoint, because it is about the token
rather than about a path: a token that has expired or been revoked cannot look *itself* up,
and a policy that does not allow ``auth/token/lookup-self`` stops it too. The message names
both without claiming the list is complete.

An expired token does not fail this command at its first refusal: it is replaced through the
workflow in :mod:`ecmwf_vault._login` and the lookup is tried once more. With no terminal to
ask on, that is reported and the command fails as it would have.

Exit status is ``0`` when the token's details were read, and ``2`` when this command could
not read them — a refused token, an unreachable Vault, a missing token — with the failure
printed to stderr under the ``vault_expiry:`` prefix.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterator, List, Tuple

from ecmwf_vault import Vault, VaultError, _login

from . import _command_contract as contract

MESSAGE_PREFIX = "vault_expiry:"

# The fields to show, in the order to show them, with the label each gets. Anything the
# response contains that is not listed here is printed afterwards under its own name, so a
# new Vault field is visible without a change here; the order is fixed so that two runs
# against the same token are diffable.
FIELD_ORDER: Tuple[Tuple[str, str], ...] = (
    ("ttl", "remaining ttl"),
    ("creation_ttl", "creation ttl"),
    ("explicit_max_ttl", "explicit max ttl"),
    ("issue_time", "issue time"),
    ("expire_time", "expire time"),
    ("renewable", "renewable"),
    ("num_uses", "uses remaining"),
    ("type", "token type"),
    ("display_name", "display name"),
    ("policies", "policies"),
    ("identity_policies", "identity policies"),
    ("accessor", "accessor"),
    ("entity_id", "entity id"),
    ("path", "created by"),
)

# Fields Vault reports in seconds: shown with the duration that many seconds is, because
# "259200" is not a number anybody reads.
DURATIONS = ("ttl", "creation_ttl", "explicit_max_ttl")

UNITS = (("d", 86400), ("h", 3600), ("m", 60), ("s", 1))


def render_duration(seconds: int) -> str:
    """A number of seconds as a compact duration: ``3d 2h``, ``1h 58m 32s``, ``0s``."""
    remaining = seconds
    parts: List[str] = []
    for suffix, size in UNITS:
        if remaining >= size:
            parts.append("%d%s" % (remaining // size, suffix))
            remaining %= size
    return " ".join(parts) or "0s"


def render_value(value: Any) -> str:
    """Any value Vault can return, as one line of text.

    Vault sends JSON, so these are the JSON shapes; a nested object is flattened to
    ``key=value`` pairs rather than left to ``repr``, which would put braces and quotes in
    the middle of the report.
    """
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, str):
        return value or "(empty)"
    if isinstance(value, list):
        return ", ".join(render_value(item) for item in value) or "none"
    if isinstance(value, dict):
        return ", ".join("%s=%s" % (key, render_value(item))
                         for key, item in sorted(value.items())) or "none"
    # A number, in every case Vault can send one. Deliberately total rather than exhaustive:
    # anything else still has to print, because raising on the way to a report would defeat
    # the point of asking.
    return str(value)


def render_field(name: str, value: Any) -> str:
    """One field's value, with the two readings that need interpreting."""
    if name in DURATIONS and isinstance(value, int) and not isinstance(value, bool):
        return "%d (%s)" % (value, render_duration(value))
    if name == "num_uses" and value == 0:
        # Vault's own encoding for "no limit", and "0" would read as "used up".
        return "unlimited"
    return render_value(value)


def field_rows(info: Dict[str, Any]) -> Iterator[Tuple[str, str]]:
    """The labelled rows to print: the known fields, then everything else, sorted."""
    known = {name for name, _ in FIELD_ORDER}
    for name, label in FIELD_ORDER:
        if name in info:
            yield label, render_field(name, info[name])
    for name in sorted(set(info) - known):
        yield name.replace("_", " "), render_value(info[name])


def notes(info: Dict[str, Any]) -> List[str]:
    """Plain-language notes for the readings that are easy to get wrong.

    Each one is a case where the numbers alone mislead: a token Vault reports with a null
    ``expire_time`` *and* a ``ttl`` of 0 does not end by time, a non-renewable token cannot be
    extended, and a token with a use limit dies when the uses run out whatever the ``ttl``
    says.
    """
    found: List[str] = []
    ttl = info.get("ttl")
    # Both halves are required, and the key has to be present. Vault sends a null
    # ``expire_time`` together with ``ttl: 0`` for a token that does not expire; a *missing*
    # ``expire_time`` is a different thing (a response this command does not understand well
    # enough to describe), and a null one beside a non-zero ttl contradicts itself. Claiming
    # the token "does not end by time" on either of those would be inventing the answer.
    if ("expire_time" in info and info["expire_time"] is None
            and isinstance(ttl, int) and not isinstance(ttl, bool) and ttl == 0):
        found.append("No expire time is set: this token does not end by time, and the "
                     "ttl above is 0 for that reason rather than because it is nearly over.")
    if info.get("renewable") is False:
        found.append("Not renewable: once it expires you need a new token, and "
                     "auth/token/renew-self cannot extend this one.")
    uses = info.get("num_uses")
    if isinstance(uses, int) and not isinstance(uses, bool) and uses:
        found.append("A limited number of uses: this token stops working once they are "
                     "spent, whatever the ttl says.")
    return found


def format_report(info: Dict[str, Any], base_url: str) -> str:
    """The formatted report: a header, the aligned fields, then any notes."""
    rendered = list(field_rows(info))
    width = max((len(label) for label, _ in rendered), default=0)
    lines = ["Vault token at %s" % base_url]
    lines.extend("  %-*s  %s" % (width, label, value) for label, value in rendered)
    for note in notes(info):
        lines.append("")
        lines.append(note)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_expiry",
        description="Report the Vault token's own details: how long it lasts, what it "
                    "may do, and what it identifies.",
        allow_abbrev=False,
    )
    parser.add_argument("--json", action="store_true",
                        help="print the raw lookup response as JSON instead of a report")
    return parser


def run(argv) -> int:
    options = build_parser().parse_args(argv)
    try:
        # A Vault of its own, closed when the report is done: this is a one-shot process and
        # the metadata is not cached, so there is nothing to keep. A token that has run out is
        # replaced and the lookup tried once more, since this command is exactly what one asks
        # when something else has just refused a token.
        with Vault() as vault:
            info = _login.run_retrying_once_if_token_lookup_refused(
                vault.token_info, prefix=MESSAGE_PREFIX)
            base_url = vault.base_url
    except VaultError as error:
        contract.report_own_error(MESSAGE_PREFIX, str(error))
        return contract.EXIT_COMMAND_FAILED
    if options.json:
        print(json.dumps(info, indent=2, sort_keys=True))
    else:
        print(format_report(info, base_url))
    return 0


def main() -> int:
    return contract.run_as_command(run, message_prefix=MESSAGE_PREFIX)


if __name__ == "__main__":  # pragma: no cover - coverage's defaults do not exclude this
    sys.exit(main())
