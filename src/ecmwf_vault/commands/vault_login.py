# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``vault_login`` command: fetch a Vault token and store it sealed.

Installed as a console script by ``pip install ecmwf-vault`` (``pyproject.toml`` maps
``vault_login`` to :func:`main`); this module is private, and the command is the public
artefact. Run it from a checkout with ``python -m ecmwf_vault.commands.vault_login``.

    vault_login

It prints the address of the Vault it will check against, reads the token you paste back
**without echoing it**, checks it with Vault's own ``auth/token/lookup-self``, and writes it to
``~/.ecmwf-vault/token`` encrypted only once that works. A paste that is not a token (one
starts with ``hvs.``) is asked for again, and a token Vault refuses is never stored. The expiry
Vault reports is printed with the confirmation.

The prompt needs a terminal, and needs that terminal to be able to disable echo; without either
it refuses rather than reading stdin or showing the token as it is typed.

There is no option and no argument: the token file is wherever the library resolves it to
(``ECMWF_VAULT_TOKEN_FILE``, or ``~/.ecmwf-vault/token``), and a token on a command line is a
token in the process list. The other commands run the same flow themselves when Vault refuses
the token they hold, so this is normally only run the first time.

Exit status is ``0`` when a token was stored, and ``2`` when none was — a paste that was not
a token and then an end of input, a token Vault refused and then an end of input, or a Vault
that could not be reached. The reason is printed to stderr under the ``vault_login:`` prefix.
"""
from __future__ import annotations

import argparse
import sys

from ecmwf_vault import VaultError, _login

from . import _command_contract as contract

MESSAGE_PREFIX = "vault_login:"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_login",
        description="Fetch a Vault token and store it encrypted in the token file.",
        allow_abbrev=False,
    )
    return parser


def run(argv) -> int:
    build_parser().parse_args(argv)
    try:
        _login.log_in(prefix=MESSAGE_PREFIX)
    except VaultError as error:
        contract.report_own_error(MESSAGE_PREFIX, str(error))
        return contract.EXIT_COMMAND_FAILED
    return 0


def main() -> int:
    return contract.run_as_command(run, message_prefix=MESSAGE_PREFIX)


if __name__ == "__main__":  # pragma: no cover - coverage's defaults do not exclude this
    sys.exit(main())
