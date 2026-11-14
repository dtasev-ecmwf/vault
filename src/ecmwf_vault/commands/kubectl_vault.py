# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The ``kubectl_vault`` command: run kubectl with a kubeconfig read from Vault.

Installed as a console script by ``pip install ecmwf-vault`` (``pyproject.toml`` maps
``kubectl_vault`` to :func:`main`); this module is private, and the command is the public
artefact. Run it from a checkout with ``python -m ecmwf_vault.commands.kubectl_vault``.

    kubectl_vault --secret user_applications_and_services_team/cems_web \
                  --field k8s-cems-test -n glofas-stage get pods

The kubeconfig is fetched over HTTPS, sealed into an anonymous memory file, and handed
to kubectl as an *inherited descriptor* via ``--kubeconfig=/proc/self/fd/<n>``. No named
file is created and kubectl inherits no Vault token. kubectl itself is a trusted consumer,
though, and it ends up holding the credential; read the limits below before treating this
as confidential end to end.

An expired token does not fail this command at its first refusal: it is replaced through the
workflow in :mod:`ecmwf_vault._login` and the read is tried once more. With no terminal to ask
on, that is reported and the command fails as any other read failure does.

Exit status is kubectl's own, so this is usable in scripts and pipelines; a failure of the
command itself — bad arguments, or a secret that could not be read — is ``2``. kubectl can
return ``2`` as well, so the way to tell them apart is that these failures are the ones
printed to stderr with a ``kubectl_vault:`` prefix. Anything after ``--`` goes to kubectl
verbatim; without ``--``, any argument this command does not recognise is passed through, so
``kubectl_vault --secret X --field Y -n glofas-stage get pods`` works.

Known limits, so they are not surprises:

* The descriptor is sealed against *writing*, not against *reading*. While kubectl holds
  it, a process running as the same user can read it through ``/proc``; ``exec`` resets
  the non-dumpable protection this package sets for its own process; and kubectl may pass
  the descriptor on to its children. Sealing means the bytes cannot change — it is not a
  confidentiality boundary.
* kubectl is trusted to use the kubeconfig sensibly. ``kubectl config view --raw`` prints
  the credential, and authentication plugins or a caller-supplied ``--kubectl`` can do
  whatever they like with it. Isolate the whole invocation (a container with a read-only
  root filesystem, or a separate account) if that is not acceptable.
* Unlike the ``vaultenv`` command, the value is never placed in kubectl's environment or
  argument list — but it is revealed in this process, because a sealed file takes bytes.
* ``kubectl config set-*`` cannot work — the descriptor is sealed read-only.
* kubectl leaks its own discovery cache to ``~/.kube/cache`` unless ``--no-kubectl-cache``
  is given (the cache holds API discovery documents, not credentials).
* ``kubectl exec -it`` and other interactive subcommands work, because stdio is inherited.
"""
from __future__ import annotations

import argparse
import os
import sys

from ecmwf_vault import _environment
from ecmwf_vault import SecretMemoryFile, VaultError, _login, value

from . import _command_contract as contract

MESSAGE_PREFIX = "kubectl_vault:"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubectl_vault",
        description="Run kubectl with a kubeconfig read from Vault.",
        # Without this, a kubectl flag that happens to prefix one of ours (say
        # --field-selector) would be swallowed as an abbreviation of --field.
        allow_abbrev=False,
    )
    parser.add_argument("--secret", required=True,
                        help="Vault path whose field holds the kubeconfig")
    parser.add_argument("--field", default=None,
                        help="name of that field; the only field is used if omitted")
    parser.add_argument("--mount", default=None,
                        help="Vault mount, if not the default 'groups'")
    parser.add_argument("--kubectl", default="kubectl",
                        help="kubectl to run, for a pinned version or a test double")
    parser.add_argument("--no-kubectl-cache", action="store_true",
                        help="pass --cache-dir=/dev/null so kubectl writes no cache")
    return parser


def resolve_field(fields, requested):
    """Return the field name to use, or explain which ones are there."""
    if requested is not None:
        if requested not in fields:
            raise SystemExit(
                "no field %r in that secret; it has: %s"
                % (requested, contract.field_names_text(fields)))
        return requested
    if len(fields) == 1:
        return next(iter(fields))
    raise SystemExit(
        "that secret has %d fields, so --field is required; it has: %s"
        % (len(fields), contract.field_names_text(fields)))


def reveal_kubeconfig(fields, field):
    """The revealed kubeconfig text, as bytes, ready to be sealed."""
    revealed = fields[field].reveal()
    if not isinstance(revealed, str):
        # Vault fields can hold JSON, not only strings, so this is reachable rather
        # than defensive: a mapping here is a misuse, not a kubeconfig.
        raise SystemExit("the field %r is %s, not kubeconfig text"
                         % (field, type(revealed).__name__))
    try:
        return revealed.encode("utf-8")
    except UnicodeEncodeError:
        # Vault JSON can carry a lone surrogate (\udXXX), which no UTF-8 encoding
        # accepts. The exception's *object* is the text, so it is never printed —
        # only the field, which is not the secret. Without this, the failure would be
        # a traceback carrying the kubeconfig.
        raise SystemExit("the field %r cannot be encoded as UTF-8, so it cannot be "
                         "kubeconfig text" % field)


def run(argv) -> int:
    ours, kubectl_arguments = contract.split_at_separator(argv)
    parser = build_parser()
    if kubectl_arguments is None:
        options, kubectl_arguments = parser.parse_known_args(ours)
    else:
        options = parser.parse_args(ours)

    try:
        # A token that has run out is replaced and the read tried once more; anything the
        # read refuses for another reason is reported unchanged.
        fields = _login.run_retrying_once_if_token_lookup_refused(
            lambda: value(options.secret, mount=options.mount), prefix=MESSAGE_PREFIX)
    except VaultError as error:
        contract.report_own_error(MESSAGE_PREFIX, str(error))
        return contract.EXIT_COMMAND_FAILED

    field = resolve_field(fields, options.field)
    memory = SecretMemoryFile(reveal_kubeconfig(fields, field))
    try:
        command = [options.kubectl, "--kubeconfig=/proc/self/fd/%d" % memory.fd]
        if options.no_kubectl_cache:
            command.append("--cache-dir=/dev/null")
        command.extend(kubectl_arguments)
        environment = _environment.child_environment()
        return contract.run_child(command, environment, message_prefix=MESSAGE_PREFIX,
                                   descriptor=memory.fd)
    finally:
        memory.close()


def main() -> int:
    # resolve_field and reveal_kubeconfig explain themselves; argparse's usage errors
    # arrive here as a number, and are passed through.
    return contract.run_as_command(run, message_prefix=MESSAGE_PREFIX)


if __name__ == "__main__":  # pragma: no cover - coverage's defaults do not exclude this
    sys.exit(main())
