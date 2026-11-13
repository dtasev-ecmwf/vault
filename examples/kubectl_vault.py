#!/usr/bin/env python3
"""Run kubectl with a kubeconfig read from Vault, without that kubeconfig ever
existing as a file.

    kubectl-vault --secret user_applications_and_services_team/cems_web \\
                  --field k8s-cems-test -- get pods -n efas-production

The kubeconfig is fetched over HTTPS, sealed into an anonymous memory file, and handed
to kubectl as an *inherited descriptor* via ``--kubeconfig=/proc/self/fd/<n>``. The
wrapper creates no named file and kubectl inherits no Vault token. kubectl itself is a
trusted consumer, though, and it ends up holding the credential; read the limits below
before treating this as confidential end to end.

Exit status is kubectl's own, so this is usable in scripts and pipelines; a failure of
the wrapper itself — bad arguments, or a secret that could not be read — is ``2``. kubectl
can return ``2`` as well, so the way to tell them apart is that the wrapper's failures are
the ones printed to stderr with a ``kubectl-vault:`` prefix. Anything after ``--`` goes to
kubectl verbatim; without ``--``, any argument this wrapper does not recognise is passed
through.

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
* ``kubectl config set-*`` cannot work — the descriptor is sealed read-only.
* kubectl leaks its own discovery cache to ``~/.kube/cache`` unless ``--no-kubectl-cache``
  is given (the cache holds API discovery documents, not credentials).
* ``kubectl exec -it`` and other interactive subcommands work, because stdio is inherited.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from ecmwf_vault import SecretMemoryFile, VaultError, value

EXIT_WRAPPER_FAILED = 2
EXIT_KUBECTL_NOT_FOUND = 127
TOKEN_VARIABLE = "ECMWF_VAULT_TOKEN"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubectl-vault",
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


def split_at_separator(argv):
    """Split our arguments from kubectl's at the first ``--``, if there is one."""
    if "--" in argv:
        cut = argv.index("--")
        return argv[:cut], argv[cut + 1:]
    return argv, None


def resolve_field(fields, requested):
    """Return the field name to use, or explain which ones are there."""
    if requested is not None:
        if requested not in fields:
            raise SystemExit(
                "no field %r in that secret; it has: %s"
                % (requested, ", ".join(sorted(fields)) or "none"))
        return requested
    if len(fields) == 1:
        return next(iter(fields))
    raise SystemExit(
        "that secret has %d fields, so --field is required; it has: %s"
        % (len(fields), ", ".join(sorted(fields)) or "none"))


def kubeconfig_bytes(fields, field):
    """The revealed kubeconfig text, as bytes, ready to be sealed."""
    revealed = fields[field].reveal()
    if isinstance(revealed, str):
        return revealed.encode("utf-8")
    # Vault fields can hold JSON, not only strings, so this is reachable rather
    # than defensive: a mapping here is a misuse, not a kubeconfig.
    raise SystemExit("the field %r is %s, not kubeconfig text"
                     % (field, type(revealed).__name__))


def child_environment():
    """Our environment without the Vault token: kubectl does not need it."""
    environment = dict(os.environ)
    environment.pop(TOKEN_VARIABLE, None)
    return environment


def run(argv) -> int:
    ours, kubectl_arguments = split_at_separator(argv)
    parser = build_parser()
    if kubectl_arguments is None:
        options, kubectl_arguments = parser.parse_known_args(ours)
    else:
        options = parser.parse_args(ours)

    try:
        fields = value(options.secret, mount=options.mount)
    except VaultError as error:
        print("kubectl-vault: %s" % error, file=sys.stderr)
        return EXIT_WRAPPER_FAILED

    field = resolve_field(fields, options.field)
    memory = SecretMemoryFile(kubeconfig_bytes(fields, field))
    try:
        command = [options.kubectl, "--kubeconfig=/proc/self/fd/%d" % memory.fd]
        if options.no_kubectl_cache:
            command.append("--cache-dir=/dev/null")
        command.extend(kubectl_arguments)
        try:
            return subprocess.call(command, pass_fds=(memory.fd,),
                                   env=child_environment())
        except FileNotFoundError:
            print("kubectl-vault: cannot run %r" % options.kubectl, file=sys.stderr)
            return EXIT_KUBECTL_NOT_FOUND
    finally:
        memory.close()


def main() -> int:
    try:
        return run(sys.argv[1:])
    except SystemExit as error:
        # resolve_field explains itself on stdout, where argparse sends usage errors.
        if isinstance(error.code, str):
            print("kubectl-vault: %s" % error.code, file=sys.stderr)
            return EXIT_WRAPPER_FAILED
        return int(error.code)


if __name__ == "__main__":
    sys.exit(main())
