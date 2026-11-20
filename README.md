<!-- SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF) -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# ecmwf-vault

Read secrets from [ECMWF Vault](https://secrets.ecmwf.int/) without writing them to disk. The package provides a Python API and commands for passing secrets to other programs.

## Install and sign in

Requires Linux, CPython 3.9 or later with `memfd_create` and file sealing support, and `gpg` or `gpg2` on `PATH`. Use a distribution Python if your Conda interpreter lacks file sealing support. There are no Python runtime dependencies. Install `kubectl` separately if you use `kubectl_vault`.

From the repository root in a venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On the VDI:
- note this requires `/home/madt/.local/bin/` on your PATH

```bash
python3.9 -m pip install --user .
```

To uninstall from VDI:
```bash
/usr/bin/python3.9 -m pip uninstall ecmwf-vault
```

1. Run `vault_login` in a terminal and paste the token at the prompt. The command does not echo the token. It validates it, saves it encrypted, and reports its expiry.
1.1. Sign in at [secrets.ecmwf.int](https://secrets.ecmwf.int/). Open your profile menu and select **Copy token**.
2. Optionally: Run `vault_expiry` to check the token's remaining lifetime and policies. Use `vault_expiry --json` for machine-readable output.

Run `vault_login` again when the token expires. Commands can prompt for a replacement token, but unattended jobs cannot.

## Commands

For KV v2 secrets, `--secret` takes the path relative to the mount, without a leading slash. The default mount is `groups`; use `--mount` for a different one. Run any command with `--help` to see its options.

### `kubectl_vault`: run kubectl with a Vault kubeconfig

```bash
kubectl_vault --secret user_applications_and_services_team/cems_web \
  --field kubeconfig -- -n glofas-stage get pods
```

This example targets the CEMS test cluster. Put kubectl arguments after `--`. Omit `--field` only if the secret has exactly one field. Use `--kubectl PATH` to select a binary or `--no-kubectl-cache` to disable kubectl's discovery cache.

The kubeconfig is passed through a read-only memory file, not a file on disk. `kubectl config set-*` cannot modify it, and `kubectl config view --raw` can print credentials.

### `vaultenv`: run a command with Vault values

```bash
vaultenv --secret my-team/database --set PGPASSWORD=password -- \
  psql -h db.example.int -U app
```

- `--field NAME` exports one field under its existing name. `--set NAME=FIELD` exports a field under a new name. Both are repeatable.
- Without either option, all fields are selected. Prefer explicit selection so the secret's field names do not determine the command's environment.
- Exported values must be text and variable names must be valid. `--force` permits overwriting inherited variables, but cannot override blocked names such as `PATH` or `VAULT_TOKEN`.

If the program accepts a file path, pass the value through a memory file instead:

```bash
vaultenv --secret my-team/client --mem-field=config:cfg -- \
  my-client --config '{cfg}'
```

`--mem-field FIELD:NAME` replaces `{NAME}` in the command arguments with a descriptor path. That field is not exported, but other fields still follow the normal export rules. Use `--mem-file NAME` with `{NAME}` to pass the whole selection as a file of `KEY=value` lines instead of exporting it. Values in that file must be single-line.

### `vault_cubby`: read the current token's cubbyhole

```bash
vault_cubby --path my-app/database --set PGPASSWORD=password -- \
  psql -h db.example.int -U app
```

Use `--path` instead of `--secret`; there is no mount option. `--field`, `--set`, and `--force` work as in `vaultenv`. Only the current token can read its cubbyhole. Vault deletes the contents when that token expires or is revoked.

## Python API

```python
from ecmwf_vault import value

secret = value("my-team/database", field="password")
password = secret.reveal()
```

`value(path)` returns a mapping of field names to `Secret` objects. These display as `<Secret>`; use `.reveal()` only where the plaintext is needed. Use `cache=False` to fetch a fresh value without caching it. Use a `Vault` context manager to control cache lifetime, and `cubbyhole_read(path)` to read from the current token's cubbyhole.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ECMWF_VAULT_TOKEN_FILE` | `~/.ecmwf-vault/token` | Path to the token file; `VAULT_TOKEN` is not used. |
| `ECMWF_VAULT_ADDR` | `https://secrets.ecmwf.int` | Vault HTTPS address. |
| `ECMWF_VAULT_MOUNT` | `groups` | Default KV v2 mount. |
| `ECMWF_VAULT_CA_BUNDLE` | System trust store | Custom CA bundle, replacing the system trust store. |
| `ECMWF_VAULT_TIMEOUT` | `10` | Request timeout in seconds. |
| `ECMWF_VAULT_SWAP_POLICY` | `refuse` | Refuse to read secrets on a host with active swap. |
| `ECMWF_VAULT_HARDEN` | `1` | Enable core-dump protection for the Vault client process. |

## Credential handling

- Keep the token file at mode `600` and its directory at `700`. The encrypted token is stored on disk; its passphrase is derived from account details, so file permissions are the access control.
- Secret values are not written to disk by the package. Once passed to another program or revealed in Python, that consumer is responsible for how it handles them.
- A memory file prevents modification, not inspection by a privileged process or another process running as the same user. Environment variables are also inherited by child processes and can appear in diagnostics. Use memory files when the receiving program supports them.

## Run the tests

From the repository root, run the offline suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t tests -v
```
