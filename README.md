<!-- SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF) -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# ecmwf-vault

Read one secret from the ECMWF Vault (`https://secrets.ecmwf.int`, a
Vault-compatible KV v2 store) and keep it off disk for its whole lifetime.

Zero runtime dependencies, Linux, CPython 3.9+.

```python
from ecmwf_vault import value

password = value("user_applications_and_services_team/cems_web/k8s-cems-test",
                 field="password").reveal()
```

The token comes from `ECMWF_VAULT_TOKEN`, or from `~/.ecmwf-vault/config` if you
have one (see [Where the token comes from](#where-the-token-comes-from)).

## Requirements

Linux, CPython 3.9+, and an interpreter **built with `memfd_create` support** — it
must expose `os.memfd_create`, `os.MFD_CLOEXEC`, `os.MFD_ALLOW_SEALING` and the
`fcntl` seal constants `F_ADD_SEALS`, `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`
and `F_SEAL_SEAL`. Rather than checking names one at a time, ask it to do the thing:

```bash
PYTHONPATH=/perm/madt/dev/ecmwf-vault/src \
/usr/bin/python3 -c "from ecmwf_vault import SecretMemoryFile; SecretMemoryFile(b'{}')" \
  && echo "this interpreter is usable"
```

A name-level probe is weaker than it looks: a build can expose three of the eight and
still be unable to seal. The package's own error message prints a full name-level check
as a one-liner, for when you would rather not have the package on the candidate's path.

**conda-forge Pythons do not have them**, and that is an interpreter property rather
than an operating-system one: those builds are compiled against an old glibc sysroot,
so the build never saw `memfd_create` even though your kernel and runtime glibc both
support it. The `fcntl` seal constants come from the same build decision, so they are
missing together. You get a diagnosis rather than a puzzle:

```
VaultError: ecmwf-vault needs Linux memfd_create with file sealing, and this interpreter lacks it
  interpreter: /home/you/apps/miniforge3/bin/python (Python 3.14.8)
  kernel: 4.18.0-553.182.1.el8_10.x86_64
  missing: os.memfd_create, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE, ...
```

Use an interpreter that has the support (a distribution Python usually does), or one
built against a newer sysroot. The check runs **before** anything is fetched, so a
missing *capability* is reported before any network call — although it can only prove
the interpreter exposes the API, not that sealing will succeed: if sealing fails for an
environment reason, the fetch has already happened and nothing is stored or returned.
Either way the package fails closed rather than falling back to a named shared-memory
object or a file, since neither keeps the promise this package exists to make.

## The value you get back is a `Secret`, not a `str`

`value()` never hands you a plain string. What comes back renders as `<Secret>`
and refuses every route that would need the value as text, so the ordinary accident
fails loudly instead of writing your password into a config file — and anything that
merely *renders* it (a log line, an f-string, `print`) shows `<Secret>` rather than
the value:

```python
password = value(path, field="password")   # a Secret

open("out", "w").write(password)           # TypeError
logger.info("pw=%s", password)             # logs "<Secret>"
f"{password}"                              # "<Secret>"
json.dumps({"pw": password})               # TypeError
os.environ["PW"] = password                # TypeError
subprocess.run(["cmd", password])          # TypeError
subprocess.run(["cmd"], env={"PW": password})   # TypeError
pickle.dumps(password)                     # refuses - bytes would be the plaintext
password.encode()                          # refuses, and tells you what to do

password.reveal()                          # the one explicit way to the value
with password.revealed() as plain:         # ... or scoped to one block
    connect(plain)
```

`value(path)` returns a mapping whose values are `Secret`s in exactly the same
way, so dumping a whole secret's fields is refused too. If the reason you wanted
to write the value out was to hand it to a **child process**, use
`Vault.memory_file()` instead — that is an inherited descriptor, and no file ever
exists.

A `str` subclass would have been the obvious way to do this and it does not work:
`TextIOWrapper.write` accepts any `str` subclass and copies its data without ever
calling `__str__`, so `handle.write(secret)` would quietly succeed. Returning
something that is not a `str` at all is what makes `TypeError` reliable.

**This is a guard-rail, not a sandbox.** `reveal()` is right there, `_value` is
reachable, and `os.write` on a descriptor, a C extension, another process, or
`memory_file()` all bypass it. The only control that actually prevents a secret
reaching a filesystem is environmental: run the process with a read-only
filesystem, or as a user with no write access outside a tmpfs.

*0.2.0 is a breaking release for this reason: every caller now needs `.reveal()`.*

## API

```python
from ecmwf_vault import Vault, value

value(path)                                  # -> {field: Secret, ...}
value(path, field="password")                # -> Secret
value(path, cache=False)                     # fetch now, retain nothing
value(path, mount="kv", base_url="https://...")   # override for this call

with Vault(mount="groups") as vault:         # your own cache and lifetime
    vault.value(path)["password"].reveal()
    vault.keys(path)                         # -> ('password', 'user'), no values
    memory = vault.memory_file(path)         # sealed fd, for a child process
    memory.close()
```

The mount defaults to `groups`; `path` is everything after the mount, with no
leading slash.

## Configuration

Precedence: keyword argument, then environment variable, then built-in default.
The token has its own order, described below.

| Setting | Env var | Default |
| --- | --- | --- |
| token | `ECMWF_VAULT_TOKEN`, else `~/.ecmwf-vault/config` | *required* |
| config file | `ECMWF_VAULT_CONFIG` | `~/.ecmwf-vault/config` |
| config file permissions | `ECMWF_VAULT_CONFIG_POLICY` | `refuse` |
| base URL | `ECMWF_VAULT_ADDR` | `https://secrets.ecmwf.int` |
| mount | `ECMWF_VAULT_MOUNT` | `groups` |
| CA bundle | `ECMWF_VAULT_CA_BUNDLE` | system trust store |
| timeout (s) | `ECMWF_VAULT_TIMEOUT` | `10` |
| swap policy | `ECMWF_VAULT_SWAP_POLICY` | `refuse` |
| process hardening | `ECMWF_VAULT_HARDEN` | `1` |

## Where the token comes from

`ECMWF_VAULT_TOKEN` first, then `~/.ecmwf-vault/config` — the same order as
HashiCorp's own CLI, so an existing caller that sets the environment variable is
unaffected. The token is resolved on **every call** and never cached, so
unsetting the variable or replacing the file takes effect immediately.

The config file is `KEY=VALUE`, read as data and never executed:

```ini
# ~/.ecmwf-vault/config   -- keep it out of reach of group and other, like an ssh key
ECMWF_VAULT_TOKEN=hvs.CAESIJ...
```

Only `ECMWF_VAULT_TOKEN` is read from it today; any other key is refused rather
than quietly ignored, so a setting you put there cannot appear to be in force when
it is not. Values are literal — do not quote them — and `#` comments must be on
their own line.

Because a config file is only private if its permissions are, the file is checked
the way OpenSSH checks a key: a symlink, a non-regular file or an oversized file
is refused outright, and a file owned by another user or readable/writable by
group or other is refused by default, with `ECMWF_VAULT_CONFIG_POLICY=warn` or
`allow` as a deliberate opt-out. **The directory holding it is held to the same
rule** (`~/.ecmwf-vault` must be mode 700): a directory another user can reach
lets them list the file, replace it, or add one beside it. A symlinked directory
is resolved first, so what is judged is the mode of wherever the file really
lives. Errors name a line number and the mode that is required, never the content.

Provision it without ever putting the token in your shell history:

```bash
install -d -m700 ~/.ecmwf-vault
read -rs -p 'Vault token: ' T; echo
printf 'ECMWF_VAULT_TOKEN=%s\n' "$T" | install -m600 /dev/stdin ~/.ecmwf-vault/config
unset T
```

A source that is *absent or blank* falls through to the next one; a source that
is *present but cannot be a token* is an error, never a quiet fall-through to a
different credential.

Everything else is read when a `Vault` is constructed; the
module-level helpers keep at most eight default instances, one per
`(base_url, mount)` pair, evicting the least recently used. `clear_cache()`
forgets the secrets; `close()` is terminal — after it, the module-level helpers
raise, so a caller who has released a secret cannot have it silently re-fetched.
Construct a `Vault` for a new lifetime.

## What it guarantees

- **No disk.** The secret is held in a sealed, anonymous Linux `memfd`, never in a
  temp file, a cache file, a log, or a child process's argument list. Sealing
  (`F_SEAL_WRITE|GROW|SHRINK|SEAL`) means the bytes cannot change after they are
  written.
- **No swap.** With the default `refuse` policy, a host with active swap is
  rejected before anything is fetched — a `memfd` can still be paged out.
- **No core dumps for this process.** With hardening on it becomes non-dumpable and sets
  `RLIMIT_CORE=0`. The dumpable flag is what does the work: where `core_pattern` pipes to a
  collector the kernel ignores `RLIMIT_CORE` completely. A process you `exec` starts dumpable
  again, so a crashed *child* is not covered — see the kubectl wrapper's notes above.
- **No accidental token movement.** The request goes over `https` only, with no
  proxy support and no redirect following, so `HTTPS_PROXY` cannot re-route a
  token-bearing request and the token cannot be replayed to another host. The TLS
  context is assembled without `ssl.create_default_context()` — the one Python
  helper that reads `SSLKEYLOGFILE` and opens the file it names — while still
  applying the same verification hardening as that helper (`VERIFY_X509_STRICT`
  and `VERIFY_X509_PARTIAL_CHAIN`, the latter being what makes a CA bundle
  holding an intermediate usable), with a test asserting parity against a real
  platform context. Your environment is never modified.
  `ECMWF_VAULT_CA_BUNDLE` replaces the trust store; a bundle that cannot be
  loaded is a plain `VaultError`.
- **A missing token fails closed.** `value()` raises `RuntimeError` before any
  network call, path validation or memory allocation — even when the mount or base
  URL you passed is itself invalid.
- **A malformed token is refused too.** `ECMWF_VAULT_TOKEN` must be printable ASCII
  with no space. A token containing a CR, LF, tab or a non-ASCII character is
  rejected before transport, precisely so it can never surface inside a
  header-validation exception.
- **Cache entries are bound to the token.** A cached secret is never served to a
  different token than the one it was fetched with.
- **A secret cannot leave by accident.** Every value `value()` returns is a
  [`Secret`](#the-value-you-get-back-is-a-secret-not-a-str), not a `str`: file writes,
  `json.dumps`, environment assignment and child process arguments raise, while anything
  that merely renders the value — logging, f-strings, `print` — shows `<Secret>`. Either
  way the plaintext needs an explicit `reveal()`. That guard is about the library API; the
  `vaultenv` command shipped with the package does put values into a child's environment,
  on purpose and by name — see [below](#running-a-command-with-vault-environment-variables),
  including why that is a weaker boundary than `kubectl_vault`'s.
- **`cache=False` really means fetch now.** It re-reads Vault even when a value for
  that path is already cached, which is how you observe rotation or a revoked token.

## What it does not guarantee

The claim is "this package never puts the secret on disk", not "the secret is
unreadable in a compromised process". Specifically:

- `ECMWF_VAULT_TOKEN` arrives in the environment, which `/proc/<pid>/environ`
  exposes to anything running as the same user, and which is **inherited by every
  child process** your script starts. If an attacker can read your environment they
  already have the token; that is inherent in supplying it this way. The config
  file avoids the inheritance, but is by definition a credential **on disk** — it
  persists in backups and snapshots, and a 0600 file is only as private as your
  home directory. Neither form survives a host that is fully compromised.
- The value a caller *reveals* is an ordinary Python object in the heap, and the
  parser's intermediate copies cannot be wiped. Swap refusal, no core dumps and a
  non-dumpable process are the mitigation for those copies — not erasure.
- Closing a `memfd` releases it; the kernel does not promise to scrub the pages. A
  child that inherited the descriptor by `fork` without `exec` keeps it alive.
- Suspend-to-disk (hibernation) writes RAM to disk and is not detected by the swap
  check.
- A host administrator, a VM snapshot, a compromised interpreter, or anything after
  the caller receives the value are out of scope.
- The `Secret` wrapper is a guard-rail, not a sandbox. `reveal()` deliberately
  exists, `secret._value` is reachable, and `os.write` on a descriptor, a C
  extension or another process are all outside what an in-process wrapper can
  police. `Vault.memory_file()` hands out a descriptor whose contents *are* the
  plaintext, by design, because that is how a secret is given to a child without a
  file. And because `open()` creates the file before `write()` fails, a refused
  write can still leave an empty file behind — what it cannot leave is the secret.
  If nothing may reach a filesystem at all, the control is environmental: run the
  process with a read-only filesystem or as a user with no write access outside a
  tmpfs.
- Importing a Python module may write `__pycache__` bytecode unless
  `PYTHONDONTWRITEBYTECODE` is set. No secret is ever in bytecode.
- The `vaultenv` command puts the fields it reads into a child's **environment**, because
  that is what an environment variable is. So any process running as the same user can read
  `/proc/<child-pid>/environ`, the child's own children inherit it, and a child that crashes
  can carry it into a core collected by a piped `core_pattern`. It is a convenience with a
  deliberately weaker boundary than `kubectl_vault`'s descriptor handover — see
  [Running a command with Vault environment variables](#running-a-command-with-vault-environment-variables).

The two lists in this section are the whole threat model: what this package guarantees, and
what it does not.

## Running kubectl with a Vault kubeconfig

The `kubectl_vault` command fetches a kubeconfig from Vault and runs kubectl with it,
without that kubeconfig ever existing as a file:

```bash
kubectl_vault --secret user_applications_and_services_team/cems_web \
              --field k8s-cems-test -n glofas-stage get pods
```

It is installed on `PATH` by `pip install ecmwf-vault` (`pyproject.toml` maps the
`kubectl_vault` script to `ecmwf_vault.commands.kubectl_vault:main`; that module is private, so the
command is the artefact and not an API). From an uninstalled checkout, run
`python -m ecmwf_vault.commands.kubectl_vault` with `PYTHONPATH=src` instead.

It seals the kubeconfig into an anonymous memory file and points kubectl at the
inherited descriptor with `--kubeconfig=/proc/self/fd/<n>`. **No named file is created**:
there is no path in any filesystem to find, and the kubeconfig is gone once the last
descriptor to it closes. kubectl does not inherit `ECMWF_VAULT_TOKEN`.

That is a statement about the kubeconfig the command fetches, not about kubectl. kubectl
is a trusted consumer here, and it is what ends up holding the credential: it *does* reopen
the descriptor — that is how it reads it — `exec` resets the non-dumpable protection this
package sets for its own process, a same-user process can read the descriptor through
`/proc` while kubectl holds it, kubectl may hand it on to its children, its output can
print the credential (`kubectl config view --raw`), and it writes its own discovery cache
to `~/.kube/cache` unless you pass `--no-kubectl-cache`. If any of that matters, isolate
the whole invocation — a container with a read-only root filesystem, or a separate
account — rather than relying on this command.

| | |
| --- | --- |
| `--secret PATH` | Vault path whose field holds the kubeconfig (required) |
| `--field NAME` | that field; the only field is used if you omit it |
| `--mount NAME` | Vault mount, if not the default `groups` |
| `--kubectl PATH` | kubectl to run, for a pinned version |
| `--no-kubectl-cache` | add `--cache-dir=/dev/null` (see below) |

Argument handling: everything after `--` goes to kubectl verbatim. Without `--`, any
argument the command does not recognise is passed through too, in order — so the example
above needs no separator, and
`kubectl_vault --secret X get pods --field-selector status.phase=Running` works.

Worth knowing:

- The descriptor is sealed against *writing*, not *reading*: sealing means the bytes cannot
  change, not that nobody else can look.
- Unlike `vaultenv`, the kubeconfig never enters kubectl's environment or argument list —
  but it *is* revealed in the `kubectl_vault` process, because a sealed file takes bytes.
- `kubectl config set-*` cannot work, because the descriptor is sealed read-only.
- `kubectl exec -it` and other interactive subcommands work: stdio is inherited.
- Exit status `2` means the command failed (arguments, or the secret). kubectl's status is
  otherwise passed through unchanged — and kubectl can return `2` itself, so the
  discriminator is stderr: the command's failures carry a `kubectl_vault:` prefix.

## Running a command with Vault environment variables

The `vaultenv` command reads a secret and runs a command with its fields as environment
variables, for that command only:

```bash
vaultenv --secret user_applications_and_services_team/cems_web/db -- psql
```

It is installed on `PATH` by `pip install ecmwf-vault` (`pyproject.toml` maps the
`vaultenv` script to `ecmwf_vault.commands.vaultenv:main`; that module is private, so the command
is the artefact and not an API). From an uninstalled checkout, run
`python -m ecmwf_vault.commands.vaultenv` with `PYTHONPATH=src` instead.

With no selection, every field of the secret becomes a variable of the same name. Usually you
want one field rather than all of them — and that is not only tidiness: the default mapping
has to name *every* field, so a secret holding a field called `k8s-cems-test` refuses the
whole run. Select what you need:

```bash
--field MY_TEST_ENV                     # just this field, under its own name
--set KUBECONFIG=k8s-cems-test          # just this field, renamed
```

Both options are repeatable and both select, so using them together is the union.

`ECMWF_VAULT_TOKEN` is removed from the command's environment, and no file is created.

| | |
| --- | --- |
| `--secret PATH` | Vault path whose fields become variables (required) |
| `--mount NAME` | Vault mount, if not the default `groups` |
| `--field NAME` | use only this field, under its own name; repeatable |
| `--set NAME=FIELD` | use only these fields, renaming them; repeatable |
| `--force` | overwrite variables the command already inherits |

**This wrapper is weaker than the kubectl one, and the difference is not cosmetic.** An
environment variable *is* plaintext in the command's memory, so there is no sealed
descriptor to hand over:

- any process running as the same user can read `/proc/<command-pid>/environ` for as long
  as the command lives, cooperating or not;
- the command's own children inherit the variables, and so does every program it execs —
  an environment cannot be scoped to a single `execve`;
- `exec` resets `PR_SET_DUMPABLE`, and this host pipes core dumps to a collector, where the
  kernel ignores `RLIMIT_CORE`, so a command that crashes can put these values into a
  collected core;
- anything that logs its environment will log these values.

So use it for values that are already environment-shaped and for short-lived commands, and
use `kubectl_vault` when the value can travel as a descriptor instead.

Two refusals, both deliberate:

- a field name that would overwrite a variable the command already inherits is an error
  unless you pass `--force`;
- a fixed list of well-known names is refused with no override, as is `ECMWF_VAULT_TOKEN`.
  Four different risks are covered, because a secret should decide none of them:
  what the command **runs** (`PATH`, `GIT_SSH_COMMAND`, the pagers and editors), which code
  it **loads** (`LD_PRELOAD`, `PYTHONPATH`, the Java/Node/Ruby/Lua startup hooks), what it
  **trusts** (the trust-store variables), and where it **writes key material**
  (`SSLKEYLOGFILE` — not code at all, and here because a secret that names that file undoes
  this package's whole promise).

That list is finite and **cannot** be complete: the command is your choice, and any program
may invent an environment variable that names a command — `GIT_SSH_COMMAND` was found by
review doing exactly that. The real boundary is not the list. In the default mapping the
secret's *field names* become variable names, so **whoever can write the secret chooses the
names**; `--field` and `--set` are how you take that choice back for yourself.

The name and collision refusals happen before any value is revealed, so they reveal nothing —
which is not the same as saying no plaintext exists by then, because fetching the secret has
already decoded it in this process. The value refusals — a field that is not text, holds a
NUL, or holds a lone surrogate no encoding accepts — can only be found by revealing, so
earlier fields in the same selection *are* revealed
before a later one is refused; what holds is that no partial environment is handed over and no
command is started, and that a field's text is never printed, only its name and type.

Worth knowing:

- Field values must be text. A JSON number or boolean is refused rather than stringified,
  because `str(True)` is `"True"` and a command expecting `"true"` would silently get the
  wrong thing; store the value as a string in Vault.
- A value containing a NUL byte is refused: no environment variable can carry one.
- Exit status is the command's own; `2` means the wrapper failed, and the wrapper's
  failures are the ones carrying the `vaultenv:` stderr prefix.

## Tests

Offline: a loopback HTTPS server with a throwaway certificate generated at test
setup. No test contacts `secrets.ecmwf.int`. Needs no installs:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t tests -v
```

With a coverage gate (needs `pytest`/`coverage`, which the host does not have).
Use `run --rm`, not `up`: podman-compose does not propagate the container's exit
code from `up --abort-on-container-exit`:

```bash
podman compose -f compose.test.yaml build
podman compose -f compose.test.yaml run --rm tests
```
