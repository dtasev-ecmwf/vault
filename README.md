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

The token comes from one place: `~/.ecmwf-vault/token` (see [Where the token comes
from](#where-the-token-comes-from)). The [`vault_login` command](#fetching-a-token-vault_login)
fills it: it reads a token from you without echoing it, checks it with Vault, and stores it
sealed.

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
from ecmwf_vault import Vault, cubbyhole_read, value

value(path)                                  # -> {field: Secret, ...}
value(path, field="password")                # -> Secret
value(path, cache=False)                     # fetch now, retain nothing
value(path, mount="kv", base_url="https://...")   # override for this call
cubbyhole_read(path)                        # the token's own cubbyhole; no mount

with Vault(mount="groups") as vault:         # your own cache and lifetime
    vault.value(path)["password"].reveal()
    vault.cubbyhole_read(path)               # same, through the cubbyhole engine
    vault.keys(path)                         # -> ('password', 'user'), no values
    memory = vault.memory_file(path)         # sealed fd, for a child process
    memory.close()
    vault.token_info()                       # the token's own ttl, policies, identity
```

The mount defaults to `groups`; `path` is everything after the mount, with no
leading slash. A cubbyhole path is everything after `cubbyhole`, and takes no mount.

## Configuration

Precedence: keyword argument, then environment variable, then built-in default.
The token itself has one source, described below.

| Setting | Env var | Default |
| --- | --- | --- |
| token file | `ECMWF_VAULT_TOKEN_FILE` | `~/.ecmwf-vault/token` |
| base URL | `ECMWF_VAULT_ADDR` | `https://secrets.ecmwf.int` |
| mount | `ECMWF_VAULT_MOUNT` | `groups` |
| CA bundle | `ECMWF_VAULT_CA_BUNDLE` | system trust store |
| timeout (s) | `ECMWF_VAULT_TIMEOUT` | `10` |
| swap policy | `ECMWF_VAULT_SWAP_POLICY` | `refuse` |
| process hardening | `ECMWF_VAULT_HARDEN` | `1` |

## Where the token comes from

One source: **`~/.ecmwf-vault/token`**, holding the token and nothing else, sealed with a
passphrase derived from your account.
[How the token file is sealed](#how-the-token-file-is-sealed) is what that means and what it is
worth; [`vault_login`](#fetching-a-token-vault_login) is how you fill it.

The token is resolved on **every call**, with nothing cached and nothing remembered, so replacing
the file — which is what a re-login does — takes effect on the next call and nowhere else.

There is one source. Nothing stale can outrank the file you just refreshed, and there is
nothing to choose between. `VAULT_TOKEN` — HashiCorp's own variable — is on the list of names a
secret may not set, because a Vault field that became that variable would authenticate the
child somewhere the secret was never about: see
[Running a command with Vault environment variables](#running-a-command-with-vault-environment-variables).

A file that is present and cannot be used is an error, never a quiet fallback. There is nowhere
else to go, which is the point: you are told the file is missing, unsafe or empty rather than
authenticated as something you did not choose.

### The file and its permissions

The shape is HashiCorp's `~/.vault-token`: a bare token, so there is no format for a mistake to
hide in. Nothing but surrounding whitespace is stripped — a trailing newline is fine, anything
else is judged as a token:

```console
$ printf '%s\n' 'hvs.CAESIJ...' > ~/.ecmwf-vault/token   # then chmod 600
$ vault_expiry                                          # shows which token was read
```

Writing it in the clear is a way in, not a mistake you are stuck with: a token found unsealed is
[sealed on the spot](#how-the-token-file-is-sealed) and the fact is printed. Two things come
before that. A file another user could reach is refused before it is opened, not repaired; and a
seal that cannot be written fails the read, because a credential this package cannot seal is one
it does not use.

Provision it without ever putting the token in your shell history:

```bash
install -d -m700 ~/.ecmwf-vault
read -rs -p 'Vault token: ' T; echo
printf '%s\n' "$T" | install -m600 /dev/stdin ~/.ecmwf-vault/token
unset T
```

A token file is only private if its permissions are, so the file is checked the way OpenSSH
checks a key and **there is no policy to relax that**: a symlink, a non-regular file, an
oversized file, a file owned by another user, or one readable or writable by group or other is
refused. **The directory holding it is held to the same rule** (`~/.ecmwf-vault` must be mode
700), because a directory another user can reach lets them list the file, replace it, or add one
beside it. A symlinked directory is resolved first, so what is judged is the mode of wherever the
file really lives. Errors name the mode required, never the content.

Everything else is read when a `Vault` is constructed; the module-level helpers keep at most eight
default instances, one per `(base_url, mount)` pair, evicting the least recently used.
`clear_cache()` forgets the secrets; `close()` is terminal — after it, the module-level helpers
raise, so a caller who has released a secret cannot have it silently re-fetched. Construct a
`Vault` for a new lifetime.

## How the token file is sealed

`~/.ecmwf-vault/token` holds the token encrypted with **gpg**, using a passphrase derived from
the account: the account name with `$` between its characters, then `_`, then the uid and gid
multiplied. For `madt` with uid 4509 and gid 5000 that is `m$a$d$t_22545000`.

**What that is not.** Every part of it is readable by anyone on the machine — the name and the
uid and gid are in the user database, world-readable — and the scheme is in this package. So
the sealed file is *not* a boundary against another user of the same host: whoever can read the
file can derive the passphrase and open it. What it buys is that the token is never a **string**
on disk. Searching a home directory, a backup or an image layer for `hvs.` finds nothing, a copy
of the file taken off the host needs this derivation and gpg rather than being the token itself,
and a file listing shows nothing worth looking at twice.

That is the trade a six-hour token makes worth having. Two consequences are worth knowing: a
copy of the file is recoverable by whoever knows the derivation and can read it, and a change to
the account's uid or gid renames the passphrase — the file then cannot be opened, and the answer
is to fetch a new token.

What it buys beyond that is that it works with nothing: the passphrase is handed to gpg on a
**pipe**, gpg runs `--batch` with its pinentry in loopback mode, and so there is no agent, no
terminal and no prompt. A `vaultenv` in a cron job can read a token that was never written down.

Three things follow from the format:

- **A token in the clear is sealed the next time anything reads it**, and the package says so on
  stderr when it does. Hand-writing the file — the `install -m600` recipe above, or `printf >
  ~/.ecmwf-vault/token` — is therefore a way in, not a permanent mistake. If the seal cannot be
  written, the token is refused: a credential this package cannot seal is one it does not use. Sealing
  rewrites the file, so a loose mode on a file in the clear is corrected to 600 as a side
  effect.
- **The mode is still the real control.** The file is checked the way OpenSSH checks a key, and
  the directory with it: a passphrase anyone can derive makes those checks matter *more*, not
  less. There is no policy that lets an accessible token file be used anyway.
- **gpg has to be there** — `gpg` or `gpg2` on `PATH` — for the token file to be readable at
  all. Where a gpg refuses loopback mode, `allow-loopback-pinentry` in `gpg-agent.conf` is what
  it wants; the package runs no agent of its own.

## Fetching a token: `vault_login`

A Vault service token lasts hours, so the one in `~/.ecmwf-vault/token` runs out while you are
working. `vault_login` is how it is replaced:

```console
$ vault_login
vault_login: Fetch your token by logging into https://secrets.ecmwf.int/. Once logged in, go to
the top right on your user icon and click, then in the menu "Copy token" and paste it here. The
token expiry date will be shown and it is stored encrypted
paste the token (it is not echoed):
vault_login: the token was stored encrypted at /home/madt/.ecmwf-vault/token; Vault says it
expires at 2026-11-14T21:00:00+00:00
```

It shows the address of the Vault it will check against — the configured one, so a login is
never pointed at one server while its token is checked against another — reads the token
**without echoing it**, checks it with Vault's own `auth/token/lookup-self`, and writes it
sealed only once that works. A paste that does not start with `hvs.` (one that is not a token
at all) is asked for again, and **a token Vault refuses is never stored**. There is no option
and no `--token`: the token file is wherever the library resolves it to, and a token on a
command line is a token in the process list.

Two refusals hold up the "without echoing it" part, because it is the point of the command:

- **It has to be run on a terminal.** With no terminal it stops and says so, rather than
  reading whatever is on stdin as though it were a paste — a pipeline or a `cron` job has
  nobody to ask.
- **If the terminal cannot turn echo off, it stops too.** `getpass` — which is what reads the
  paste — warns and then reads an ordinary, *echoed* line in that situation. A warning is not
  enough when the promise is that the token does not appear on screen, so the warning is
  turned into a refusal and the fallback reads nothing.

`vault_login` prints the expiry Vault reported for the token it stored:

```
vault_login: the token was stored encrypted at /home/madt/.ecmwf-vault/token; Vault says it
expires at 2026-11-14T21:00:00+00:00
```

The value is re-rendered, not echoed as Vault wrote it. `datetime.fromisoformat` accepts any
separator between the date and the time and any number of fractional digits, so what is printed
is the instant the value names, as one canonical ASCII timestamp. A value that names no instant
is not printed at all, so a response cannot put arbitrary text — which could be the token
itself — into that line.

### When a token runs out

Every command that reads a secret runs the same workflow around its operation, so a token that
has expired is replaced rather than ending in a 403. The order is the point:

1. the operation runs;
2. if Vault refuses it, the token is looked up once;
3. and only a token that **cannot be looked up either** is replaced, after which the operation
   is tried exactly once more.

Nothing is replaced *before* the operation. A token can be refused its own lookup and still be
allowed to do the work — a policy that does not permit `auth/token/lookup-self` — so a lookup
refusal is evidence about the lookup, not about the token. The refusal that matters is the one
the command's own request got: a token that can still describe itself is being told "not this
path", a policy refusal rather than an expiry, and the command's own error stands untouched.

Three things bound what that can fix, and each is said rather than worked around:

- **Asking needs a terminal.** A pipeline or a `cron` job gets the same explanation and fails,
  because a process with nobody at the keyboard must not wait for one. That is fine for `cron`:
  the sealed token file needs no prompt, so `vaultenv` runs unattended until the token runs out,
  and the failure then says what to run.
- **The retry happens once.** A second refusal is handed back, not asked about again.

That is the whole list, because there is one token source: replacing the file is always the
fix, and the only thing that can stop the command doing it is having nobody to ask.

A prompt cannot print the token it read, and neither can any message around it: the paste is
not echoed, the check is the library's own lookup (which withholds a token Vault reports as
`id`), and no diagnostic is built from the token — a refusal says the token was refused, not
what it was. As everywhere else here, the token is in the process's memory while it is used;
what this package keeps off disk is the *stored* form, and `~/.ecmwf-vault/token` is a sealed
file the moment it is written.

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
- **A malformed token is refused too.** What the token file holds must be printable
  ASCII with no space. A token containing a CR, LF, tab or a non-ASCII character is
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

- The token is a credential **on disk**, sealed rather than plaintext: that keeps it out of a
  search, a backup or an image layer as a *string*, but it is still reachable by anything
  running as you, and by root, and its privacy is the file mode and the directory mode. The
  passphrase that seals it is derived from your account name and identifiers, all of them
  world-readable, so sealing is not a boundary against another user of this host — see
  [How the token file is sealed](#how-the-token-file-is-sealed). Neither the file nor any other
  form survives a host that is fully compromised.
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
descriptor to it closes. kubectl is handed no Vault token either: this package reads the token
from the file and uses it only as a request header, and the environment passed to kubectl is
this process's minus `ECMWF_VAULT_TOKEN` — a name nothing here reads, but which an older copy of
this package running as the child still would.

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

No file is created: the variables exist only in the command's environment, and
`ECMWF_VAULT_TOKEN` is removed from what it inherits.

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
- a fixed list of well-known names is refused with no override. It covers five things a secret
  should decide nothing about: what the command **runs** (`PATH`, `GIT_SSH_COMMAND`, the pagers
  and editors), which code it **loads** (`LD_PRELOAD`, `PYTHONPATH`, the Java/Node/Ruby/Lua
  startup hooks), what it **trusts** (the trust-store variables), where it **writes key
  material** (`SSLKEYLOGFILE` — not code, and here because a secret naming that file undoes this
  package's whole promise), and whose **credential** it holds (`VAULT_TOKEN`, and the legacy
  `ECMWF_VAULT_TOKEN` name that the child's environment is otherwise scrubbed of — a field must
  not be able to put back what the scrub removes).

That list is finite and **cannot** be complete: the command is your choice, and any program may
invent a variable it reads as an instruction. The real boundary is not the list. In the default
mapping the secret's *field names* become variable names, so **whoever can write the secret
chooses the names**; `--field` and `--set` are how you take that choice back for yourself.

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

## Reading the token's own cubbyhole: `vault_cubby`

`vault_cubby` is `vaultenv` pointed at a different place. It takes a cubbyhole path instead of a
mount and a secret path, and behaves the same way otherwise:

```console
$ vault_cubby --path madt/efas --field DB_PASSWORD -- psql -U cems -h db.example.int
```

| | |
| --- | --- |
| `--path PATH` | cubbyhole path whose fields become variables (required) |
| `--field NAME` | use only this field, under its own name; repeatable |
| `--set NAME=FIELD` | use only these fields, renaming them; repeatable |
| `--force` | overwrite variables the command already inherits |

There is no `--mount`: the request is `/v1/cubbyhole/<path>`. The refusals are `vaultenv`'s —
same names, same rules, same functions rather than a copy of them.

It is installed on `PATH` by `pip install ecmwf-vault` (`pyproject.toml` maps the `vault_cubby`
script to `ecmwf_vault.commands.vault_cubby:main`; that module is private, so the command is the
artefact and not an API). From an uninstalled checkout, run
`python -m ecmwf_vault.commands.vault_cubby` with `PYTHONPATH=src` instead.

**A cubbyhole belongs to a token, not to a person, and not to the name in the path.** Three
consequences worth stating before you store anything there:

- only the token that makes the request can read it. Another token of the same account —
  a second login, a colleague's, a job's — gets nothing;
- its contents are **deleted when that token expires or is revoked**. `vault_login` replaces the
  token, and a replacement has its own, empty cubbyhole;
- a policy cannot widen it. Cubbyhole ignores ACLs by design, so there is no grant to ask for.

So it is a store for the lifetime of one login, and nothing longer. It is not a place to keep a credential
something else needs to read: for that, use a KV v2 path under a mount your token's policy
allows, which is what every other command here reads.

The Vault UI shows cubbyholes at a path like `/ui/vault/secrets-engines/cubbyhole/show/<you>/<x>`.
That is a console route, served by your browser's session, and it is not the API path; the UI
address of a cubbyhole says nothing about whether a service token can read it.

## Checking the token's expiry

The `vault_expiry` command reports the details Vault holds about the token you are using —
how long it lasts, what it may do, and what it identifies:

```console
$ vault_expiry
Vault token at https://secrets.ecmwf.int
  remaining ttl      7112 (1h 58m 32s)
  creation ttl       43200 (12h)
  explicit max ttl   0 (0s)
  issue time         2026-11-14T09:00:00.000000000Z
  expire time        2026-11-14T21:00:00.000000000Z
  renewable          yes
  uses remaining     unlimited
  token type         service
  display name       cems-read
  policies           cems-read, default
  identity policies  cems-read
  accessor           Qk3mExampleAccessor
  entity id          1f2e3d4c-0000-1111-2222-333344445555
  created by         auth/token/create
```

It reads `auth/token/lookup-self` — Vault's own endpoint for a token's details, at a fixed
path, so `ECMWF_VAULT_MOUNT` has nothing to do with it. Which token it reads is decided the
same single source as everywhere else here: `~/.ecmwf-vault/token`. There is deliberately no
`--token` option: a token on a command line is a token in the process list.

`--json` prints the response's metadata object itself — not the whole envelope with its
`data` wrapper, matching the way `value()` returns a secret's fields rather than the transport
detail around them — so the fields are at the top level (and `id` is substituted there too,
so piping this somewhere cannot leak the token):

```bash
vault_expiry --json | jq .ttl          # not .data.ttl
```

Three readings in that output are easy to get wrong, so the command adds a line each time one
applies: a token with **no expire time** reports a `ttl` of `0` because it does not end by
time, not because it is nearly over; a **non-renewable** token cannot be extended with
`auth/token/renew-self`; and a token with a **use limit** stops working when the uses are
spent, whatever the `ttl` says. Any field Vault returns that this command has not been taught
is printed too, under its own name, so the report never silently drops one — with a single
substitution. Vault reports the token's `id`, and for some token types that field **is the
token's value**; when it is, it is replaced by a fixed note rather than printed, because
this is a report you read on a terminal and token values do not belong in one. Use
`accessor` to identify a token: Vault documents it as safe to share, and it works for a
lookup or a revocation without revealing the token.

Two things about failing here. A **403 is about the token rather than about the path you
asked for**: a token that has expired or been revoked cannot look *itself* up, and a policy
that does not allow `auth/token/lookup-self` stops a perfectly good one too. The message names
both, and does not claim the list is complete. That is the case you want
it for — "is this token still any good?" is exactly the question to ask when something else
has just refused. And because a 403 here is a token that cannot describe itself, this command
is one of the ones that will offer to fetch a new token — see
[When a token runs out](#when-a-token-runs-out).

Exit status is `0` when the details were read and `2` when this command could not read them,
with the reason on stderr under the `vault_expiry:` prefix.

## Tests

Offline: a loopback HTTPS server with a throwaway certificate generated at test
setup. No test contacts `secrets.ecmwf.int` — and that is enforced, not just intended.
Importing `tests/_fakes.py` installs a guard that fails any name resolution or connection
to an address that is not this machine, so a test that forgets to pin `ECMWF_VAULT_ADDR`
cannot quietly reach the real Vault. There are two controls, because one alone has the wrong
failure mode: `block_network_layer()` also replaces what the guard falls through to, so a test
checking a refusal cannot send a packet *when the guard is the thing that broke*. Picking a
harmless-looking address is not that control — documentation space is not guaranteed unroutable,
and an unresolvable name still reaches a resolver. The commands are also run as fresh
interpreters, so `_loopback_guard.child_python_path()` installs the same guard at a child's
startup through `sitecustomize`; a test needing startup code of its own composes both with
`sitecustomize_dir()`, because CPython imports only the first `sitecustomize` on the path.
Needs no installs:

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
