# ecmwf-vault — design

Status: **draft v2 for review** (design stage; no code written yet). v2 amends v1 after the
first round of design-quality and security review — see §13.

## 1. Goal

A small, zero-dependency, Linux-only Python library that a script imports to read one
secret from the ECMWF Vault HTTP API (`https://secrets.ecmwf.int`, a Vault-compatible
KV v2 store) and keep the retrieved value **off disk for its whole lifetime**, using the
same techniques the AgMon MCP executor already uses for run credentials.

Target call site, exactly as requested:

```python
import os
os.environ["ECMWF_VAULT_TOKEN"] = "..."          # supplied out of band

from ecmwf_vault import value

password = value("user_applications_and_services_team/cems_web/k8s-cems-test",
                 field="password")
```

Acceptance criteria (used by the reviewers):

1. `value(secret_path)` returns the secret's fields; `field=` returns one field.
2. The Vault token comes from `ECMWF_VAULT_TOKEN` or a private config file (§20);
   `value()` raises a
   `RuntimeError` when it is missing or blank, **before any network call, path
   validation, or memory allocation**.
3. The secret is never written to a file, a temp file, a named shared-memory object,
   a log, an exception message, a `repr` of a library object, or a child process argument
   list.
4. Zero third-party runtime dependencies; imports and runs on CPython 3.9–3.14+.
5. Stdlib-only test suite, high coverage of the shipped modules.

## 2. Non-goals

- Not a general Vault client: no writes, no delete, no dynamic/leased credentials,
  no token renewal, no auth backends beyond a token supplied by the caller.
- Not a CLI and not a daemon; no caching across processes.
- Not a secrets manager: no rotation, no persistence.
- No cross-platform promise. The no-disk guarantee rests on Linux `memfd_create`,
  `/proc/swaps` and `prctl`; other kernels fail closed (see §8).

## 3. Prior art in this workspace (what we copy and what we do not)

| AgMon mechanism | Source | Reuse |
| --- | --- | --- |
| `SealedMemoryFile`: `memfd_create(MFD_CLOEXEC\|MFD_ALLOW_SEALING)`, `fchmod 0600`, write, `F_ADD_SEALS(WRITE\|GROW\|SHRINK\|SEAL)` | `agmon/mcp-server/lease_registry/memory.py` | Copied and hardened: write-all loop, size cap, `pread` reads, `dup`-based ownership |
| `require_no_swap()`: fail closed when `/proc/swaps` shows swap | `lease_registry/policy.py` | Copied; checked on **every** call, before transport |
| `harden_process()`: `RLIMIT_CORE=0` + `prctl(PR_SET_DUMPABLE, 0)` | `agmon/mcp-server/utils.py` | Copied, applied once before the first fetch, opt-out |
| Credential delivered to a child only as an inherited fd, never argv/env | `lease_registry/registry.py` | Kept as an exposed, explicitly owned capability (`memory_file`), not the default path |
| Strict JSON parse: duplicate-key rejection, allow-listed shape | `lease_registry/kubeconfig.py` | Copied for the Vault response envelope |
| Bounded output + deadline | `utils.bounded_output` | Copied as a response size cap + socket timeout |
| Container hardening, `logging: driver: none` | `mcp-server/compose.yaml` | Documented as deployment guidance for the CI/test container only |

Not copied: the run/lease/session model, scope policy, kubeconfig rewrite, MCP surface —
none of that applies to a per-call secret read.

## 4. Public API

`src/ecmwf_vault/__init__.py` exports:

```python
def value(path: str, *, field: str | None = None, mount: str | None = None,
          cache: bool = True, base_url: str | None = None) -> object: ...
def clear_cache() -> None: ...
def close() -> None: ...

class Vault:
    def __init__(self, *, base_url=None, mount=None, timeout=None,
                 swap_policy=None, harden=None, ca_bundle=None): ...
    def value(self, path, *, field=None, cache=True): ...
    def keys(self, path, *, cache=True) -> tuple[str, ...]:   # field names only
    def memory_file(self, path, *, cache=True) -> SecretMemoryFile: ...
    def clear_cache(self) -> None: ...
    def close(self) -> None: ...

# errors
class VaultError(RuntimeError): ...
class VaultTokenMissingError(VaultError): ...
class SwapPolicyError(VaultError): ...
class InvalidSecretPathError(VaultError): ...
class SecretNotFoundError(VaultError): ...
class VaultPermissionError(VaultError): ...
class VaultUnavailableError(VaultError): ...
class VaultResponseError(VaultError): ...
class SecretFieldMissingError(VaultError): ...
```

Module-level `value()/clear_cache()/close()` delegate to one lazily created **default
`Vault` instance**. `VaultError` subclasses `RuntimeError`, so the required "it
`RuntimeError`s" behaviour holds for the missing-token case and every other failure; the
subclass lets callers be more precise.

Return shapes (per the agreed answers):

- `value(path)` → `dict[str, object]` — every field of the KV entry, JSON types preserved
  (no silent string coercion; a JSON number stays a number).
- `value(path, field="password")` → the single field's decoded value.
- `keys(path)` → field names only, so a caller can discover shape without handling values.
- `value(path, cache=False)` → fetch now, retain nothing afterwards (§8).

### 4.1 Ownership rules (settled after review)

The cache lives **inside one `Vault` instance** — never process-global. `clear_cache()`
and `close()` affect only the instance they are called on; the module-level functions
affect the default instance only. Two `Vault` instances never observe each other's cache
(§8.3). This removes the "who owns the shared entry" ambiguity for `memory_file()`:

- `Vault.value()` never returns a descriptor; it returns decoded values only.
- `Vault.memory_file(path)` always returns a **caller-owned** `SecretMemoryFile`. For a
  cache hit it wraps a fresh `os.dup()` of the store's descriptor with `FD_CLOEXEC` set,
  so closing it cannot disturb the cached entry or any other caller. For `cache=False` it
  returns the only descriptor, and the caller must close it.
- `SecretMemoryFile.close()` is idempotent and, being the owner, the caller may always
  call it. The cache keeps its own descriptor and closes it on eviction or `Vault.close()`.
- A returned `SecretMemoryFile` is usable until closed; it is never invalidated behind the
  caller's back except by an explicit `Vault.close()`/`clear_cache()` on the cache's fd,
  which by construction is a different descriptor than the one handed out.

`SecretMemoryFile` (exported) is the sealed memfd holding the secret's canonical bytes:
`.fd` (int, for `subprocess(..., pass_fds=(fd,))` when a caller must hand the secret to a
child without a file), `.read() -> bytes`, `.close()`, plus `__enter__/__exit__`. Its
`repr` is `<SecretMemoryFile fd=N size=K sealed=True>` — never the payload.

## 5. Configuration

Precedence: explicit keyword argument > environment variable > built-in default.
The **token** is resolved at call time (environment, then a config file), never
cached, and never stored on the client, so a script can replace it at any point
and tests need no import ordering. The other settings are resolved when a `Vault`
is constructed; the module-level helpers construct their default instance on first
use, so setting `ECMWF_VAULT_ADDR`/`ECMWF_VAULT_MOUNT`/etc. before the first call
still works.

| Setting | Env var | Default | Notes |
| --- | --- | --- | --- |
| token | `ECMWF_VAULT_TOKEN`, else the config file | *required* | See §20; no `~/.vault-token` lookup, no prompt, no `token=` argument |
| config file | `ECMWF_VAULT_CONFIG` | `~/.ecmwf-vault/config` | Read only when the environment does not supply a usable token |
| config file permissions | `ECMWF_VAULT_CONFIG_POLICY` | `refuse` | `refuse` \| `warn` \| `allow`; no constructor argument, see §20 |
| base URL | `ECMWF_VAULT_ADDR` | `https://secrets.ecmwf.int` | Must be `https`; `http` is refused |
| mount | `ECMWF_VAULT_MOUNT` | `groups` | KV v2 mount name |
| CA bundle | `ECMWF_VAULT_CA_BUNDLE` | system trust store | Optional override; must be an existing regular file |
| timeout (s) | `ECMWF_VAULT_TIMEOUT` | `10` | Connect + read, applied to the socket |
| swap policy | `ECMWF_VAULT_SWAP_POLICY` | `refuse` | `refuse` \| `warn` \| `allow` |
| hardening | `ECMWF_VAULT_HARDEN` | `1` | `0` skips core-dump/dumpable hardening |

Rationale for a security control that an environment variable can relax: anything that can
set a variable in the process environment can already read `ECMWF_VAULT_TOKEN` from it, so
the policy variable grants no new capability — it only helps a developer who cannot change
the host. The relaxed settings emit a one-line warning to `stderr` (never to stdout) and
are recorded on the `Vault` instance so they show up in `repr`.

## 6. Secret path handling

- Request URL: `{base_url}/v1/{mount}/data/{path}` (KV v2 read endpoint).
- `path` is validated before any network use by a single strict predicate: non-empty,
  ≤ 512 bytes, segments split on `/`, each segment matching `[A-Za-z0-9._@+-]+`, no empty
  segment (so no `//`, no leading/trailing `/`), and no `.` or `..` segment. `mount` is
  validated the same way as a single segment. Anything else raises
  `InvalidSecretPathError` with the offending path quoted **only after** it has been
  length-clamped and control-character-escaped (a hostile path must not be able to inject
  newlines into a log).
- Values are URL-quoted when the request target is built, so the validated path can never
  change the request line, add a query, or smuggle a fragment.
- No `field` name ever reaches the URL; it is used only as a mapping key.

## 7. Transport

`http.client.HTTPSConnection` rather than `urllib.request`, deliberately:

- no proxy support, so `HTTPS_PROXY`/`ALL_PROXY` cannot redirect a token-bearing request;
- no automatic redirect following, so the token header cannot be replayed to another host
  (a `3xx` is treated as an error, not followed);
- explicit control of exactly one request per call.

Details:

- Context: assembled directly as `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with
  `verify_mode=CERT_REQUIRED`, `check_hostname=True`, `minimum_version=TLSv1_2`, the
  factory's `VERIFY_X509_PARTIAL_CHAIN | VERIFY_X509_STRICT` flags, and either
  `load_verify_locations(cafile=ca_bundle)` or `load_default_certs(Purpose.SERVER_AUTH)`.
  No `CERT_NONE`, no `check_hostname = False` anywhere. `ssl.create_default_context()` is
  deliberately *not* used, for the key-log reason below.
- **The key-log variable is never consulted, and the process environment is never
  touched.** CPython's `create_default_context()` **reads `SSLKEYLOGFILE` and opens the file
  it names while the context is being created**, so pinning `keylog_filename = None`
  afterwards is too late: an empty file is left on disk, and a value naming a missing or
  unwritable path makes context creation raise `FileNotFoundError`. A TLS key log is a
  plaintext record of the session key and would expose both the token and the secret in any
  captured session. The context is therefore assembled directly —
  `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`, which does not read the variable — so nothing
  has to be hidden from anyone, and no other thread can observe a temporarily missing
  variable or have its own value overwritten. (An intermediate revision did mask the
  variable around the factory call; review round 4 rejected that as process-global mutation.)
- **The factory's hardening is mirrored exactly, not approximated.** Assembling the context
  by hand silently dropped `VERIFY_X509_STRICT` and `VERIFY_X509_PARTIAL_CHAIN` (measured
  flags `32768` against the platform's `557088`), so `create_context()` reproduces the
  factory's own line,
  `verify_flags |= VERIFY_X509_PARTIAL_CHAIN | VERIFY_X509_STRICT`, by flag bit rather than
  by name: Python only exposes `VERIFY_X509_PARTIAL_CHAIN` from 3.10 and
  `VERIFY_X509_STRICT` from 3.13, but the bits are fixed in OpenSSL
  (`X509_V_FLAG_PARTIAL_CHAIN` `0x00080000`, `X509_V_FLAG_X509_STRICT` `0x00000020`), so
  the numbers are spelled out as fallbacks and a test pins them against the `ssl` constants
  wherever those exist. `PARTIAL_CHAIN` is used only when the linked OpenSSL is new enough to
  understand it — `ssl.OPENSSL_VERSION_INFO >= (1, 0, 2)`, the release that introduced
  `X509_V_FLAG_PARTIAL_CHAIN` (verified against the OpenSSL sources for 1.0.1, 1.0.2, 1.1.0
  and 1.1.1) — because a bit the library does not know would be a silent no-op.
  Both matter: without `STRICT` OpenSSL keeps its workarounds for broken certificates, and
  without `PARTIAL_CHAIN` a CA bundle holding an **intermediate** cannot be used as a trust
  anchor at all (OpenSSL then insists on a self-signed root in the store) — pinned by a
  three-certificate regression test. A test asserts that the assembled context is **never
  weaker than the running platform's factory** (no missing flag, option or cipher) rather
  than demanding equality: the factory only gained `PARTIAL_CHAIN`/`STRICT` over 3.13–3.14,
  so on 3.9–3.12 this package adds whichever of them exist, which is stricter than that
  platform's factory and is what a CA bundle holding an intermediate needs. A future Python
  that adds a flag makes the "never weaker" assertion fail rather than silently weakening
  this.
- `minimum_version = TLSv1_2` is set explicitly because the factory has not always raised it
  and the guarantee must not depend on the linked OpenSSL's default; `keylog_filename` is
  pinned to `None` as well.
- **A CA bundle replaces the trust store.** `create_context(ca_bundle=...)` loads that bundle
  *instead of* the system store, so an override cannot widen trust to every CA the host
  happens to know. A bundle that cannot be loaded is a fixed `VaultError`, never an `OSError`
  naming the path.
- One `GET /v1/{mount}/data/{path}` with `X-Vault-Token: <token>`, `Accept:
  application/json`, `Content-Length: 0`, `Connection: close`. No token in the URL or body.
- Response body read in bounded chunks, capped at 256 KiB (`MAX_RESPONSE`), so a hostile or
  broken server cannot exhaust memory. Body bytes accumulate in a preallocated
  `bytearray` that is **overwritten in place with zero bytes** of the same length before
  the call returns (§8.4).
- Status mapping, all without echoing the response body or the token:
  `200` → parse; `400` → `VaultResponseError`; `403` → `VaultPermissionError`;
  `404` → `SecretNotFoundError`; `429` → `VaultUnavailableError` (Vault standby health
  answers 429 per the workspace README); any other `4xx`/`5xx`/`3xx` →
  `VaultUnavailableError`/`VaultResponseError` as appropriate.
- Parse: strict JSON — reject duplicate object keys (`object_pairs_hook`), reject
  `NaN`/`Infinity` (`parse_constant` raises), require the envelope
  `{"data": {"data": {<field>: <json>}}}`. A missing/again-nested/wrong-shaped envelope is
  `VaultResponseError("unexpected Vault response shape")` — no fragments of the body.
- One request per `value()` call; the connection is closed in a `finally`.

## 8. Memory: the no-trace store

### 8.1 Order of operations

`Vault.value()` runs strictly in this order, so no secret exists in memory before the host
policy has been enforced:

1. resolve config (base URL, mount, timeout, policy) — no secret involved;
2. resolve the token: `ECMWF_VAULT_TOKEN`, else the config file (§20); a token that is
   nowhere, or present but not usable, raises `VaultTokenMissingError` /
   `VaultTokenInvalidError` / `VaultConfigFileError` (acceptance criterion 2), before any
   path validation or network call;
3. enforce policy: swap check **on every call, including cache hits**, plus one-time
   process hardening if enabled;
4. validate `path`/`mount` (§6);
5. cache lookup, keyed by `(base_url, mount, path)` **and bound to the token** (§8.3);
6. on a miss: check the interpreter can create a sealed memfd, fetch (§7), parse,
   serialize, seal into a memfd, store;
7. decode from the memfd and return.

Three ordering choices here are deliberate:

- The swap check moving ahead of the fetch is a v1 fix: in v1 the only check happened inside
  memfd construction, i.e. after the response had already been parsed into ordinary memory,
  which is too late to keep the plaintext out of swap.
- Token resolution precedes the swap check, even though it may read a file. The token is not
  the secret this package protects: it is already in the process environment (which
  `/proc/<pid>/environ` exposes and every child inherits) or already on disk in a 0600 file,
  in both cases before this code runs. Reading it earlier cannot page anything out that was
  not already pageable, and keeping it first is what makes "no token configured" win over an
  invalid `mount` (§8.1 step 2, pinned by a test).
- The interpreter capability check (§8.2) runs before the request, not only inside the store
  that needs it. A missing capability should be reported before the network call, which is the
  expensive, server-visible half of the operation, and having the secret in hand cannot make
  an interpreter able to seal. It checks for the *presence* of the API, not that sealing
  works: a sealing failure still aborts after the fetch, storing and returning nothing.

### 8.2 The sealed memory file

`SecretMemoryFile` holds the canonical secret bytes in a sealed, anonymous memfd.
`require_support()` refuses before anything else when the interpreter cannot do that
(§24), including before any request is made (§8.1).

1. `fd = os.memfd_create("ecmwf-vault-secret", MFD_CLOEXEC | MFD_ALLOW_SEALING)`.
2. `os.fchmod(fd, 0o600)`.
3. **write-all loop**: `os.write` may perform a short write, so the payload is written in a
   loop until every byte is accounted for; a short/zero write or any `OSError` closes the
   fd and re-raises. Without this, a partially written secret could be sealed and later
   returned as if complete.
4. `os.lseek(fd, 0, SEEK_SET)`.
5. `fcntl.fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)`
   — write, grow and shrink are refused afterwards, so the bytes cannot be altered once
   fetched and cannot be grown past what was written.
6. On any failure the fd is closed and the exception re-raised; `close()` is idempotent.

Reads use `os.pread(fd, size, 0)`, which does not move the shared file offset and works
even after sealing. The memfd has no name in the filesystem: it appears only as
`/proc/<pid>/fd/<n>` → `/memfd:ecmwf-vault-secret (deleted)`.

`memory_file()` hands out a `dup` of the descriptor with `FD_CLOEXEC` re-applied (`dup`
clears it), so an `exec` in a forked child does not inherit the secret unless the caller
deliberately passes it via `pass_fds` (§4.1).

Payload stored in the memfd is the **compact, key-sorted JSON serialization** of the field
mapping, not the raw HTTP body, so the store is canonical and re-parses deterministically.

### 8.3 Cache scope, ownership and authentication binding

- The cache is a dict on the `Vault` instance, behind a `threading.Lock`. There is no
  process-global cache, so two `Vault` instances cannot read each other's secrets and one
  instance's `close()` cannot invalidate another's.
- Each entry records a SHA-256 digest of the token that produced it. The token itself is
  never stored. On lookup the current token's digest must match the entry's; a mismatch
  **closes and evicts** that entry and refetches. This is a v1 fix: with caching keyed only
  by `(base_url, mount, path)`, swapping a privileged token for a different non-empty token
  would have returned the privileged value without the new token ever being authorized for
  it.
- The token is resolved on each call — from the environment, or from the config file when the
  environment does not supply a usable one (§20) — and held only for the duration of
  the request; it is deliberately not cached. Removing the environment variable therefore
  re-resolves the token: the next call uses the config file if one is configured, and raises
  `VaultTokenMissingError` only when neither source has a token. Note that this observes only
  the *local* sources: removing the environment variable does **not** revoke the token
  server-side, and a cache hit means no request is made, so server-side token expiry or
  revocation is not observed until an entry is evicted or a miss occurs.
- `cache=False` always fetches — even when an entry for the same key is already warm — seals
  the bytes, decodes them, then closes the memfd before returning: nothing is retained and
  nothing is disturbed. That is the point of the flag: it is how a caller observes a rotated
  value, a revoked or downgraded token, or a permission change, which a warm entry would
  otherwise mask.
- `clear_cache()`/`close()` close every retained descriptor. `close()` marks the instance
  unusable, so a later `value()` on it fails loudly instead of silently refetching. The
  module-level `close()` is terminal in the same way: it empties the default pool and marks
  the module-level helpers closed, and a later `value()` raises rather than building a fresh
  instance, because a caller who has released the secret must not have one silently
  re-fetched. A script that wants a new lifetime constructs a `Vault`.
- The default pool is bounded and least-recently-used (`MAX_DEFAULT_INSTANCES = 8`): each
  entry holds a `Vault` and its TLS context, so unbounded growth from many distinct
  `mount`/`base_url` overrides is not acceptable. Eviction **drops the pool's reference
  instead of closing the instance**, because another thread may already have selected that
  instance and be inside a call on it; closing it would fail that call for no reason the
  caller could see. The instance and its sealed descriptors are released when the last
  reference goes. A cached read still re-runs the swap check (§8.1 step 3) even though it
  performs no I/O with the secret.

### 8.4 Honest erasure boundaries

CPython gives no guarantee that a secret can be removed from a process's memory, and this
design does not claim otherwise:

- The response `bytearray` is overwritten in place with zero bytes (`buf[:] =
  bytes(len(buf))`, equal length, no reallocation) and then dropped. That is a real
  best-effort overwrite of *that* buffer.
- Everything the parser derives from it is a normal immutable Python object — the decoded
  `str`, the parsed `dict`, the re-serialized bytes, and the `dict` the caller receives —
  and **cannot** be wiped. The design's mitigation for those copies is the process posture
  (swap refused, core dumps disabled, process non-dumpable), not erasure.
- Closing a sealed memfd is resource release, not guaranteed zeroization: the kernel frees
  the pages when the last reference goes, and does not promise to scrub them first. A
  forked-without-exec child that inherited the descriptor keeps the pages alive until it
  exits. `Vault.close()` therefore reduces exposure, it does not erase history.
- Consequently the claim is "this library never writes the secret to disk; the cache holds
  only sealed memfd bytes", not "nothing survives the process" and not "zeroized".

Hardening applied once per process before the first fetch (skippable via
`ECMWF_VAULT_HARDEN=0`):

- `ctypes` `prctl(PR_SET_DUMPABLE, 0)` — the process cannot be ptraced or dumped by another
  same-UID process. This is also the control that actually stops a crash spilling the secret:
  `PR_SET_DUMPABLE`'s own documentation says the attribute "determines whether core dumps are
  produced for the calling process".
- `resource.setrlimit(RLIMIT_CORE, (0, 0))` — the belt to that brace, and a no-op on a host
  whose `core_pattern` pipes to a collector, because `core(5)` states plainly that
  "RLIMIT_CORE will be ignored if the system is configured to pipe core dumps to a program".
  Both are set, so the outcome holds either way; the distinction matters only to whoever
  considers removing one. The hard limit is set to zero rather than just the soft one, so a
  child cannot raise it back.
- **Neither survives `exec`.** The attribute is reset when a process executes (see §25.1 for
  what that means for the kubectl wrapper), so these protect *this* process, not its children.

Both fail closed (`VaultError`) if they fail while hardening is requested, matching AgMon.
The swap condition must remain true for the whole life of the process, not just at the
first call — that is why the check runs per call (AgMon's `policy.py` states the same
requirement).

Deferred, with rationale: `mlock`-ing the memfd pages. It would add defence beyond the
swap refusal, but needs `RLIMIT_MEMLOCK` headroom (often 64 KiB by default) and does not
cover suspend-to-disk; the swap refusal is the primary control, and this can be added later
without an API change.

## 9. Threat model — what this does and does not buy

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Secret written to disk by the library | memfd only; no temp files, no cache files, no logs | none from the library itself |
| Secret spilled by swap | refuse when `/proc/swaps` shows swap, checked per call | `allow`/`warn` policy, or a host that lies |
| Secret spilled to disk by suspend-to-hibernation | none | **not covered**: the swap check does not detect hibernation; documented, host-side control |
| Secret spilled by a crash | `PR_SET_DUMPABLE=0` — a non-dumpable process is not dumped at all — plus soft-and-hard `RLIMIT_CORE=0`, which is the effective control only where `core_pattern` writes files | none for *this* process; an `exec`'d child is dumpable again and a piped collector ignores the rlimit, so the kubectl wrapper's own crash is not covered (§25.1) |
| Secret spilled to disk by a TLS key log | the context is assembled without the platform factory, so `SSLKEYLOGFILE` is never read and its file is never created, and the process environment is never modified | none from the library |
| Verification hardening silently weakened | the factory's own `verify_flags` line is mirrored, with a parity test against a real platform context (round-4 fix) | none from the library |
| A CA bundle holding an intermediate unusable | `VERIFY_X509_PARTIAL_CHAIN` is set, pinned by a three-certificate regression test (round-4 fix) | none from the library |
| Secret read by another same-UID process | non-dumpable process; sealed fd is not on a filesystem; `F_SEAL_WRITE` | root, a compromised interpreter, a same-UID process that inherited the fd via `fork` without `exec` |
| Secret read by snapshot/backup of the running VM | none | out of scope, as AgMon states |
| A caller writes the secret to disk by accident | every `value()` result is a non-`str` `Secret`: file writes, `writelines`, binary writes, `json.dumps`, pickle/copy, environment assignment and child-process arguments/environment all refuse, and rendering masks | `reveal()`, `_value`, `os.write`, `memory_file()` (whose descriptor is plaintext by design) and the empty file `open()` leaves behind; §22.5 |
| A secret passed to a child process is read or retained by that child | only the descriptor handover is controlled (no environment, no argument, no named file); the child is a trusted consumer | **not covered**: sealing prevents modification, not reading; `exec` resets non-dumpability, so a same-user process can read the descriptor through `/proc` while the child holds it; the child may pass it on or print it; §25.1 |
| Token read by another same-UID process (environment form) | *not* mitigated — it arrives in the environment, which `/proc/<pid>/environ` exposes to the same UID | inherent to supplying it in the environment; documented |
| Token inherited by a child process (environment form) | none — children inherit the environment by default | documented; the config-file form avoids it (§20.4) |
| Token read by another same-UID process (config-file form) | mode 600 enforced, non-regular/symlink refused, no other user's file accepted | a same-UID reader can read it, and it persists in backups/snapshots; documented |
| Privileged cached value served to a different token | cache entries bound to the token digest; mismatch evicts and refetches | none from the library |
| Token text quoted by a header-validation exception | the token must be printable ASCII with no space; anything else is refused before transport, so `http.client` can never raise `ValueError`/`UnicodeEncodeError` carrying it (round-2 fix) | none from the library |
| A response field whose text cannot be encoded | `ensure_ascii=True`, so a lone surrogate is stored as an escape and no exception can quote the mapping (round-2 fix) | none from the library |
| A stale value served as if it were current | `cache=False` always fetches, even over a warm entry | none from the library, once the caller asks |
| Token replayed to another host | no proxies, no redirect following, https-only base URL, ASCII host | none from the library |
| Secret leaked via error/log/`repr` | every error message is a fixed string; no library `repr` prints values | a caller that prints the returned `dict` (documented) |
| Hostile or broken Vault | strict JSON, envelope allow-list, 256 KiB cap, socket timeout | a compromised `secrets.ecmwf.int` |
| Mutation between read and use | `F_SEAL_WRITE` on the store | none |

Explicitly out of scope: a host administrator, a VM snapshot or hibernation image, a
compromised Python interpreter, and anything after the caller receives the decoded value
(a plain `dict` in the heap). This mirrors the boundary AgMon states in its own README's
"Security boundary" section.

## 10. Layout, packaging, compatibility

```
ecmwf-vault/
  DESIGN.md
  README.md                     # usage + threat model + how to run tests
  pyproject.toml                # setuptools, PEP 621, no runtime deps
  src/ecmwf_vault/
    __init__.py                 # public API + default Vault
    _errors.py                  # VaultError hierarchy
    _policy.py                  # swap policy + process hardening
    _memory.py                  # SecretMemoryFile
    _paths.py                   # validation + URL building
    _transport.py               # HTTPS GET + strict parse
    _client.py                  # Vault: config, fetch, cache, thread lock
    py.typed
  tests/
    test_memory.py  test_policy.py  test_paths.py
    test_transport.py  test_client.py  test_no_disk.py
    _fakes.py                   # loopback TLS server + throwaway certs
  compose.test.yaml             # optional pytest+coverage gate (host has neither)
```

Compatibility (CPython 3.9–3.14+):

- `from __future__ import annotations` everywhere; no `X | Y` at runtime; no `match`; no
  `tomllib`; `typing` forms (`Optional`, `Dict`, `Tuple`, `List`) in annotations.
- Relies on `os.memfd_create` (3.8+), `os.MFD_*`, `fcntl.F_ADD_SEALS`/`F_SEAL_*`,
  `os.pread`, `os.dup`, `resource`, `ctypes` — all present on the target Linux guests
  across that range. Non-Linux or a kernel without `memfd_create` raises
  `VaultError("ecmwf-vault requires Linux memfd_create")` rather than falling back to a
  disk- or shm-backed store.
- `ssl.VERIFY_X509_PARTIAL_CHAIN` (3.10+) and `ssl.VERIFY_X509_STRICT` (3.13+) are not
  assumed to exist: the flag bits are spelled out (`0x00080000`, `0x00000020`), with the
  OpenSSL 1.0.2 condition applied to `PARTIAL_CHAIN`, and pinned against the `ssl` constants
  where they do exist. On 3.9 the assembled context is therefore neither weaker than that
  interpreter's factory nor missing the intermediate-anchor behaviour the design promises.
- 3.9 has no `dict | dict`; not used. `str.removeprefix` (3.9) avoided for clarity.

## 11. Tests (stdlib `unittest`, high coverage)

Every test is offline: a loopback HTTPS server with a throwaway cert generated at test
setup via the `openssl` CLI into a temp dir (no committed key material), plus
`unittest.mock` for the policy hooks. No test contacts `secrets.ecmwf.int` or any network
beyond `127.0.0.1`. The `openssl` CLI is a *different* build from the interpreter's linked
OpenSSL, so the fixtures pass certificate extensions through `-config`/`-extensions` rather
than `-addext` (which only arrived in CLI 1.1.1). The suite must run with no installs:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t tests -v
```

(`tests/` is a flat, importable directory so `_fakes` resolves; the exact command is pinned
in `README.md` and CI. `coverage`/pytest are only needed inside `compose.test.yaml` for the
coverage gate, because the host has neither.)

| File | Pins |
| --- | --- |
| `test_memory.py` | fd is an anonymous sealed memfd (`readlink` contains `/memfd:ecmwf-vault-secret`); `write` after sealing raises `OSError`; `pread` returns exact bytes; short writes are retried (patching `os.write` to write 1 byte at a time still yields the whole payload); a mid-construction failure closes the fd; `close` is idempotent; `dup` ownership — closing a handed-out `SecretMemoryFile` leaves the cached entry readable; `repr` contains no payload bytes |
| `test_policy.py` | swap detected → refused by default; `warn` and `allow` proceed; hardening calls `setrlimit`/`prctl` once and raises when they fail; `ECMWF_VAULT_HARDEN=0` skips; the swap check runs before the network — with swap forced on the fake server records zero requests, for both a cold and a warm cache |
| `test_paths.py` | accepts the requested example path; rejects `..`, `%2e%2e`, `//`, leading `/`, trailing `/`, empty, over-long, control chars, `?`, `#`, spaces, non-ASCII (and does so without raising an encoding error that quotes the path); mount validation; a non-ASCII base URL host; URL building quotes correctly |
| `test_config.py` | token precedence (the environment wins, a blank environment value falls through, a malformed one never does, the file is re-read per call, the default path found through a redirected `HOME`, an explicitly named missing file is an error, no token anywhere fails before any request); every refusal (0644/0660/0667 refused, `warn`/`allow` opt-outs, another owner, a symlink under every policy, a directory, a FIFO without blocking, an oversized file, a file that grows during the read, non-UTF-8, unreadable); parser behaviour (comments, blank lines, CRLF, a literal `#`, duplicate key, unsupported key, quoted value, malformed line, empty value); and that no raised message ever contains the token |
| `test_transport.py` | request line is exactly `/v1/groups/data/<path>`, `X-Vault-Token` is sent, `Accept` is JSON; `302` is an error and the header is not re-sent; `400/403/404/429/500` map to the right error class; duplicate-key JSON, `NaN`, wrong envelope, non-mapping `data.data`, and an oversized body are all rejected; no body fragment appears in any error message; `SSLKEYLOGFILE` is never read and no file is created whatever it names, and the process environment is untouched; the context keeps the platform's `VERIFY_X509_*` flags, options and ciphers; a bundle holding an intermediate is usable as a trust anchor; a CA bundle replaces the trust store and fails with a fixed error; a lone-surrogate field parses |
| `test_client.py` | dict return; `field=` return; unknown field; `mount=`/`base_url=` overrides; `cache=True` sends exactly one request for two calls; `cache=False` sends two, and still fetches over a warm entry (rotation, and a 403 seen uncached) without disturbing the cache, for `value()`, `keys()` and `memory_file()`; module-level overrides keep their own cache, bounded to the cap with LRU eviction (distinguished from FIFO by request counts), an evicted instance released rather than closed, and a held instance still usable after eviction; a token change evicts and refetches (privileged entry is not served to a second token); two `Vault` instances do not share entries; `clear_cache`/`close` behaviour, the terminal module-level `close()` and post-close failure; missing and blank `ECMWF_VAULT_TOKEN` raise `RuntimeError` **and open no socket** (server records zero hits); a missing token wins over invalid configuration; a malformed token is refused before any request and never appears in `str`, `repr` or a formatted traceback; a lone surrogate field round-trips; 40 concurrent reads over more mounts than the cap all succeed |
| `test_no_disk.py` | with `tempfile.*` and every write-mode `os.open`/`open` instrumented to fail, and a `TMPDIR` snapshot before/after, a full cold and warm `value()` creates no file; reads of `/proc/swaps` and the CA bundle are allowed and expected; `SecretMemoryFile`/`Vault`/error `repr`s contain no secret bytes (the *returned* `dict`'s contents are out of scope by design, §8.4) |

Coverage achieved: 100% of statements and branches across every shipped module
(`_client`, `_errors`, `_memory`, `_paths`, `_policy`, `_transport`), measured with
`coverage.py --branch`; 164 tests. `compose.test.yaml` gates at 99% so a small
environment-specific gap cannot fail a legitimate run.

## 12. Open questions deferred to the implementer (not blocking review)

- Whether `keys()` is worth its API surface versus `value(path).keys()`.
- Whether to add an `ECMWF_VAULT_VERIFY=0` escape hatch for a broken CA — currently
  rejected on purpose; the CA bundle override covers the legitimate case.

## 13. Changes since review round 1

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: `memory_file()`/cache ownership undefined | §4.1 ownership rules; cache is instance-private; `memory_file()` hands out a `dup` with `FD_CLOEXEC`; `cache=False` returns the only, caller-owned descriptor |
| terra BLOCKER: single `os.write` can short-write and seal a partial secret | §8.2 step 3 write-all loop; `test_memory.py` short-write pin |
| terra BLOCKER: test plan asserted `repr` of returned values and "no regular file opened" | §11 reworded: library objects only; reads allowed, writes forbidden; added the `PYTHONPATH=src` no-install command |
| sol HIGH: `SSLKEYLOGFILE` can write TLS secrets to disk | §7 key-log pinning; `test_transport.py` pin; §9 row |
| sol HIGH: cache survived an authentication-identity change | §8.3 token-digest binding, instance-private cache, evict-and-refetch; `test_client.py` pins; corrected the "unsetting env revokes" wording |
| sol MEDIUM: swap check happened after the plaintext was parsed | §8.1 re-ordered: token, then policy+swap (per call, incl. cache hits), then path, then fetch; §8.4 keeps AgMon's "swap must stay off during operation" |
| sol MEDIUM: erasure overclaims (`buf[:] = b""`, "zeroize", "nothing survives") | §8.4 honest boundaries: in-place zero overwrite, immutable copies acknowledged, close is release not erasure, fork/hibernation residuals; §8.2 no longer says "zeroize"; §9 residuals corrected |

## 14. Implementation notes (deviations from the reviewed design)

Implemented in `src/ecmwf_vault/`, 100 tests, 100% statement and branch coverage.
Everything the two reviewers asked for is in the code; these are the places where
the implementation made a further choice the design did not pin down:

1. **§5 configuration timing.** Only the token is read per call. Base URL, mount,
   timeout, CA bundle, swap policy and hardening are resolved when a `Vault` is
   constructed (the module-level default instance is constructed on first use).
   Re-reading them per call would buy nothing and would make the cache key
   unstable. §5 has been corrected to say this.
2. **§7 envelope detail.** A KV v2 response with `data.data` *absent* is a
   `VaultResponseError` (a shape we do not understand), while `data.data: null` —
   the deleted/destroyed-version case — is a `SecretNotFoundError`. The design
   mentioned only the second case.
3. **§8.1 hardening is split** into `harden_now()` (the raw calls) and
   `harden_process()` (run once), so both the once-only behaviour and the failure
   paths are testable in isolation. Internal only.
4. **§8.3 concurrency.** The instance lock is held across the fetch, so an instance
   performs at most one in-flight request; concurrent callers on one instance
   serialise rather than duplicate a fetch. Callers wanting concurrency use
   separate instances. `memory_file()` hands out an `os.dup()` with `FD_CLOEXEC`
   re-applied, so closing a returned object never disturbs the cache.
5. **§4 module-level `value(mount=..., base_url=...)`.** Default instances are
   memoised per `(base_url, mount)` pair, so overrides cache exactly like a
   hand-built instance. (An earlier revision used a throwaway instance per call
   with an override, which silently defeated caching; review round 2 rejected it.)
6. **§8.2 `_adopt`.** `duplicate()` wraps the descriptor without copying the
   payload, so handing out a descriptor is one syscall and no extra secret copy.
7. **Optional `fcntl` import** in `_memory` (and a lazy `resource`/`ctypes` import
   in `_policy`), so `import ecmwf_vault` succeeds on a non-Linux interpreter and
   fails closed with `VaultError("ecmwf-vault requires Linux memfd_create")` at the
   point of use. Every host this is deployed to is Linux; the import contract in
   §10 now holds anyway rather than relying on that.
8. **§11 test harness.** `unittest` only, so the suite runs with zero installs;
   `pytest`/`coverage` appear only in `Dockerfile.test`/`compose.test.yaml`. The
   throwaway TLS identity is generated once per test process (an `openssl
   rsa:2048` key per test made the suite 20x slower) and the fake server polls for
   shutdown every 20 ms, which took the suite from 29 s to 1.5 s.
9. **`ECMWF_VAULT_CA_BUNDLE`** name kept as designed; it is the only way to point
   at a private CA, and `ECMWF_VAULT_VERIFY=0` remains deliberately unimplemented
   (§12).
10. **`py.typed`** is shipped, and `pyproject.toml` declares no runtime
    dependencies, so an install cannot drag a transitive one in.
11. **Error messages never echo the input.** The design (§6) allowed the offending
    path to be quoted in `InvalidSecretPathError` after clamping and escaping; the
    implementation simply never includes it, which removes the injection surface
    entirely. Path-length counting also uses characters rather than
    ``path.encode()``, so a hostile path cannot make `_paths` raise a
    `UnicodeEncodeError` that quotes it.
12. **`VaultTokenInvalidError` was added** to the error hierarchy for a token that
    is present but cannot be a header value (§15). It is the one error class the
    reviewed design did not list.

## 15. Changes since review round 2 (implementation review)

Both reviewers rejected the first implementation. Every finding was accepted and
fixed; none was disputed.

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER + sol MEDIUM: `cache=False` returned a warm cached value and did not fetch | §8.3: the flag now short-circuits the lookup, always fetches, and never disturbs the entry; `test_client.py` pins a warm-cache rotation, a 403 seen uncached, and `keys()`/`memory_file()` with `cache=False` |
| terra BLOCKER: module-level `value(mount=..., base_url=...)` never cached despite `cache=True` | §4: default instances are memoised per `(base_url, mount)` instead of a throwaway per call; `clear_cache()`/`close()` act on all of them; `test_client.py` pins one request for two identical override calls and separate caches per override |
| terra BLOCKER + sol HIGH: `ssl.create_default_context()` reads `SSLKEYLOGFILE` and creates its file before the pin | §7: the context is now built from `SSLContext(PROTOCOL_TLS_CLIENT)` with explicit `CERT_REQUIRED`/`check_hostname`/`TLSv1_2` and `load_default_certs`/`load_verify_locations`, so the variable is never read. `test_transport.py` builds a context *under* the variable, asserts no file, asserts an unusable path cannot break a read, and asserts `create_default_context` is not called |
| terra BLOCKER: with no token and an invalid mount, the config error won | §8.1: the module-level `value()` checks the token before any instance is constructed; regression test covers missing-token + bad mount and missing-token + `http://` base URL |
| sol HIGH: a malformed token leaked through `http.client`'s header-validation exception | §7/§6: `_read_token()` now requires printable ASCII with no space (new `VaultTokenInvalidError`), so no header exception can be raised at all; tests assert no request, and that `str`, `repr` and the formatted traceback contain no token, for CR, LF, space, tab, DEL, non-ASCII and NUL |
| sol HIGH: a lone surrogate in a response field made `json.dumps(ensure_ascii=False).encode()` raise `UnicodeEncodeError`, whose `repr` carries the whole mapping | §8.2: the stored payload is serialized with `ensure_ascii=True` and encoded as ASCII, so the surrogate becomes an escape and round-trips losslessly; `test_client.py` and `test_transport.py` pin a secret field beside a surrogate |
| sol (implied): non-ASCII base URL host | §6: the host must be ASCII, refused with a fixed message instead of an IDNA `UnicodeError` naming the host |

## 16. Changes since review round 3

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: module-level `close()` let a later `value()` silently create a fresh default | §8.3: `close()` now sets a module-level closed flag and `value()` raises `VaultError` rather than rebuilding; `clear_cache()` and a repeated `close()` stay safe. The test class reopens the API explicitly (white-box) because the documented behaviour is terminal |
| terra BLOCKER + sol MEDIUM (high impact): the hand-built context dropped `VERIFY_X509_STRICT` / `VERIFY_X509_PARTIAL_CHAIN` | §7: back to `ssl.create_default_context()`, with `SSLKEYLOGFILE` removed from the environment under a lock for the one call and restored afterwards. Measured on this host: hand-built flags `32768` vs the platform's `557088`. `test_transport.py` now asserts `verify_flags`, `verify_mode`, `check_hostname`, `minimum_version`, that no platform option is omitted, and cipher-list parity against a reference context |
| terra BLOCKER: the default-instance pool grew without bound (including `cache=False` calls and failed reads), and `clear_cache()` left TLS contexts resident | §8.3: the pool is capped at `MAX_DEFAULT_INSTANCES = 8` and least-recently-used, evicting and closing the oldest; `test_client.py` pins the bound, the eviction order and reuse |
| sol (side finding, accepted): an unusable CA bundle surfaced as an `OSError` naming the path | §7: a fixed `VaultError` instead; tested with a missing path and a malformed file |

## 17. Changes since review round 4

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: masking `SSLKEYLOGFILE` in `os.environ` is process-global mutation an unrelated thread can observe or have overwritten | §7: the environment is no longer touched at all. The context is assembled directly again, now mirroring the factory's own `verify_flags` line (`PARTIAL_CHAIN | STRICT`, each constant looked up individually) so it is neither weaker nor version-drifted, with a parity test against a real platform context. Neither rejected fix is reintroduced: the flags are pinned by tests in both directions |
| terra BLOCKER: pool eviction could close an instance another thread had already selected | §8.3: eviction drops the pool's reference instead of closing the instance, so an in-flight caller is unaffected; the sealed descriptors close when the last reference goes. Pinned by a `weakref`-based release test and, in `test_memory.py`, by a collection-closes-the-descriptor test |
| terra BLOCKER: pool tests did not distinguish LRU from FIFO and claimed reuse of an evicted entry | `test_client.py` now fills the pool, touches the oldest entry, inserts one more, and asserts (with request counts) that the *touched* entry survives and the second-oldest is evicted; plus a `ThreadPoolExecutor` test over more mounts than the cap |
| terra (round 3, still open): a trusted intermediate CA must work | `test_transport.py` generates a root/intermediate/leaf chain, serves the leaf and trusts only the intermediate — which verifies only with `PARTIAL_CHAIN` |

## 18. Changes since review round 5

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: the parity assertion demanded *equality*, which fails on CPython 3.12 where the factory does not yet set `PARTIAL_CHAIN`/`STRICT` | `test_transport.py` now asserts the invariant that matters — nothing the platform sets may be missing — and separately that the flags this package promises are present. §7 documents the cross-version intent: on a Python whose factory lacks these, adding whichever exist is stricter, never weaker |
| terra BLOCKER: no deterministic test that a selected instance survives eviction (the weakref and concurrency tests would both pass if eviction closed it) | `test_client.py::test_an_instance_selected_before_eviction_still_works` holds the default instance, forces eviction by filling the pool, then asserts the held instance is not closed and still serves its cached value |
| terra BLOCKER: §7 and §8.3 still described factory construction and closing eviction | Both sections updated to the assembled context and to eviction dropping the pool's reference |

## 19. Changes since review round 6

Both findings concern the same `verify_flags` line: the constants are now spelled out, and
the OpenSSL condition that gates `PARTIAL_CHAIN` is at the right version.

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: `ssl.VERIFY_X509_PARTIAL_CHAIN` does not exist before CPython 3.10 (nor `VERIFY_X509_STRICT` before 3.13), so on 3.9 the intermediate-anchor guarantee was silently dropped and the new test raised `AttributeError` | Neither constant is named unconditionally. `_PARTIAL_CHAIN`/`_X509_STRICT` are `getattr` over `ssl` with the OpenSSL bits (`0x00080000`, `0x00000020`) as fallbacks; a test pins those numbers against the `ssl` constants wherever they exist; the other tests reference the module constants, so nothing touches an attribute 3.9 lacks |
| terra BLOCKER: the OpenSSL guard was then set at 1.1.1, but `X509_V_FLAG_PARTIAL_CHAIN` has existed since 1.0.2, so on OpenSSL 1.0.2/1.1.0 the guarantee was still silently disabled | `_PARTIAL_CHAIN_SINCE = (1, 0, 2)`, compared at use time against `ssl.OPENSSL_VERSION_INFO`, with a boundary test over 1.0.1 (omitted), 1.0.2, 1.1.0 and 3.5 (applied). The provenance was verified by fetching `x509_vfy.h` from the OpenSSL 1.0.1, 1.0.2, 1.1.0 and 1.1.1 branches: `PARTIAL_CHAIN` is `0x80000` from 1.0.2 on (absent in 1.0.1) and `X509_STRICT` is `0x20` in all four, which also confirms the spelled-out constants |
| terra BLOCKER: the certificate fixtures used `openssl req -addext`, which the CLI only gained in 1.1.1, so TLS tests failed to set up on a host with an older CLI | `tests/_fakes.py` now passes extensions through a generated `-config` file and `-extensions` (understood from 1.0.0), for the self-signed identity, the chain root and the CSRs; no `-addext` or `-subj` remains. §11 records why |


## 20. Token sources (environment, then a private config file)

Requested after the first review cycle: the token should be able to come from
`~/.ecmwf-vault/config` at mode 600, like an ssh key, instead of only from the
environment. This section is the design of that change; §21 records what its own
review round found.

### 20.1 Precedence

`ECMWF_VAULT_TOKEN` (environment) → `~/.ecmwf-vault/config` → error.

Environment first, for two reasons: it is what HashiCorp's own CLI does
(`VAULT_TOKEN` overrides `~/.vault-token`), so it is the least surprising order;
and it means a caller that already supplies the variable — including any CI or
systemd unit wired up before this change — keeps working untouched, with the file
purely additive.

The token is resolved **per call**, never cached, so unsetting the variable or
replacing the file takes effect on the next call. That is the same rule the
environment-only version already followed.

- A source that is **absent or blank** falls through to the next one.
- A source that is **present but cannot be a token** is an error, never a silent
  fall-through. Quietly using a different credential than the one supplied is the
  same class of surprise as the cache bug review round 2 found.
- A file **named explicitly** by `ECMWF_VAULT_CONFIG` and missing is an error; the
  *default* path being absent means "not configured", so an environment-only caller
  never notices this feature exists.

### 20.2 File format

`KEY=VALUE` lines, parsed as data and never executed:

- blank lines and whole-line `#` comments are ignored;
- CRLF is accepted; surrounding whitespace on the key and the value is trimmed;
- the value is taken **literally** — a quoted value is refused with an explicit
  message rather than guessed at, because a token can legitimately contain a quote
  and stripping one would silently corrupt it;
- an inline `#` is part of the value, not a comment, for the same reason;
- only `ECMWF_VAULT_TOKEN` is recognised today. Any other key is refused: a setting
  you believed was in force because you put it in the file would otherwise silently
  come from the environment or a default. Adding `ECMWF_VAULT_ADDR`/`MOUNT`/etc. to
  the file later is additive;
- the same key twice is refused, matching the duplicate-JSON-key rule in §7;
- a token from the file passes exactly the same header-safety validation as one from
  the environment (§7): printable ASCII, no space. A newline cannot even be
  represented in this format, and is refused either way.

Parse and validation errors carry the **line number and nothing else**. A malformed
file can put a secret in the key position (a token on a line with no `=`), so
echoing the offending text would defeat the whole point.

### 20.3 File permissions

A config file is only as private as its permissions, so the file is treated the way
OpenSSH treats a private key — refused rather than used:

- **Unconditional refusals**, whatever the policy: a **symlink** (opened with
  `O_NOFOLLOW`, so this cannot be raced), a **non-regular file**, and a file over
  64 KiB (checked both on `fstat` and again while reading, since a file can grow in
  between). `O_NONBLOCK` is part of the open flags so that opening a FIFO returns
  immediately instead of blocking before the regular-file check can reject it.
- **Policy-governed**: ownership (`st_uid == geteuid()`) and group/other access
  (`st_mode & 0o077`). The rule is deliberately "not reachable by group or other" rather
  than "exactly 0600", which is the same rule OpenSSH applies to a private key: it accepts the
  strictly safer read-only 0400 and the merely unusual 0700, and refuses 0640/0666. A literal
  0600 check would refuse 0400 and push a careful user to *loosen* their file.
  `ECMWF_VAULT_CONFIG_POLICY` is `refuse` by default, with `warn` and `allow` as deliberate
  opt-outs, mirroring the swap-policy idiom; **both** relaxed modes warn once on `stderr`, so
  there is deliberately no silent insecure mode — exactly as for the swap policy, where
  `allow` warns too.
  0600 is what the docs, the provisioning recipe and the error message ask for, and both
  accepted variants are pinned by tests.
- All checks read the **descriptor**, not the path, so there is no window between
  checking and reading.

Unlike the swap policy there is no constructor argument for this policy, and no
`token=` argument either: the token source is deliberately not client state, and a
token argument would invite `Vault(token=sys.argv[1])` and put the credential back
into `ps`. `ECMWF_VAULT_CONFIG` and `ECMWF_VAULT_CONFIG_POLICY` are environment
only.

### 20.4 What this costs, stated plainly

The *token* now lives on disk in a long-lived file, which is a real step back from
"the token is only ever in the environment". It is the same posture as
`~/.ssh/id_ed25519` (a 0600 private key on disk) and it is the posture the Vault CLI
itself uses, but it is a trade, not a free win:

| | environment variable | 0600 config file |
| --- | --- | --- |
| Readable by a same-UID process | yes (`/proc/<pid>/environ`) | yes (it is your file) |
| **Inherited by child processes** | **yes, by default** | no |
| Leaked while *setting* it | easily: shell history, `ps`, CI `set -x` | no |
| **Persists on disk** | no | **yes**: backups, snapshots, stale copies |
| Rotation | edit every place it is set | one file |

The guarantee that matters is unchanged and must stay unambiguous in the docs: **the
secret fetched from Vault still never touches disk.** The token is a credential the
caller already had, and where it lives is the caller's choice, now offered in two
forms rather than one.

Non-goals: no writing, creating or rotating the file (a provisioning recipe lives in
the README); no `~/.vault-token` lookup; no interactive prompt; no other keys from
the file yet.

## 21. Changes since review round 7 (the token-source feature)

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: the README provisioning command wrote the bare token, which the parser rejects as malformed | The recipe now writes `printf 'ECMWF_VAULT_TOKEN=%s\n' "$T" \| install -m600 /dev/stdin …`, and §1 and §8.3 no longer claim the token comes only from the environment. Verified by running the documented snippet in a scratch `HOME` and resolving a token through the resulting file: mode `0600`, correct content, `resolve_token()` returns the provisioned value |
| terra BLOCKER: the mode check accepts 0400/0700, which is not literally 0600 | Kept as "not reachable by group or other" (`st_mode & 0o077`), which is the rule OpenSSH applies to a private key, and is now stated explicitly in §20.3 and the README rather than implied. A literal 0600 check would refuse the strictly safer read-only 0400 and push a careful user to loosen their file, so the deviation is deliberate; 0400, 0600 and 0700 are pinned by tests as accepted, and 0640/0604/0660/0666/0607 as refused |
| terra BLOCKER: tests that assume there is no config file only patched `HOME`, so an inherited `ECMWF_VAULT_CONFIG`/`_POLICY` could change them; and `test_config.py` restored the environment in the wrong order | `_fakes.vault_environment()` now removes every variable this package reads, points `HOME` at an empty directory and then applies the caller's overrides, restoring the original environment atomically; it replaces the ad-hoc `patch.dict` blocks plus the hand-written save/restore. `_fakes.make_vault()` also pins `mount` and `timeout`, and the setUps isolate the environment *before* constructing anything, because a `Vault` built under an inherited variable is not the one the test means to build. Proven by running the whole suite with a real `~/.ecmwf-vault/config` present plus `ECMWF_VAULT_TOKEN`, `ECMWF_VAULT_CONFIG`, `ECMWF_VAULT_CONFIG_POLICY=allow`, `ECMWF_VAULT_MOUNT`, `ECMWF_VAULT_ADDR`, `ECMWF_VAULT_TIMEOUT=not-a-number`, `ECMWF_VAULT_SWAP_POLICY` and `ECMWF_VAULT_HARDEN` all exported: no failures |
| terra BLOCKER: `DESIGN.md` §8.3, the module docstring and the module-level `value()` docstring still described the token as environment-only, contradicting the implemented precedence | All three now say the token is resolved from the environment *or* the config file, and §8.3 states that removing the environment variable re-resolves the token — the file if one is configured, `VaultTokenMissingError` only when neither source has one — rather than always raising |
| terra BLOCKER: §20.3 promised that both relaxed permission policies warn, but `allow` was silent | `check_permissions` now warns once for `warn` **and** `allow`, mirroring `_policy.enforce` for the swap policy, and the message names the policy in force. §20.3 says there is deliberately no silent insecure mode; a test asserts both policies accept a 0644 file, warn, and name the policy |

**Feature status.** Both reviewers approved the token-source feature: the security reviewer
after reviewing the mechanism (`& 0o077` descriptor checks, symlink/non-regular refusal,
bounded parser, shared header validation), the design reviewer after the six findings above
were fixed. 164 tests, 100 % statement and branch coverage, and the suite passes even under a
deliberately hostile inherited environment.

## 22. The `Secret` wrapper (0.2.0)

Requested after the token-source feature: "if the user attempts to just write out the
value to disk it would also error". This is that restriction, and this section is also
the record of what it cannot do, because over-trusting a guard-rail is worse than not
having one.

### 22.1 What is enforceable, and what is not

Nothing in-process can *prevent* a determined caller from putting a value on disk: the
keystrokes are theirs, and `os.write` on a descriptor, a C extension or another process
are all outside anything a library can police. What is enforceable is refusing to be the
*easy* source of it, so the accident fails loudly:

- `open(path, "w").write(value(path))`
- `json.dumps(settings)` after a secret was mixed into `settings`
- `os.environ[...] = secret`, `subprocess.run([..., secret])`, `env={...: secret}`
- `pickle.dumps(secret)`, which would produce the plaintext as bytes

Each of those needs a real `str` (or, for pickle, a reducible object), so that is the
handle to remove.

A log line is the one route that is *not* refused, because it does not need the text: it
formats, so `logger.info("password=%s", secret)` writes `<Secret>` into the log instead
of failing. That is the outcome to want, and §22.2 explains why raising there would only
break ordinary code.

### 22.2 Why not a `str` subclass, and why not a raising `__str__`

The obvious implementations both fail, and the reason is the same in each case:
`TextIOWrapper.write` accepts any `str` **subclass** and copies its data without ever
calling `__str__`. So a subclass whose `__str__` raises still lets
`handle.write(secret)` succeed silently, which is precisely the case being guarded.
The return value therefore has to be an object that is **not** a `str` at all, so that
`write` raises `TypeError` on the type check.

Rendering is then *masked* (`<Secret>`) rather than raising. An f-string or a log line
formats whatever it is given, so the only thing either can carry to a disk is the literal
`<Secret>`; refusing instead would make ordinary code fail without keeping anything else
off disk.

### 22.3 What is covered

`Secret` wraps any JSON payload (a string, number, boolean, null, list or mapping), and
`value(path)` returns a mapping whose values are all `Secret`s, so no route returns
plaintext. It refuses: file writes in text, binary and `writelines` form; `json.dumps`
of the secret or of any structure containing it; pickle and `copy`/`deepcopy` (both
would yield the plaintext as bytes); assignment into `os.environ`; child-process
`argv` and `env`; `len`; concatenation; and `join`. It does not forward string
methods, so `secret.split(...)` is an `AttributeError`.

**Rendering masks rather than refusing**, and that distinction matters when reading
this section: `str()`, `repr()`, `f"{secret}"`, `"%s" % secret`, `"{}".format(secret)`
and a `logging` handler all produce `<Secret>` rather than raising. A rendering *can*
reach a disk — `handle.write(f"{secret}")` succeeds — but all it can write is the mask.
Only routes that need the real text to write with, serialise with or pass to a process
are refused.

`encode()` is implemented for the sole purpose of raising with a pointer at
`reveal()`: hashing is the one string operation callers reach for often enough that a
bare `AttributeError` would teach nothing.

`__eq__` and `__hash__` delegate to the wrapped value, so `secret == expected` and
`secret` as a set member still work. Comparison reveals nothing, and forcing every
comparison through `reveal()` would push callers to reveal far more often than they
need to. The test suite compensates deliberately: assertions go through
`_fakes.revealed()`, so a test cannot pass merely because a `Secret` compares equal to
the value a test expected, which is exactly how an API change like this one hides.

### 22.4 `memory_file()` is the sanctioned bypass

A caller who wanted to write the secret out in order to give it to a child process
should use `Vault.memory_file()` plus `pass_fds`, which is an inherited descriptor and
creates no file. That descriptor's contents *are* the plaintext, so it is a deliberate
hole in the guard-rail, not an oversight; the alternative would be to remove the only
safe way to hand a secret to a subprocess.

The way out has to come from the documentation, not from the error. Only the refusals
this package raises itself — `encode()` and pickling — can name `reveal()`.
A file write, a serialiser or a child-process argument fails inside CPython with its own
generic `TypeError` (`write() argument must be str, not Secret`), and an object cannot
improve a message it does not raise.

### 22.5 Honest limits

- `reveal()` exists, and `secret._value` is reachable. This is a guard-rail.
- `open()` creates or truncates the file *before* `write()` raises, so a refused write
  can leave an empty file behind. What it cannot leave is the secret; the tests assert
  both halves.
- `memory_file()`, `os.write`, C extensions and other processes bypass it.
- The only control that actually keeps a secret off a filesystem is environmental: a
  read-only root filesystem, or a user with no write access outside a tmpfs.
- 0.2.0 is a breaking release: every caller needs `.reveal()`.

### 22.6 Tests

`tests/test_secret.py` pins the refusals (text, binary and `writelines` writes, JSON,
pickle, copy, environment, child process argv and env, `len`, concatenation, `join`,
`encode`), the masking (all rendering forms, nested in a collection, every JSON payload
type), comparison, hashing and truthiness. `tests/test_no_disk.py` pins the headline
case end to end — a write to a real file raises `TypeError` and leaves the file empty —
and `tests/test_client.py` pins that both `value()` shapes return `Secret`s and that
`json.dumps` of a whole field mapping raises.

### 22.7 The careless-caller survey

The claim "the accident fails" was checked by trying it, not by reasoning about it: each
route below was run with a canary string and the destination inspected for the canary.

| Route | Outcome | Canary on disk |
| --- | --- | --- |
| `open(p,"w").write(secret)` | `TypeError` | no |
| `open(p,"wb").write(secret)` | `TypeError` | no |
| `open(p,"a").writelines([secret])` | `TypeError` | no |
| `print(secret, file=stream)` | renders `<Secret>` | no |
| f-string, `"%s" % secret`, `"{}".format(secret)` | renders `<Secret>` | no |
| `logging` through a real `StreamHandler` | renders `<Secret>` | no |
| `json.dumps(secret)` and `json.dumps({"pw": secret})` | `TypeError` | no |
| `pickle.dumps(secret)`, `copy.deepcopy(secret)` | `VaultError` | no |
| `csv.writer(f).writerow([secret])` | **succeeds**, writes `<Secret>` | no |
| `sqlite3` insert as a parameter | `ProgrammingError` | no |
| `pathlib.Path(p).write_text(secret)` | `TypeError` | no |
| `os.environ[...] = secret` | `TypeError` | no |
| `subprocess.run([..., secret])` and `env={...: secret}` | `TypeError` | no |
| `os.write(fd, secret)` | `TypeError` | no |
| `ValueError(secret)` and its formatted traceback | `str(exception)` is `<Secret>` | no |

Two outcomes are worth recording rather than glossing over. `csv` stringifies its fields,
so it writes a literal `<Secret>` instead of raising — safe, but silent, and the caller
plainly did not get what they wanted. And an exception carrying a `Secret` renders masked
in the traceback, which is a property worth having: the failure path cannot become the leak.

## 23. Changes since review round 8 (the `Secret` wrapper)

| Finding (reviewer / severity) | Change |
| --- | --- |
| terra BLOCKER: assertions could still pass through `Secret.__eq__` — the warm-cache rotation test compared a wrapper directly, and `_fakes.revealed()` did not check what it was given | The rotation assertion calls `.reveal()`. `_fakes.revealed()` now raises when a value is not a `Secret` at all (so a test cannot quietly stop checking the wrapper) and when revealing one yields another `Secret` (so a double-wrapped value cannot hide); both are pinned by `RevealedHelperTests` and were verified by hand |
| terra BLOCKER: §22.4 claimed the refusal message points at `reveal()`/`memory_file()`, but a direct file write raises CPython's generic `TypeError` | §22.4 now says the way out must come from the documentation: only the refusals this package raises itself (`encode()`, pickling) can name `reveal()`, and an object cannot improve a message it does not raise |
| terra BLOCKER: four places described rendering as a refusal, though `%s`-formatting, `format` and logging mask instead | `_secret.py`, `__init__.py`, `_client.Vault.value`, `DESIGN.md` §22.3 and the README now separate the two: rendering shows `<Secret>`, and only routes that need the text itself are refused. `%`-formatting was removed from every refusal list |
| terra BLOCKER (follow-up round): the same two mistakes survived in four more places — the `_secret` module docstring (it grouped `logger.info` with routes that need a real `str`, and claimed the refusal names `reveal()`/`memory_file()`), §22.1's route list, §22.2, §22.3 ("a rendering cannot reach a disk") and the README's intro | All corrected, and the *inverse* error too: a rendering **can** reach a disk — `handle.write(f"{secret}")` succeeds — it can only ever write the mask. §22.1's list is now split, with the log line named as the one route that is *not* refused and a pointer to §22.2 for why. A repo-wide grep for both phrasings is clean, which is what should have been run the first time |

**Feature status.** Both reviewers approved the `Secret` wrapper: the security reviewer judged
that no blocking plaintext-leak path remains in the accidental-disclosure scope, and the design
reviewer after the assertion and documentation findings (six across two rounds) were fixed.
180 tests, 100 % statement and branch coverage.

Note what those two rounds changed: one test assertion, one assertion helper and documentation.
The implementation of the wrapper did not change after it was written. The second round exists
only because the first pass fixed the instances it was pointed at instead of grepping for the
mistake, which is worth recording as a process point rather than a code one.

## 24. The interpreter capability check

Found not by review but by a user: on RHEL 8 with a **conda-forge** Python, every read
failed with `ecmwf-vault requires Linux memfd_create`. That message was true and
useless — it sent the reader to the operating system when the problem was the
interpreter.

The diagnosis, from the failing machine (`lfcb-008`, kernel 4.18, glibc 2.28):

| Probe | Result |
| --- | --- |
| `os.memfd_create` | absent |
| `os.MFD_CLOEXEC`, `os.MFD_ALLOW_SEALING` | absent |
| `fcntl.F_ADD_SEALS`, `fcntl.F_SEAL_*` | absent |
| `glibc` exports `memfd_create` | yes |
| `memfd_create` syscall from that kernel | works (`/memfd:probe (deleted)`, seals applied) |
| its `pyconfig.h` | `#define HAVE_LINUX_MEMFD_H 1`, `/* #undef HAVE_MEMFD_CREATE */` |

conda-forge builds Python against an old glibc sysroot, so the build never saw
`memfd_create` (added in glibc 2.27) and never defined the `fcntl` seal constants
either. The kernel and the runtime glibc are both fine. Nothing about this is RHEL 8,
and upgrading the environment's Python does not fix it.

### 24.1 The check

`missing_support()` reports **every** missing feature rather than the first, because
they arrive together; `require_support()` raises with a message naming them, the
interpreter and its version, the kernel release, the usual cause, and the one-line probe
that tells the reader whether a candidate interpreter has the support. It runs in
`SecretMemoryFile.__init__` *and* before the request in `Vault._fetch_into_memory`, so a
missing capability is reported before the network call — the expensive, server-visible
half of the operation. It checks for *presence of the API*, not that sealing works: a
sealing failure still aborts after the fetch, storing and returning nothing, which is
what §24.2 means by "the cost of not having the fallback is a clear error rather than a
lost guarantee".

The message is a fixed template; the only interpolated values are the interpreter path
(sanitised so a control character cannot reshape the log), its version and the kernel
release. No path, request or secret is echoed.

### 24.2 What was deliberately not done

The obvious fix is a fallback: call the `memfd_create` syscall through `ctypes` and pass
`F_ADD_SEALS`/`F_SEAL_*` as the numeric constants `1033`/`0xF`, since the kernel accepts
both regardless of what the interpreter's modules expose. I prototyped it and it works on
this host — created, sealed, write refused with `EPERM`. It was **not** adopted for now:
it adds a second creation path to the most security-critical module for the sake of one
environment's build, and the cost of not having it is a clear error message rather than a
lost guarantee. The runtime check and the diagnosis are what was asked for; §24.1 is
therefore the whole of the change.

Non-goals of this check: it does not probe whether sealing *works* (the tests do), and it
does not fall back to a named shared-memory object or a file, either of which would break
the promise the package exists to make.

## 25. The kubectl wrapper (`examples/kubectl_vault.py`)

Requested once the package worked end to end: fetch a kubeconfig from Vault and hand it
to kubectl. This is the use case the sealed memory file was built for — it is exactly
what the AgMon executor does with a lease's kubeconfig — so the wrapper is small and the
interesting decisions are about what *not* to add.

### 25.1 How the kubeconfig reaches kubectl

`--kubeconfig=/proc/self/fd/<n>` with the descriptor inherited through
`subprocess(pass_fds=...)`. No *named* file is created: there is no path in any
filesystem to find, and the kubeconfig is gone once the last descriptor to it closes.
Verified against the real kubectl 1.32.11, not only against a stand-in: `kubectl config
view --minify -o json` returns the kubeconfig the wrapper fetched, which is the assumption
the whole wrapper rests on (and the reason one test uses the real binary).

**Correction, from security review.** An earlier draft of this section said there is "no
file for kubectl to reopen", which was wrong and was caught: kubectl *does* reopen the
descriptor, because that is how it reads the kubeconfig at all. The honest statement of
the boundary is narrower than it looked:

- Sealing is integrity, not confidentiality. `F_SEAL_WRITE` stops the bytes changing; it
  does not stop the owner reading them. While kubectl holds the descriptor, a process
  running as the same user can read it through `/proc/<kubectl-pid>/fd/<n>`.
- `exec` resets `PR_SET_DUMPABLE`. The hardening §8.4 applies to *this* process is gone the
  moment kubectl starts, and the wrapper cannot set it for a program it does not control.
- `pass_fds` keeps our own close-on-exec flag intact and clears it for the child, but that
  only governs the handover: kubectl may hand the descriptor to its children, and “the
  same user can read it while it is open” remains true.
- `RLIMIT_CORE=0` is inherited, which is not a universal guard against a piped core
  collector.
- kubectl's own behaviour is outside the wrapper: `kubectl config view --raw` prints the
  credential, authentication plugins or a caller-chosen `--kubectl` can do what they like
  with it, and its discovery cache lands in `~/.kube/cache` unless `--no-kubectl-cache` is
  given.

So the guarantee is: **the wrapper never creates a named file, and never hands the
credential to a child through the environment or an argument list.** Everything past
handover belongs to kubectl, which is a trusted consumer. If the residual exposure matters
— a shared account, a hostile co-tenant, an audit requirement — isolate the invocation
(a container with a read-only root filesystem, a separate account) rather than expecting an
in-process wrapper to provide it. There is no code fix short of not running kubectl.

The wrapper seals the *revealed field text* in its own `SecretMemoryFile` rather than
using `Vault.memory_file()`: that call returns the memfd holding the canonical JSON of
the whole field mapping (`{"k8s-cems-test": "apiVersion: v1..."}`), which is not a
kubeconfig. `memory_file()` stays the right call for a child that can parse that JSON.
The plaintext is briefly a Python `str` either way — the field is a JSON string and the
caller must have it — so this is not a new exposure, just an honest note that the
wrapper is a `reveal()` call with a well-understood consumer.

### 25.2 Decisions worth recording

- **Argument handling.** Everything after `--` goes to kubectl verbatim; without `--`,
  anything the wrapper's parser does not recognise is passed through. The parser is
  built with `allow_abbrev=False`, because without it a kubectl flag that prefixes one
  of ours — `--field-selector` against `--field` — would be swallowed silently. That is
  a trap worth one line of code and one test.
- **The child environment.** `ECMWF_VAULT_TOKEN` is removed before kubectl runs. The
  README already argues that a file-held token is better than an environment one because
  an environment variable is inherited by children; that argument is worth honouring
  even when the token came from the environment, and kubectl has no use for it.
- **Exit status.** kubectl's own, so the wrapper composes in pipelines. `2` is reserved
  for the wrapper failing (bad arguments, unreadable secret), `127` for kubectl missing,
  following the shell's convention.
- **No new package API, and no console script.** The wrapper lives in `examples/` and is
  run with `PYTHONPATH=...src`. Adding a `kubectl-vault` entry point would mean the
  package publishing a command whose usefulness depends on an install that this host
  cannot do anyway (§24: site-packages is read-only), and the wrapper needs no library
  change at all.
- **Limits, in the wrapper's own docstring** so a user meets them before the surprise:
  the descriptor is sealed, so `kubectl config set-*` cannot work; kubectl writes its
  discovery cache to `~/.kube/cache` unless `--no-kubectl-cache` is given (that cache is
  API discovery, not credentials); interactive subcommands work because stdio is
  inherited.

### 25.3 Testing

Fourteen black-box tests run the wrapper as a subprocess, the way a user does: the
descriptor in argv, the contents kubectl actually receives, the token absent from
kubectl's environment, nothing left in the working or temporary directory, field
selection (only field, several fields, unknown field), a non-text field, argument
pass-through including `--field-selector`, exit-status pass-through, a missing kubectl,
a Vault failure, an interpreter without `memfd_create`, missing arguments and `--help`.

The library's 100 % statement-and-branch gate covers `src/ecmwf_vault` only; `examples/`
is deliberately outside it, and its behaviour is pinned through its real command line
rather than by in-process unit tests. That is stated here so the 100 % figure is not read
as covering the example.

The test image had to learn about `examples/`: `Dockerfile.test` copied `src/` and
`tests/` only, so all fourteen wrapper tests failed inside the container ("can't open
file '/app/examples/kubectl_vault.py'") while every library test passed. The gate caught
it, which is the point of running the gate — and it is worth recording that the failure
mode was a *silent* one on the host: on a machine with the repository checked out, the
wrapper is simply there.

## 26. Changes since review round 9 (the wrapper)

| Finding (reviewer / severity) | Change |
| --- | --- |
| sol BLOCKER: the descriptor handoff was described as if kubectl could not reopen it; `exec` resets non-dumpability, a sealed memfd is readable by the same user through `/proc` while any descriptor is open, `pass_fds` does not constrain onward inheritance, `RLIMIT_CORE=0` is not a universal guard, and kubectl's own output or plugins can print or persist the credential | Corrected in the wrapper's docstring, the README and §25.1 — with the correction written *into* §25.1 rather than silently edited, because the wrong version is the intuitive one. The guarantee is narrowed to what is true: **the wrapper creates no named file and hands the credential to no child through the environment or an argument list**; everything after handover belongs to kubectl as a trusted consumer. Added a §9 row stating the residual exposure, and "isolate the invocation" as the answer if it matters |
| terra BLOCKER: `Dockerfile.test` did not copy `examples/`, so the wrapper's tests could not run in the container | Fixed (§25.3 records it; the container gate found it before review reported it). Gate now runs the wrapper tests too: 206 passed, 1 skipped (no kubectl in the image) |
| terra BLOCKER: the recommended candidate-interpreter probe named three of the eight required features, so a build missing `F_SEAL_GROW` would print True and mislead | `_probe_command()` now *generates* the one-liner from `_FROM_OS` and `_FROM_FCNTL`, so it cannot drift from the check that produced the message. Tests assert every required name appears in it, and that the command actually prints True on this interpreter |
| terra BLOCKER: the README said the wrapper leaves nothing in `~/.kube` while also saying kubectl writes its discovery cache there, and claimed exit status 2 was exclusively the wrapper's | Both corrected: "no *named* file" is stated precisely, the cache is named as kubectl's, and the docs now say kubectl can itself return 2 so stderr's `kubectl-vault:` prefix is the discriminator. A test pins that kubectl's own 2 passes through unaltered and unprefixed |
| terra (side finding): `test_nothing_is_left_behind_in_the_working_or_temporary_directory` passed even when the wrapper never ran — which is precisely how it passed in the container before `examples/` was copied in | The test now asserts the wrapper exited 0 and produced its output before checking the directory |

### 26.1 The boundary, measured on the host

Sol's finding was verified rather than taken on trust, because the corrected wording is a
*security claim* and a wrong correction in either direction is worse than the original error:

| Probe | Result |
| --- | --- |
| The parent (an ancestor of the holder) reads `/proc/<pid>/fd/<n>` of a live child holding the sealed canary | **read the canary** |
| An independent same-user process — a sibling, not an ancestor — does the same | **read the canary** |
| `kernel.yama.ptrace_scope` | `0`, so nothing restricts same-user `/proc` access here |
| The holder after `exec` | dumpable again (`NoNewPrivs: 0`), i.e. §8.4's `PR_SET_DUMPABLE` does not survive |

So the "same user can read it while it is open" statement is not a hedge: on this host it is
unconditionally true for any process running as that user. Where `ptrace_scope` is `1` the
non-ancestor case would be refused by the kernel, but the holder's *ancestor* — which is what
the wrapper is — still reads it, and that is the case that matters for `pass_fds`.

The `RLIMIT_CORE=0` half is worth stating precisely as well, since it is inherited and can
look like a stronger guarantee than it is: our own process is both non-dumpable and
core-limited, but `exec` resets the dumpable flag, and where `core_pattern` pipes to a
collector the kernel ignores `RLIMIT_CORE` altogether. A crashed kubectl is therefore not
covered by §8.4, which is why §25.1 lists it as a residual rather than a mitigation. (The
hard limit is also set to zero, not just the soft one, so a child cannot raise it back —
that is the part §8.4 does buy.)
The `exec` question was settled the same way, because the man pages are ambiguous about a
*plain* exec and the whole correction depends on it (`PR_SET_DUMPABLE`'s page says the flag is
reset when credentials change, i.e. for set-uid/set-gid and file-capability binaries):

| Probe | Result |
| --- | --- |
| Parent calls `PR_SET_DUMPABLE=0`, then `exec`s a plain child with the sealed descriptor (`kubectl` is a plain 0755 binary with no file capabilities) | parent reports `PR_GET_DUMPABLE: 0`; the `exec`'d child's `/proc/<pid>` is **owned by the user**, i.e. dumpable again; an independent same-user process read the canary from `/proc/<child>/fd/<n>` |
| Control: parent leaves itself dumpable, same child | identical — canary read, `/proc` owned by the user |

So the finding stands as reviewed and the documentation is not understating it either: an
`exec`'d consumer is dumpable however carefully the parent hardened itself, and the descriptor
it holds is readable by any process running as that user on this host. That is why §25.1 now
says "the wrapper creates no named file and hands the credential to no child through the
environment or an argument list" and nothing more.
