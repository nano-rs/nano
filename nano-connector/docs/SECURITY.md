# nano-connector: threat model and red-team brief

This file is the target brief for nano-red. It covers the entry points, the
trust boundaries, the assets, what is already tested, and where to push. It
describes the engine crate (`nano-connector/`). The service around it
(scheduler, PG checkpoints, Vector HEC sink) is a separate lane, and the
brief notes where that lane must hold up its end.

## 1. What the engine does

A connector is a YAML spec plus an optional VRL `program`. One run, for one
tenant, does this:

1. Compile the spec and check every template.
2. Resolve the allowlist against the tenant's `config`, then apply the
   platform and tenant egress deny lists.
3. Spawn one sandboxed VRL worker per program stream. Every program compiles
   in its worker before any request is sent.
4. Loop through these steps:
   - build the request;
   - apply auth (the engine holds the secrets);
   - send it through the broker;
   - redact secrets from the response;
   - give the response to the VRL worker, or to declarative extraction;
   - dedupe and cap the events;
   - send the events to the sink and wait for the ack;
   - checkpoint;
   - build the next request.

All code is in `src/`:
- `policy.rs`: allowlist, deny lists, IP classes
- `broker.rs`: the only code that opens sockets
- `engine.rs`: the run loop
- `secrets.rs`: redaction
- `sandbox.rs` and `vrl_exec.rs`: the worker
- `auth.rs`: auth plugins
- `template.rs`: templating

## 2. Assets

| Asset | Where it lives | Must never |
|---|---|---|
| Tenant credentials (API keys, OAuth client secrets, SA private keys, mTLS keys) | `RunInput.credentials`, host process memory, one run only | reach VRL, an event, a checkpoint, an error message, preview output, a log, or a request to a host other than through the auth plugin |
| Derived secrets (OAuth access tokens) | `TokenCache` per run | same as above (they are added to the redaction set) |
| Platform secrets (pod env, mounted files, service tokens) | host process env and filesystem | be readable by a connector, VRL included |
| Cursors and checkpoints (`state`, window watermark, seen uids) | `CheckpointStore` (PG, service lane) | grow without bound; be read or written across tenants |
| Tenant event data | sink | go to a host outside the spec allowlist, or be mixed across tenants |
| The jobs process itself | the hosted lean jobs pod, or the compose `api` container | be crashed or starved by one tenant's spec (it serves every tenant) |
| Internal network | cluster services, metadata endpoints, node IPs | be reachable from any connector |

## 3. Trust boundaries and actors

- **Spec author (untrusted).** This is a tenant admin, the meloD wizard
  acting for one, or a catalog spec. They control the whole YAML: templates,
  the allowlist, limits within the ceilings, and the VRL program. They do
  not control the engine ceilings, the platform deny list, or other tenants'
  inputs.
- **Vendor endpoint (untrusted).** This is any allowlisted host. It may be
  attacker-controlled, for example a templated `{{config.X}}` host under an
  allowed suffix. It controls status, headers, body, `Location`,
  compression, timing and DNS answers for its name.
- **DNS (untrusted).** Answers may change between lookups (rebinding).
- **The VRL program (untrusted code)** runs in the worker process. Treat a
  VRL interpreter bug as arbitrary code execution inside the worker.
- **The host process (trusted, multi-tenant).** It holds the credentials of
  every concurrent run in one address space. Tenant separation inside it
  rests on Rust code: a broker, credentials and pool connections per run.
  There is no OS boundary between tenants here.
- **The service lane (trusted).** It supplies `tenant`, `credentials`,
  `config`, `checkpoints` and `egress_deny` per run. It must never hand one
  tenant's values to another.

## 4. Entry points

| Entry | Input | Code |
|---|---|---|
| `engine::run(cfg, spec, RunInput, sink, store)` | spec YAML, tenant config, credentials, checkpoints | `engine.rs` |
| `engine::compile` / `preview::validate` / `nano-connector validate` | spec YAML (VRL compiled in a worker only) | `engine.rs`, `preview.rs` |
| `preview::preview` / `nano-connector preview` | spec plus recorded responses; prints events, checkpoints, the request log, errors | `preview.rs` |
| Vendor responses | everything the broker reads | `broker.rs::send_once` |
| Redirect `Location` and Link headers, `next_request` from VRL | URLs | `engine.rs::exchange`, `build_next`, `paging.rs` |
| Worker protocol | one JSON line per call, both ways | `vrl_exec.rs` |
| Environment (sandbox) | `NANO_CONNECTOR_SECCOMP`, `NANO_CONNECTOR_CGROUP`, `NANO_CONNECTOR_CGROUP_PARENT`, `NANO_CONNECTOR_SANDBOX`. Unknown values are errors | `sandbox.rs::SandboxPolicy::from_env` |
| Environment (runner) | `CONNECTOR_EGRESS_DENY_CIDRS`, `CONNECTOR_EGRESS_DENY_HOSTS`, `CONNECTOR_INGEST_HOST_SUFFIX`, `CONNECTOR_VRL_MAX_WORKERS`, `CONNECTOR_VRL_MAX_PER_TENANT`, `CONNECTOR_VRL_WORKER_AS_BYTES`, `CONNECTOR_VRL_ACQUIRE_SECS`, `DEPLOYMENT_MODE` | `bin/nano-connector-runner.rs`, `service/runner.rs::platform_egress_deny` |
| Hidden CLI | `vrl-worker`, `sandbox-probe <op>`. A probe only attempts things against itself | `bin/nano-connector.rs` |
| Dev / CI only | `preview --mock-url` (loopback-only transport, after the host policy) and the shadow-run uid check, which runs first-party `parser_vrl` in process with the full stdlib. Neither is reachable from the runner | `loopback.rs`, `parse_check.rs` |

## 5. Controls

### Egress (broker + policy)

- Only `https` on port 443 is allowed. Userinfo is refused. URLs are capped
  at 8 KiB.
- The host must exactly match an allow rule after IDNA. A plain LDH name is
  required, with no numeric TLD.
- A templated host must sit under a dot-prefixed suffix. A suffix without
  the dot is a spec error.
- Reserved names are refused: `localhost`, `metadata`, `.internal`,
  `.local`, `.svc`, `.cluster.local`, `.onion`, `.test`, `.lan`, `.corp`,
  `.home.arpa` and similar.
- Path prefixes are segment-aligned. Encoded `/`, `\`, `.`, NUL, CR and LF
  are refused.
- **IPv4:** every IANA special-purpose range is refused, plus Azure
  WireServer `168.63.129.16`.
- **IPv6:** only `2000::/3` is allowed. Within it, these are refused:
  - `2001::/23` (Teredo, ORCHID, benchmarking);
  - documentation ranges;
  - 6to4;
  - AS112.

  Anything that embeds IPv4 (mapped, compatible, SIIT, NAT64 `64:ff9b::/96`
  and `64:ff9b:1::/48`) is refused without decoding.
- **Deny lists:** `EngineConfig.platform_deny` and `RunInput.egress_deny`
  hold hosts (exact, or `.suffix`) and CIDRs. A v4 CIDR also matches the
  v4-mapped form, and a v4-mapped CIDR (`::ffff:10.0.0.0/104`) is stored as
  the v4 range it names. Deny always beats allow. If the deny list removes
  every allowed host, the run is refused before any request.
- **Runner deny:** the runner fills `platform_deny` from
  `CONNECTOR_EGRESS_DENY_CIDRS` / `CONNECTOR_EGRESS_DENY_HOSTS`
  (comma-separated) and always adds `.<CONNECTOR_INGEST_HOST_SUFFIX>`. Each
  run also denies its own feed's ingest host. In hosted shared mode the
  runner refuses to start without `CONNECTOR_EGRESS_DENY_CIDRS`. The deny
  binds only the vendor side (the broker and its `HostPolicy`): the
  runner's own POST to the tenant ingest uses the HEC sink's separate
  client (bounded by `CONNECTOR_INGEST_HOST_SUFFIX`), and per-feed ingest
  credential issuance is a PostgreSQL transaction with no HTTP at all.
- **DNS:** the broker resolves each name itself, once per run. Every answer
  must pass, so a mixed answer is refused. The first answer is pinned. TCP
  goes to the pinned IP; SNI, certificate name and `Host` are the name.
- **Connection reuse:** idle HTTP/1.1 connections are pooled per broker,
  which means per run. The pool key is (host, pinned address). Nothing
  crosses runs, so nothing crosses tenants, and two hosts never share a
  connection.
- **Redirects:** every hop is re-checked against the allowlist and deny
  lists before any connection. Auth is applied only on the origin host. A
  cross-host `Location` that contains a secret (in any shape) is refused.
  Hops are capped by `max_redirects`.
- **Request caps:** body 4 MiB, 64 headers, 8 KiB per header value. Header
  names and values with CR, LF or NUL are refused.
- **Response caps:** total bytes are capped, and a `Content-Length` above
  the cap is refused early. Decompression is one bounded step only
  (gzip/deflate). `gzip, gzip`, `br`, `zstd` and other encodings are
  refused. Response headers are capped at 128, with a 256 KiB head buffer.
- **Timeouts:** connect, TLS handshake, response headers (30 s), the gap
  between body frames (20 s), the whole exchange (60 s), and the run wall
  clock.

### Secrets (`secrets.rs`)

`SecretSet` holds every shape of every credential and derived token:

- raw;
- percent-encoded, in upper- and lowercase hex, with the reserved sets of
  the common encoders: everything non-alphanumeric, RFC 3986 unreserved,
  `encodeURIComponent`, Python `quote`, and forms;
- JSON-escaped: as serde writes it, with `\/`, Go-style (`<>&` as
  `\u003c`...), Python `ensure_ascii`, and every non-alphanumeric character
  as `\uXXXX` in either hex case;
- hex in both cases;
- base64 (standard and url-safe). This includes the core of the secret at
  each of the three byte alignments inside a longer base64 run, and
  `base64(a:b)` for every pair of credentials (HTTP Basic).

A single Aho-Corasick pass both detects and redacts. For refusal,
`contains_decoded` also matches every view reachable by up to three rounds
(one round for inputs above 1 MiB, to bound memory) of percent-decoding (`+` as space) and JSON-unescaping, in any order, so a
shape missing from the list (mixed hex case, nested encodings, a program's
own encoding that the engine percent-encodes once more in a query) is
still caught. It is applied:

- to responses before VRL or extraction sees them. The body is redacted by
  shape; if a decoded view still shows a secret, a JSON body is redacted
  string by string (the whole string goes), and any other body is refused
  (`CredentialInResponse`). A header that decodes to a secret is replaced;
- to outbound URL, body and headers, raw and decoded, which are refused on
  a match (only the auth plugin may add a secret);
- to cross-host redirect targets, raw and decoded;
- to the final error message: a match turns into `EngineError::Scrubbed`.

### VRL worker (`sandbox.rs`, `vrl_exec.rs`)

- The host never compiles or runs tenant VRL. The VRL compiler recurses on
  nesting: about 700 levels of `[` overflow an 8 MiB stack, and a stack
  overflow aborts the whole process. Compilation happens only in the
  worker, which gets a 64 MiB stack, and a crash there becomes a spec error
  (a seccomp stop during compilation is a sandbox error instead).
- The function set is an allowlist (`ALLOWED_FUNCTIONS`). Everything else is
  undefined at compile time, including all of nanosiem-core's
  `BLOCKED_VRL_FUNCTIONS` (`http_request`, `get_env_var`, `dns_lookup`,
  `reverse_dns`, `get_hostname`), checked by a test that reads that file.
  The engine also refuses:
  - randomness;
  - VRL-side decompression;
  - file-reading functions;
  - the secrets API;
  - `log`;
  - keyed crypto.
- **Spawn (`pre_exec`):**
  - environment cleared, cwd `/`, new session, `no_new_privs`;
  - `RLIMIT_AS` (1 GiB default), `RLIMIT_CPU`, `FSIZE=0`, `CORE=0`,
    `NOFILE=8`, `MEMLOCK=0`, `MSGQUEUE=0`, `STACK=64 MiB`;
  - `NPROC=0`, so the worker cannot fork even without seccomp;
  - `oom_score_adj 1000`, so without a cgroup the kernel OOM killer takes a
    worker, not the runner.
- **In the worker, before it reads any input:**
  1. every core-dumping signal (ABRT, SEGV, BUS, ILL, FPE, SYS, XCPU, XFSZ,
     TRAP, QUIT) gets a handler that calls `_exit(128 + sig)`. A crashing,
     CPU-limited or seccomp-stopped worker therefore never enters the
     kernel's core-dump path. `RLIMIT_CORE 0` alone does not stop a
     `|systemd-coredump` core pattern, and `fs.suid_dumpable=2` dumps even a
     non-dumpable process;
  2. set `RLIMIT_CORE 0` again and `PR_SET_DUMPABLE 0`;
  3. close every fd above 2 (`close_range`, else `/proc/self/fd`, else a
     loop up to the fd hard limit);
  4. install two seccomp filters:
     - a trap list for sockets, connect, send/recv, exec, clone/fork,
       ptrace, `process_vm_*`, pidfd, kill/tkill, unshare, setns, mount,
       bpf, userfaultfd, perf, io_uring and keyrings. The syscall never
       runs; the SIGSYS ends the worker with exit 159 (a `KILL_PROCESS`
       action would always dump core);
     - an allowlist of read/write on existing fds, memory (mmap and
       mprotect only without `PROT_EXEC`), futex (wait/wake only, no PI,
       requeue or wake-op), clocks, getrandom, signals to itself, and exit.
       Everything else fails with EPERM, so there is no `open`, which means
       no filesystem and no `/proc`.
- **Fail closed:** an unknown `NANO_CONNECTOR_*` value is an error (a typo
  such as `require` → `required` never means `prefer`). A worker that
  cannot read its mode uses `require`. The runner refuses to start in
  hosted shared mode unless seccomp is `require`, and before taking work
  it spawns one worker as a self-test and refuses to start if a required
  layer is missing.
- **cgroup v2 (where delegated):** one leaf per worker, with `memory.max`,
  `memory.swap.max 0`, `memory.oom.group`, `pids.max 1` and optional
  `cpu.max`. The leaf is removed after the run (`cgroup.kill`, then
  rmdir).
- **Budgets:** wall time per call (`vrl_timeout_ms`); the worker is killed
  when it is exceeded. Output is capped at twice `max_response_bytes`.
  Every death is classified: seccomp, CPU limit, cgroup OOM, stack
  overflow, or memory.
- **Pool:**
  - global and per-tenant worker caps. The library default is 32 and 4;
    the runner uses `CONNECTOR_VRL_MAX_WORKERS` (32) and
    `CONNECTOR_VRL_MAX_PER_TENANT` (4 × runs per tenant, and never below
    the runs per tenant);
  - a run that finds no slot within `CONNECTOR_VRL_ACQUIRE_SECS` is
    deferred: recorded as `timeout` with `deferred`, retried after one to
    two poll intervals, and not counted as a feed failure;
  - a run reserves all its slots at once (FIFO), so two runs cannot
    deadlock each other;
  - a spec with more VRL streams than the per-tenant cap is refused;
  - workers are single-use: one stream of one run, then killed. They are
    never reused across runs or tenants.

### Caps on persisted state

`max_checkpoint_bytes` defaults to 4 MiB with a 16 MiB ceiling. It is
checked before every save, so an oversized checkpoint is never persisted.
`window.max_seen` is capped at 200,000.

## 6. Where each isolation layer works

The two container columns were checked on a local Docker 2026-10 host
(cgroup v2, builtin seccomp profile), running the binary inside the hosted
hosted jobs image. The k8s column was simulated with
`--user 65534 --cap-drop ALL --security-opt no-new-privileges --read-only`.
None of this ran on live Rackspace Spot nodes.

| Layer | Hosted lean jobs pod (k8s, unprivileged, RuntimeDefault) | Open-core docker compose (defaults) | Bare metal / systemd `Delegate=yes` / podman |
|---|---|---|---|
| Cleared env, closed fds, `no_new_privs`, rlimits, `NPROC=0` | yes | yes | yes |
| seccomp kill list + allowlist | **yes** (probes: socket/exec/fork → SIGSYS, open → EPERM) | **yes** (same) | yes |
| cgroup v2 per-worker leaf | **no**: `/sys/fs/cgroup` is mounted read-only. Runs report `cgroup: unavailable: ... Read-only file system`, with a one-time warning | **no**: same | **yes** (tested with systemd user delegation: a 256 MiB allocation against a 64 MiB `memory.max` is OOM-killed and reported) |
| Per-worker memory bound without cgroup | `RLIMIT_AS` (virtual memory) | same | — |

What "degraded" means without the cgroup: memory is bounded by `RLIMIT_AS`
and CPU by `RLIMIT_CPU` plus the per-call wall budget. pids are bounded by
the seccomp clone kill and `NPROC=0`. The pod's or container's own limits
bound the aggregate.

Operators must keep `CONNECTOR_VRL_MAX_WORKERS ×
CONNECTOR_VRL_WORKER_AS_BYTES` below the pod memory limit. Otherwise many
tenants together can push the pod into OOM (and then `oom_score_adj` makes
the kernel pick workers first).

**Settings:**

- **Hosted:** set `NANO_CONNECTOR_SECCOMP=require` (the runner refuses to
  start in hosted shared mode without it). A pod where seccomp cannot be
  installed then fails its boot self-test instead of degrading. Keep
  `NANO_CONNECTOR_CGROUP=prefer`; k8s offers no delegation without
  privileges.
- **Self-hosted with delegation:** set
  `NANO_CONNECTOR_CGROUP_PARENT=/sys/fs/cgroup/<delegated dir>` (the
  directory must hold no processes) and `NANO_CONNECTOR_SANDBOX=strict`.

Every run returns `RunOutput.sandbox` (and preview prints `sandbox`) with
the isolation each worker actually got.

**Deploying the runner (hosted):**

- set `CONNECTOR_EGRESS_DENY_CIDRS` to the cluster pod and service CIDRs
  and the node addresses that are not already non-public (GUA IPv6 pod
  ranges on dual-stack, node public IPs). The runner refuses to start in
  hosted shared mode without it; the ingest suffix is added automatically;
- set `NANO_CONNECTOR_SECCOMP=require`;
- the runner passes `tenant` and the feed's ingest host per run; there is no
  tenant deny column yet.

## 7. Attacks already covered (all must fail closed)

To run them: `cargo test -p nano-connector`. Every suite runs its workers
with seccomp `require`, so a host where the filter does not install fails
the tests (opt out with `NANO_CONNECTOR_TEST_SECCOMP=prefer`). The cgroup path needs a writable
delegated cgroup: run the `tests/sandbox.rs` binary outside a sandbox, or set
`NANO_CONNECTOR_TEST_CGROUP_PARENT`.

| Family | Test | Variants |
|---|---|---|
| SSRF via URL parsing | `g2_attacks::ssrf_url_parsing_tricks_never_dial` | 54 URLs: decimal/octal/hex/short IPv4, `%`-encoded hosts, v4-mapped/NAT64/6to4/Teredo/compatible IPv6, link-local, ULA, metadata (AWS/GCP/Azure/Alibaba/Oracle), userinfo, `#@`, `\@`, Cyrillic and ideographic-dot look-alikes, underscores, ports 0/80/8443, http/file/gopher/ftp, scheme-relative, `.svc`/`.cluster.local`/`.internal`/`.onion`, traversal and encoded separators, NUL, CRLF, 9 KiB URL. Nothing dialed |
| SSRF via DNS | `dns_answers_in_special_ranges_are_refused_before_connect`, `g2_security::*` | 25 bad answers, mixed answers, platform/tenant deny CIDR |
| Rebinding | `g2_security::dns_rebinding_cannot_move_a_pinned_connection`, `pooled_connections_stay_pinned_and_per_run` | public → private flip; pooled pages stay on the pin; the next run re-resolves and is refused; two hosts on one IP get two connections |
| Tenant deny | `tenant_deny_beats_the_spec_allowlist` | exact and suffix deny; refused at run start when nothing is left |
| Redirects | `redirect_matrix_revalidates_every_hop`, `g2_security::redirect_*` | IP literals, downgrade, userinfo, scheme-relative, port, traversal, secret (raw, percent-encoded, base64) in a cross-host Location, loop, tenant-denied hop, auth not forwarded cross-host |
| Encoder variants | `encoder_variants_cannot_smuggle_a_credential`, `secrets::tests::*` | secret with `~/&'()<>`: reflected Go-escaped (raw JSON), lowercase-percent RFC 3986, `encodeURIComponent`, mixed hex case in a value and an object key, in a header → events clean; same in a text body → page refused; program sends lowercase/`encodeURIComponent`/mixed-case/Go-escaped forms in query, form and JSON → refused; cross-host `Location` with a mixed-case percent form → refused before dialling |
| Credential exfil | `credentials_cannot_leave_in_any_encoding_or_channel`, `derived_oauth_tokens_are_redacted_like_credentials`, `preview_output_never_shows_a_secret`, `g2_security::credentials_*` | reflection as raw/base64/inner-base64 at offsets/hex/percent-encoded/Basic, in body and headers; program forwards what it saw via query/JSON/state; program that knows the secret places it in path/fragment/query/form/JSON, raw or encoded; secret in an error message (scrubbed); OAuth access-token reflection; preview output; checkpoints |
| Decompression and size bombs | `decompression_and_encoding_bombs_are_capped`, `g2_security::decompression_*` | 200 MiB gzip, 100 MiB zlib, 2,000-member gzip, stacked `gzip, gzip`, `br`, endless chunked body, 500 headers, one 512 KiB header, 40 MiB body |
| Slowloris | `slowloris_responses_hit_their_timeouts` | TLS handshake never answered, headers dripped, body stalled, body dripped under the idle timeout (total deadline) |
| VRL CPU, memory and crash | `hostile_vrl_cannot_crash_or_starve_the_host`, `g2_security::vrl_*` | 50k-deep `[`, 50k `!`, 60k-term `+` chain (host aborts if compiled in process), 1 TiB string doubling, catastrophic loop vs 300 ms budget, 4 MiB output vs cap, healthy run afterwards |
| No core dumps | `sandbox::workers_never_dump_core`, `sandbox::tests::*` | worker runs with `RLIMIT_CORE` 0/0 and not dumpable; abort, stack overflow, CPU limit and a seccomp trap all end in `exit(128 + sig)`, never a signal death; death reasons decode those exits |
| Fail-closed config | `sandbox::tests::unknown_enforce_values_are_errors_not_defaults`, `service::runner::tests::*` | `required`/`enforce`/`on`/`yes`/`strictt` are errors; shared runner needs deny CIDRs; bad CIDR or host refused; the ingest suffix is denied; mapped-v6 CIDR width (`policy::tests::mapped_v6_deny_ranges_keep_their_width`) |
| Worker escape | `sandbox::worker_sandbox_blocks_escape_attempts` | socket (inet, unix), execve, fork, kill(parent), ptrace → SIGSYS (exit 159); open `/etc/passwd`, `/proc/self/environ`, `/proc/<ppid>/mem`, `PROT_EXEC` mmap → EPERM; env empty; leaked fd closed; control run without seccomp proves the probes are meaningful |
| cgroup | `sandbox::cgroup_limits_apply_where_delegated_and_degrade_loudly_elsewhere` | OOM-kill by `memory.max`, the report says `enforced`, leaves cleaned up; or, where there is no delegation, `Require` refuses |
| State and checkpoint | `oversized_state_and_checkpoints_are_refused` | 2 MiB state vs 1 MiB cap, never persisted; spec cannot raise the ceiling; `max_seen` above the ceiling refused |
| Fairness | `one_tenant_cannot_take_every_vrl_worker` | per-tenant cap (ordered by events, not sleeps); another tenant not starved; too many VRL streams refused |
| Cross-tenant | `hostile_spec_cannot_reach_another_tenants_credentials`, `workers_are_single_use_and_strict_mode_is_honoured` | while tenant A runs: B templates `credentials`, reads `config`, calls `get_env_var`/`get_secret`/`get_hostname`/`dns_lookup`/`http_request`, names a path-like credential; nothing of A's or the platform's reaches B; workers are fresh per run; `Require` without a cgroup refuses |
| Policy properties | `policy_props::*` (proptest) | IPv4 table vs an independent reference (4k cases with range edges); every v4-embedding v6 form; non-`2000::/3`; CIDR membership; 20k spliced URLs: accepted ⇒ the right host, 443, `/v1`, stable on re-parse, clean request line; templated host suffix; encoded secrets found and removed |

## 8. Residual risk: where nano-red should push

1. **One host process, many tenants.** Credentials of concurrent runs share
   an address space. Separation is per-run Rust objects, not the OS. A
   memory-safety bug in hyper, rustls, flate2 or serde_json, or a logic bug
   that hands one run's broker or `Credentials` to another, crosses
   tenants. The recommendation is a secret-free runner pool for
   hosted-shared.
2. **No cgroup in k8s or compose.** Per-worker memory is `RLIMIT_AS`
   (virtual), and CPU is `RLIMIT_CPU` plus the wall budget. Many workers at
   once can OOM the pod. Try to find a VRL workload that stays under the
   per-call wall budget but holds a lot of RSS across calls.
3. **Redaction is pattern-based.** It does not catch:
   - secrets shorter than 6 characters;
   - reversed, XOR'd, truncated or split secrets, more than three nested
     percent/JSON layers, or any other reversible transform;
   - HTML entities;
   - secrets inside compressed or encrypted payloads.

   It also over-matches: every credential field is treated as secret,
   including identifiers such as `client_id` or `client_email`, so those
   are redacted out of events too (auth plugins do not yet declare which
   keys are secret).

   A reflected secret in such a shape reaches VRL, which can send it only
   to allowlisted hosts. The real target is catalog specs and allowlisted
   hosts that an attacker controls, such as templated `{{config.X}}` hosts
   under a broad suffix.
4. **The allowlist is the trust.** Whoever controls an allowlisted host
   receives whatever the program sends there, including data fetched from
   other allowlisted hosts in the same run. Look for review gaps in
   `host_suffixes` breadth in catalog specs.
5. **`platform_deny` is only as good as its configuration.** The runner
   requires `CONNECTOR_EGRESS_DENY_CIDRS` on shared deployments but cannot
   check that it names every cluster range. Library callers other than the
   runner start with it empty.
6. **System resolver.** Pins come from `getaddrinfo` in the pod, which uses
   cluster DNS and `/etc/hosts`. A poisoned cluster resolver can return a
   public-looking address that the platform deny list does not cover.
7. **Seccomp `prefer`.** If seccomp cannot be installed and the mode is
   `prefer` (dedicated / compose only; shared refuses), a VRL interpreter
   escape runs with the host's uid. The runner sets `PR_SET_DUMPABLE 0` and
   `RLIMIT_CORE 0` on itself first thing, so `/proc/<ppid>/environ` and
   `mem` are closed to it; other same-uid files are not.
8. **The kernel surface through the allowlist** (read, write, mmap, futex,
   clocks, getrandom) is small but not zero.
9. **Dedupe degrades.** When the seen map evicts, delivery becomes
   at-least-once (`max_seen`), and a vendor can force duplicates.
10. **Host suffixes are not checked against the public suffix list.** A
    catalog spec with `host_suffixes: [co.uk]` would admit every `*.co.uk`.
    Catalog review must catch it.
11. **Shared pool buckets.** `VrlPool` keeps one semaphore per tenant id for
    the process lifetime, and preview / validate share the `default` /
    `validate` buckets; an API that exposes them must pass a real tenant.
12. **HTTP/1.1 only, no proxy support.** A deployment that needs an egress
    proxy has to add it in the broker: everything else about connecting is
    in one place.

**Outside this crate:** `nanosiem-core/src/parsers/validator.rs` compiles
tenant parser VRL in the API process. The same deep-nesting input that
crashes the VRL compiler above (about 700 levels in an 8 MiB stack, less on
a 2 MiB tokio worker) should abort `nanosiem-api`. That was not tested here;
it is tracked separately.
