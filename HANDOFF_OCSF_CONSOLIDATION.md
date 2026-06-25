# OCSF Consolidation — Session Handoff

**Tracking issue:** NAN-1319 (OCSF: consolidate the schema seam) — child of NAN-1241 (OCSF epic), under NAN-1262 (OCSF hardening).
**Date:** 2026-06-08. **Branch base:** `main` (all today's work merged).

---

## TL;DR / strategic framing

OCSF is staying — it's customer-requested and becoming the de-facto standard. The pain
we've been hitting is **finite implementation debt**, not a doomed direction. The engine
is **UDM-native at its core**; OCSF is a bolt-on `SchemaProfile` mapping layer. Bugs come
from that translation layer being leaky in three repeating ways. Today we **stopped the
bleed** (10+ surface fixes, all merged + validated on live CH). The next session should
**close the wound**: consolidate the fixes into the profile seam so they stop recurring
(NAN-1319), then mop up the remaining filed items.

---

## The 3 recurring root causes (this is the whole story)

1. **OCSF host is split; the mapping is incomplete.** `udm_column_sql("src_host")` →
   `src_endpoint.hostname` only. But a **sysmon/endpoint host lives in `device.hostname`**
   (only network events populate `src_endpoint.hostname`). Proven live: asset for
   `ws-eng-074` = **27 events** via `src_endpoint.hostname` vs **411** via
   `device.hostname ∪ src_endpoint.hostname ∪ dst_endpoint.hostname`. Every surface that
   resolves "host" had to re-learn `device.hostname` separately
   (NAN-1295/1296/1287/1291/1302/1318).
2. **Display aliasing leaks UDM names to OCSF users.** Surfaces aliased OCSF columns back
   to UDM-canonical (`dst_endpoint.hostname AS dest_host`) so the UDM-built frontend
   renders. Search is native; asset was canonical until NAN-1303. Wrong for OCSF users.
3. **Manifest maps operational concepts to OCSF-semantic columns.** `id`→`metadata.uid`,
   `source_type`→`class_uid` — wrong when a caller wants the physical/operational value
   (fixed ad-hoc in NAN-1316/1317).

---

## Where the asset view is now (the surface we drove to ground today)

`<host> | asset` under OCSF now: resolves identity (NAN-1300), shows the host's **full**
activity not just network (NAN-1318), renders **native OCSF field names** (NAN-1303), row
labels show populated values + summary falls through empty fields (NAN-1303), row-expand
loads the full event (NAN-1316 id, NAN-1317 source_type). **Needs a `nanosiem-core` +
`nanosiem-web` rebuild to see it.** Last reported issue ("only network events") = NAN-1318,
fixed + merged; pending the user's visual confirmation after rebuild.

---

## Merged today (all on `main`, validated on live local CH)

| Issue | What |
|---|---|
| NAN-1299 | PREWHERE resolved through SchemaProfile (UDM-alias search terms 500'd under OCSF) |
| NAN-1306 | cloud-overview accounts subquery aliasing (silent empty facet) |
| NAN-1301 | prevalence-artifacts matching_logs CTE aliasing (400s) |
| NAN-1311 | `sequence` registers dotted capture cols as computed (Code 47 event) |
| NAN-1314 | `allow_ddl=1` for nanosiem profile so IPinfo sync cleanup runs (Code 392) |
| NAN-1300 | asset/risk entity classification via `EntityType` + UDM-canonical fallback |
| NAN-1302 | `device.hostname` added to OCSF entity-extraction order (risk=unknown) |
| NAN-1315 | field-stats wraps multi-CTE queries instead of slicing (Code 62) |
| NAN-1316 | asset stream projects physical `id` not `metadata.uid` (row-expand) |
| NAN-1317 | asset stream projects literal `source_type` not `class_uid` (422) |
| NAN-1303 | asset stream renders **native OCSF** fields + `display_field_name` seam |
| NAN-1318 | asset matches all OCSF host columns incl `device.hostname` (27→411) |
| NAN-1310 | (earlier) ip_enrichment_dict load uncapped — IPinfo import stalled all ingestion |

New seam introduced today: **`SchemaProfile::display_field_name(concept)`**
(`nanosiem-core/src/schema/profile.rs`, OCSF override in `ocsf.rs`) — the native field
name a row should be keyed by. Reuse this for the native-display generalization.

---

## NAN-1319 — the consolidation pass (next session's job)

1. **Class-split `src_host`** at the profile level → `device.hostname` ∪
   `src_endpoint.hostname` (∪ `dst_endpoint.hostname`). Use the existing
   `class_split_udm_field` (`nanosiem-core/src/schema/ocsf.rs:263`, already does
   user/process/url). Then every `udm_column_sql("src_host")` caller (search, detection,
   risk, grouping, asset) picks up the device host automatically → the per-surface patches
   become redundant safety nets. **⚠ Validate:** it emits an `if(...)` expr — confirm it
   doesn't break PREWHERE (NAN-1299 path) or double-count, and re-run the asset 27→411
   check on live CH.
2. **Audit the other concepts** (user, ip, process, hash) for the same by-class
   incompleteness vs how OCSF actually populates them.
3. **Native display everywhere.** Generalize `display_field_name`; grep for remaining
   `AS <canonical>` display aliasing + frontend hardcoded UDM keys (search already native;
   asset done; check matches/pivots/inspector/dossier).
4. **Route everything through the seam.** `OCSF_PROFILE_AWARENESS_AUDIT.md` (repo root) +
   NAN-1248 is the map of UDM-hardcoded sites.
5. **Regression coverage.** One harness asserting host/user/ip resolve through the profile
   to the right OCSF column(s) per event class; per-surface OCSF smoke tests.

**Follow-up (separate path):** `build_entity_identity_clause` /`entity_time_range_agg`
identity rollup (first/last-seen across identities) needs the same `device.hostname`
awareness — `asset.rs:460`. Not the event-stream clause (that's fixed).

---

## Other open OCSF backlog (not part of 1319)

- **NAN-1312** — parser rejects bare `| prevalence` (needs `enrich=true`/condition); AI
  shadow-hunts emit it bare. Fix: parser accepts bare `prevalence`. Small.
- **NAN-1313** — shadow-investigation structured verdict degrades to prose on gemma (no
  tool-calling/JSON) → NAN-1297 severity recommendation never runs. Fix: route verdict
  agent to a tool-calling model (Kimi). High value.
- **NAN-1307** — AI triage throughput controls (concurrency/budget) — feature, backlog.

---

## Local dev environment (for a fresh session)

- Stack: `NANO_SCHEMA_PROFILE=ocsf`, app at `localhost:5173`, api `:3000`, search `:3002`.
  Login `dan@nano.rs`. Data in `nanosiem.ocsf_logs` (~local CH, docker `nanosiem-clickhouse`).
- **CH creds:** user `nanosiem`/`nanosiem`, admin `nanosiem_admin`/`nanosiem_admin_secret`.
  Helper: `/tmp/nh.sh` (`nlogin`, `napi`, `nsearch`, `nch`); JWT 15-min expiry, re-`nlogin`.
- **Validation pattern (the one that worked all session):** generate SQL via the generator
  in a throwaway `#[cfg(test)]` dump OR `/api/search/explain`, then execute against local
  CH (`docker exec nanosiem-clickhouse clickhouse-client --user nanosiem_admin ...`).
  Compare old-vs-new clause shapes. **Local CH validates correctness, not scale.**
- **demo tenant is UDM + production — off-limits.** All validation was localhost.
- **Rebuild:** `nanosiem-core`/`nanosiem-web` changes need a rebuild+restart to show in-app;
  CH-config changes (e.g. query_limits.xml) are live via `SYSTEM RELOAD CONFIG`.
- **Local uncommitted (intentional, do not commit):** `clickhouse/config.d/zzz-dev-override.xml`
  (CH `max_server_memory_usage` bumped to 16 GiB for the 22 GiB Docker VM),
  `clickhouse/users.d/default-user.xml`. Vector parser `.toml`s under
  `config/vector/sources/parsers/` are local disk noise — never stash/stage.

## Workflow notes

- Per-issue branch off `main`, validate on live CH, PR, squash-merge, pull. Don't trigger
  build/deploy workflows. `cargo fmt` is NOT clean repo-wide — match surrounding style by
  hand. A linter occasionally reverts in-flight edits — re-check the file before committing.
- UDM must stay byte-identical (the OCSF epic invariant): `display_field_name` /
  `udm_column_sql` default to identity for UDM, so route changes through the profile.
