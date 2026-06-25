# OCSF 1.8.0 conformance — overnight work + morning restart/test steps

## What got done (overnight, autonomous)
Full OCSF 1.8.0 conformance pass on the ingestion path. Every promoted column was
audited against the **live OCSF 1.8.0 schema server** (see `OCSF_COLUMN_AUDIT.md`)
— two real conformance defects found + fixed across all four layers, plus several
isolated parser fixes. Everything below is committed and test-green.

### Defects fixed
1. **Process role inversion.** OCSF `process_activity` 1007: top-level `process`
   (required) = the SUBJECT (launched/terminated/accessed); `actor.process` =
   parent/initiator. We had it backwards (subject in `actor.process`, required
   `process` unset). Flipped in parsers + manifest + DDL + profile:
   - process_name→`process.name`, command_line→`process.cmd_line`,
     process_id→`process.pid` (new col), process_guid→`process.uid` (new col),
     process_hash→`process.file.hashes.sha256` (new col)
   - parent_command_line→`actor.process.cmd_line` (initiator IS the parent)
   - dropped `actor.process.parent_process.cmd_line`
   - `prevalence_process_hash` + the hash-prevalence MV now key on the subject hash
2. **HTTP url placement.** `http_activity` 4002 has no top-level `url`; the URL
   lives in `http_request.url`. Added promoted `http_request.url.hostname` +
   `http_request.url.url_string`; repointed UDM url_domain/url at them. Top-level
   `url.*` columns stay (valid for `network_activity` 4001).
3. Isolated parser fixes: Authentication 3002 now sets `dst_endpoint` (satisfies
   `at_least_one(service, dst_endpoint)`); Network 4001 omits `protocol_num` when
   unknown (no `-1`); CloudTrail moved `is_mfa`→`unmapped`, always emits required
   `src_endpoint`; apache URL is `http_request.url.path` only (no bogus url_string).

### Where the code is
- **nanosiem** branch `feat/NAN-1241-ocsf-schema-support` (PR #1909), **committed locally, NOT pushed**:
  - `c8e98608` — schema conformance (init.sql + udm_ocsf_mapping.json + ocsf.rs)
  - `216c98b6` — NAN-1266 profile-aware repo sync (parsers-ocsf/ + rules-ocsf/)
- **parsers** repo `main` — **MERGED** (PR #10 `d53c1db`): conformance-fixed `parsers-ocsf/*`.

### Tests (all green)
- `cargo test -p nanosiem-core --test ocsf_manifest_ddl_consistency` → 6/6
- `cargo test -p nanosiem-core --lib schema` → 40/40 (ocsf profile + byte-identical UDM)
- `scripts/validate-vrl.sh` all 5 parsers → 5/5 OK
- `vector vrl` spot-checks confirmed: EID1 `process`=created / `actor.process`=parent;
  conduit `http_request.url` populated, no top-level `url`.
- NOT run: live-CH `ocsf_materialization_integration` (needs the recreated table — do after restart).

## ⚠️ Morning restart/test steps (order matters)
1. **Rebuild** the nanosiem image/binaries so the schema commit (`c8e98608`) + NAN-1266
   are in the running api/search. (Dev startup script owns the build.)
2. **Recreate `ocsf_logs`** — CRITICAL. `clickhouse/ocsf/init.sql` is `CREATE TABLE IF
   NOT EXISTS`, so the existing table will KEEP the old columns and the new
   `process.*`/`http_request.url.*` columns won't materialize. The table is empty
   (0 rows), so drop + recreate:
   - drop the dependent MV first (`ocsf_hash_prevalence_summary_mv`), then
     `DROP TABLE nanosiem.ocsf_logs`, then re-run `clickhouse/ocsf/init.sql`
     (admin creds `nanosiem_admin`/`nanosiem_admin_secret`; the `nanosiem` user is DDL-prohibited).
   - Confirm new cols exist: `DESCRIBE nanosiem.ocsf_logs` shows `process.pid`,
     `process.uid`, `process.file.hashes.sha256`, `http_request.url.hostname`,
     `http_request.url.url_string`; and NO `actor.process.parent_process.cmd_line`.
3. **Re-sync** the parser log-source-repository (now resolves `parsers-ocsf/` via NAN-1266)
   → pulls the 5 conformance-fixed parsers from `parsers` main.
4. **Vector OCSF sink**: re-publish/deploy should regenerate `_ocsf_sink.toml` via the
   generator. If the prepare transforms show "has no consumers" again, the stopgap
   `config/vector/sources/parsers/_ocsf_sink.toml` is already on disk (local artifact).
   (Open item: confirm the generator actually writes the sink on publish — it didn't
   last session; see below.)
5. **Blast** log-blaster → verify:
   ```sql
   SELECT source_type, class_uid, count() FROM nanosiem.ocsf_logs
   GROUP BY source_type, class_uid ORDER BY source_type;
   ```
   Spot-check conformance on a real row, e.g.:
   ```sql
   SELECT `process.name`, `process.cmd_line`, `actor.process.name`,
          `http_request.url.hostname`
   FROM nanosiem.ocsf_logs WHERE class_uid=1007 LIMIT 5;
   ```
   Expect `process.*` = the launched process, `actor.process.name` = the parent.

## Open items
- **Generator didn't emit `_ocsf_sink.toml` on publish last session** (prepare transforms
  had no consumer → OCSF rows dropped). Worked around with a hand-written sink. Root cause
  unconfirmed (stale binary vs publish not running full `deploy()`); confirm after the rebuild
  that a publish regenerates the sink, else file a bug.
- **traffic bytes_in/out direction**: OCSF `bytes_in` = destination→source. Names match UDM;
  audit flagged to confirm the UDM direction convention matches before relying on it semantically.
- nanosiem `feat/NAN-1241` commits are local — push when ready to ship PR #1909.
