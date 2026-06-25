# OCSF Overnight Test Findings (NAN-1262)

Stack: localhost, NANO_SCHEMA_PROFILE=ocsf, binaries built post-merge (ee9c3f6a, 21:35).
ocsf_logs: 166k rows; classes 1005/4002/6003/3002/1007/4001/201001/201002/3003/1001/2004/4003.
Method: probe each surface end-to-end vs CH, tail service logs for errors, file Linear bugs.

## Findings

### F1 [P1] UDM-alias `field=value` search terms 500 / silent-0 under OCSF (raw token in PREWHERE)
- **Symptom**: `src_ip="x"`, `src_host="x"`, `dest_ip=`, `dest_host=`, `process_name=`, `action=`, `event_type=` → **HTTP 500**; `user="x"` → **HTTP 200 but 0 results** (truth: 80). Native OCSF fields work (src_endpoint.ip=1044, device.hostname=109, actor.user.name=2000, user.name=80).
- **CH error**: `Code: 47 UNKNOWN_IDENTIFIER: src_ip ... PREWHERE ... AND (src_ip = '...')`.
- **Root cause**: `nanosiem-core/src/query/clickhouse_sql_gen.rs::extract_prewhere_conditions` (L578) is a **profile-blind free fn** (comment L582-584 admits the profile isn't threaded). It emits the raw `normalize_field_name(field)` UDM token (L615-631) into PREWHERE for any field in `PREWHERE_FIELDS` (L478: src_host/src_ip/dest_host/dest_ip/process_name/user/action/event_type). The WHERE clause IS profile-resolved (`lower(toString("src_endpoint.ip"))`), so PREWHERE and WHERE disagree; the raw token isn't an ocsf_logs column → Code 47.
- **Blast radius**: breaks the advertised "UDM aliases resolve under OCSF" guarantee that the migration story + AI agents (which still emit UDM names) rely on. Also any UDM-field **detection rule** executed under OCSF would 500 / silently not match.
- **Fix direction**: thread the active `SchemaProfile` into `extract_prewhere_conditions` (and `has_selective_prewhere`) and resolve the field via `profile.udm_column_sql`/`resolve` before emitting — OR skip PREWHERE promotion for fields that resolve to a JSON/expr/unmapped column. UDM path must stay byte-identical.
- **Repro**: `POST :3002/api/search {"query":"src_ip=\"89.248.167.131\"","time_range":{...}}` → 500.

### F2 [P2] Asset dossier/view empty for NATIVE OCSF identifier fields (collect_asset_identifiers hardcodes UDM names)
- **Symptom**: `POST /api/search/asset-dossier {identifier_field:"device.hostname", value:"ws-eng-001.corp.local"}` → all sections EMPTY (timeline 0, processes 0, network 0). Same call with `identifier_field:"src_host"` → POPULATED (28 buckets, ssh.exe/sc.exe, 5 conns). `device.hostname="X" | asset` and `src_endpoint.ip="X" | asset` → 0 results.
- **Root cause**: `nanosiem-core/src/search/service/asset.rs::collect_asset_identifiers` (L340) `match identifier_field { "src_ip"|"dest_ip" => ips, "src_host"|"dest_host" => hostnames, "user" => users, _ => {} }`. Native OCSF fields (`device.hostname`, `src_endpoint.ip`, `src_endpoint.hostname`, `user.name`, `actor.user.name`) hit `_ => {}` → value dropped → empty identity set → empty dossier. (Sibling `build_log_identity_clause_for` IS profile-aware; this bucket-classifier is not.)
- **Nasty interaction w/ F1**: F1 makes the UDM path (`src_host=…|asset`) 500, and F2 empties the native path (`device.hostname`), so OCSF host asset views can be broken both ways. Entity extraction (NAN-1287) now emits `device.hostname` as the host entity, so the round-trip likely passes the native field.
- **Fix direction**: classify `identifier_field` into ip/host/user buckets via the active SchemaProfile's EntityType (not a UDM-name match) so native OCSF dotted fields route correctly; keep UDM names working.
- **Open**: confirm in the UI which identifier_field the Asset drilldown sends for an OCSF host (native vs UDM) to finalize P1/P2.

### F3 [NOT A BUG] ai_recommended_severity empty across all 37 cases — timing, not a defect
- Column exists (migration applied). All 37 cases triaged BEFORE the 21:35 rebuild (latest 2026-06-07 23:21Z < 01:35Z build; 0 triaged post-rebuild). NAN-1297 code deployed but hasn't run. TODO: trigger a fresh shadow investigation (injector) to verify recommended_severity persists + escalation fires.

### Enrichment [VERIFIED OK] geo/asn dual-mode works under OCSF (NAN-1278)
- src 89.248.167.131 → NL / AS202425 "IP Volume inc" via dictGet (event had no native enrichment). apache/cloudtrail public src ~50% country — partial LOCAL ip_enrichment_dict sample (920986 entries), not a bug. sysmon/proxy/winevent src IPs are internal → correctly 0.
- IOC enrichment 0 across all rows = EXPECTED: ioc_enrichment_dict / custom_ioc_enrichment_dict / custom_enrichment_dict all LOADED with 0 elements (no IOC feed data loaded locally). Not a bug. prevalence dicts populated (ip 555964, domain 2314, hash 430).

### Detection rules [VERIFIED OK] OCSF query generation correct for complex rules
- 15 rules (7 live/8 alerting). Top matcher lateral_movement_multi_host_logon=611. 3 zero-match rules (windows_failed_login_threshold, rundll32_javascript_c2_beacon, remote_wmi_process_enumeration) — all updated 11:20-11:25Z (AFTER data window closed 23:25Z), so detection-engine rolling lookback saw no fresh data. Running their EXACT nPL via search over the data window returns the expected matches (R1=2 [failures 7,6 > 5], R2=1 [rundll32 javascript:], R3=1 [WMIC /node:]). Confirms OCSF codegen handles stats/dc()/values()/CONTAINS/where-threshold/group-by-device.hostname correctly. Zero-match = timing, not a defect.

### Env note: AI provider dead locally ("Empty response from model")
- jobs.log: siem_health AI falls back; shadow investigation / AI verdict / melod agents (query-correction etc.) cannot be functionally validated locally. NAN-1297 escalation + AI-native-prompt surfaces need a working provider or demo tenant to test.

### Case grouping [VERIFIED OK] (NAN-1295/1296)
- PG: host(6)/user(3)/rule(5) grouped cases ALL have non-null grouping_key (0 nulls). 26 ungrouped (type='') have null key (expected). The "grouping_key:None" in the case-detail API is just a non-serialized field, not a DB null. device.hostname grouping works.

### F4 [P2] prevalence-artifacts endpoint 500/400 under OCSF (matching_logs CTE missing class-split hash columns)
- **Symptom**: `POST /api/search/prevalence-artifacts {query:"...", time_range}` → 400 for any query (generic `*` AND real `source_type="windows_sysmon" class_uid=1007`). Powers the prevalence scatter / artifact summaries UI.
- **CH error** (from logs): `Code: 47 UNKNOWN_IDENTIFIER: process.file.hashes.sha256 in scope SELECT DISTINCT if("process.file.hashes.sha256" != '', "process.file.hashes.sha256", "actor.process.file.hashes.sha256") AS hash FROM matching_logs WHERE (... != '') AND (length(...) >= 32)`. The outer artifact-extraction references the class-split OCSF hash expression, but the inner `matching_logs` CTE doesn't project those dotted columns.
- **Contrast**: inline `| prevalence process_hash`/`file_hash` pipe works (200) — NAN-1293 fix holds. Only the prevalence-ARTIFACTS endpoint path is broken.
- **Fix direction**: project the OCSF artifact columns into the `matching_logs` CTE (or compute the artifact expression inside it) so the outer DISTINCT can reference them. Related to NAN-1293; the NAN-1262 backlog lists "prevalence artifact-detail/inline-context column resolution" as needing coverage.

### Test-noise (NOT bugs) — confirmed via unquoted re-test
- `where "device.hostname"="X"` → 0 and `is_private_ip("src_endpoint.ip")` → 500: caused by ME quoting field names (SPL semantics: quoted = string literal). Unquoted forms all correct: where device.hostname=→109, src_endpoint.ip=→1044, user.name=→80, eval is_private_ip(src_endpoint.ip)→24. nPL where/eval over OCSF dotted fields works.

### Cloud / field-values [VERIFIED OK]
- cloud-dossier (intern01): populated — 16 IAM actions (Read 188/91-err), timeline, resources. cloud-overview, cloud-events, cloud-dossier all work under OCSF.
- field-values: returned VALUES are correct (svchost.exe 1652, taskhostw.exe 995 = CH top exactly). total_count is approximate & varies across runs (917/503/755) — likely SAMPLE-based, not clearly OCSF-specific (values, the thing autocomplete uses, are right). Not filing.

### F5 [related NAN-1301] asset-artifacts returns 0 hashes/domains despite data
- asset-artifacts for ws-eng-001.corp.local (BOTH device.hostname and src_host identifier) → hashes:0 domains:0, but CH shows 96 hash-bearing events on that host (72025 actor.process hashes overall). Host IS found (src_host dossier populated). So the artifact HASH EXTRACTION is broken under OCSF — same prevalence_processing.rs artifact-column-resolution family as NAN-1301 (there it 400s; here it silently returns empty). Should be fixed together.

### F6 [P1] Risk-entity auto-detect omits device.hostname → host sysmon findings get risk_entity="unknown"
- **Symptom**: 49 of the 2004 findings have unmapped.risk_entity="unknown" — ALL host-centric sysmon rules (persistence_scheduled_task_system 14, persistence_wmi_event_subscription 12, lsass_credential_dump_comsvcs 8, certutil_suspicious_download 8, persistence_registry_run_key 7). User/IP rules (cloudtrail, data_staging→jsmith, lateral_movement) attribute correctly.
- **Root cause**: `nanosiem-core/src/schema/ocsf.rs` OCSF_ENTITY_EXTRACTION_ORDER = [src_endpoint.ip, dst_endpoint.ip, user.name, actor.user.name, src_endpoint.hostname, dst_endpoint.hostname, file.hashes.sha256, process.file.hashes.sha256, http_request.url.hostname] — **device.hostname is MISSING**. Host-grouped sysmon match rows carry only device.hostname (group key); none of the listed fields are present → auto-detect (calculator.rs ~L300-320, loops entity_extraction_order + get_string_field) falls through to default → "unknown".
- **Impact**: hosts never accumulate risk from sysmon detections under OCSF; Risk page / entity-context for those hosts wrong/empty. Same class also feeds materialized_view + detection/service helpers risk auto-detect (per NAN-1296 audit) → real-time host detections affected too. Risk read side (entity-context, NAN-1254) works for the entities that DID resolve.
- **Fix**: add (EntityRole::SrcHost/Host, "device.hostname") to OCSF_ENTITY_EXTRACTION_ORDER (high priority for endpoint events) — mirrors the device.hostname additions already made for grouping (NAN-1295/96), matches entity (NAN-1287), shadow investigation (NAN-1291). UDM order unchanged.

### F7 [P1, USER-REPORTED] Asset event stream (AssetStream.tsx) hardcoded to UDM fields → events don't paint under OCSF
- **User report**: asset page lower section "completely fucked", events don't paint, `dest_host=-` shown, "Couldn't load full event (Invalid request body). Showing cached fields only."
- **Root cause (frontend)**: `nanosiem-web/src/components/search/asset/AssetStream.tsx` is UDM-hardcoded:
  - event `user` ← `details.user` (L524) — UDM; OCSF has user.name / actor.user.name.
  - client `classifyEventType` (L538-603) reads UDM `action`/`auth_result`/`file_action`/`category`/`process_name`/`dest_ip`/`src_port`/`dest_port`/`query` → can't classify OCSF events (everything → EVENT/wrong).
  - summary fallback key list (L616-625) = `['dest_host','dest_ip','process_name','command_line','file_path','query','event_type','message']` — all UDM → renders `dest_host=-` etc.
- **Server-side EVENT_TYPE_SQL is profile-aware (classification.rs), but this CLIENT fallback classifier + field rendering is UDM-only** (NAN-1256 fixed many components but missed AssetStream).
- **Secondary**: "Couldn't load full event (Invalid request body)" = 422 on event-detail load. fetch_log works server-side with valid {id,time_range,source_type}; suspect the asset event rows lack a real `id` under OCSF (AssetStream fabricates `event-<random>` at L519) or a companion field-stats/detail call sends an invalid body — needs the exact failing request from the browser network tab.
- **Combines with NAN-1300** (backend collect_asset_identifiers drops native OCSF identifier → empty dossier/identity). Asset page is broken across backend identifier + frontend stream + event-detail.
- **Fix**: make AssetStream profile-aware — resolve event fields + the summary key list via the active schema (/api/schema/fields or the OCSF field set), and use the server-attached `event_type` (don't fall back to the UDM client classifier under OCSF). Project a stable `id` on asset events.

### Rule engine [VERIFIED OK] detection-engine codegen matches OCSF queries
- /api/rules/test over the data window: rundll32-beacons>0 → 3, WMIC-/node:>0 → 3, lsass comsvcs-minidump (raw) → 39, proxy-blocked → 30. Detection codegen handles raw filters, CONTAINS, aggregates, thresholds, group-by device.hostname under OCSF.
- failed-login threshold rule returns 0 via rule-test = LEGIT per-execution-window bucketing (7 failures spread over 7h never >5 in one window); search-over-whole-window returns 2. Not a bug.
- Note: rule-test on a UDM-alias query (src_ip=) returns 200/0 (silent), NOT 500 — detection path doesn't hit the PREWHERE bug the same way as search. Rules are authored OCSF-native (rules-ocsf) so low impact.

### Dashboards [PARTIAL] query tool works native; UDM-alias inherits NAN-1299
- /api/dashboards/panel/query native (`* | stats count by device.hostname`) → 200, 5 rows ✓.
- UDM-alias (`src_ip=`) → 422. NAN-1299 (PREWHERE raw-token) reaches the dashboard query tool too. Blast radius of NAN-1299 = search + where + dashboard panel query (all 500/422); rule-test = silent 0.

### F8 [P2] Frontend entity-pivot query builders incomplete/broken under OCSF (NAN-1256 survivors)
- **MatchesDetail.tsx (42-46) = CORRECT reference**: ORs UDM+OCSF incl device.hostname → IP pivot 1779, host pivot 145. Works.
- **NotebookSidebar.tsx (414-447, 743-746)**: IP pivot `(src_ip OR dst_ip)` works (resolves, 1779). BUT user pivot `user="${value}"` (bare) → 0 results under OCSF (F1/NAN-1299 silent-0; truth 80). Host pivot `(src_host OR dst_host)` is UDM-only → resolves to src_endpoint.hostname/dst_endpoint.hostname, MISSES device.hostname (sysmon hosts under-counted). Hash pivot `(file_hash OR process_hash)` UDM-only.
- **RiskLeaderboard.tsx:67**: builds `${field}:${value}` with field in {user, "src_ip OR dest_ip", "src_host OR dest_host"} → 400 PARSE_ERROR "Colons are not allowed in keyword searches". Pivot from risk leaderboard is broken (syntax + UDM fields).
- **Fix**: adopt the MatchesDetail OR-both-incl-device.hostname pattern (or resolve via /api/schema/fields) for NotebookSidebar + RiskLeaderboard; fix RiskLeaderboard's `field:value`→`field="value"` syntax. NAN-1256 (closed) missed these.

### F9 [P2, NOT OCSF-specific] Aggregate rules re-alert historical data on re-evaluation → duplicate findings + risk inflation
- **Observation**: 2004 findings doubled 785→1535 with NO new data (ingestion ended Jun-7 23:25). Burst of 750 inserted Jun-8 11:40.
- **Root cause**: jobs up since 01:35Z but first rule execution Jun-8 11:40 (rules enabled/updated 11:20-11:25). At 11:40 the rules evaluated a lookback window covering the static Jun-7 data and re-alerted matches already alerted during ingestion. lateral_movement: 606 entities Jun-7, 662 Jun-8, **399 in BOTH** (same rule+entity re-alerted). Confirmed not internal dupes (0 by rule+entity+event_time) — because AGGREGATE-rule findings are stamped with DETECTION-time, not source-event time, so the natural dedup key is unique each execution → no cross-execution dedup.
- **Aggregate vs raw**: raw rules (lsass/persistence, keyed on event_hash) did NOT re-fire; only aggregate (`| stats`) rules (lateral_movement, cloudtrail bursts, proxy_blocked) re-alerted. The gap is dedup for aggregate findings.
- **Impact**: any rule edit/enable, jobs restart, or scheduler gap re-alerts the entire lookback window of historical matches → duplicate findings, inflated risk scores, potential alert storms. Schema-agnostic (would happen under UDM too); exposed here by static replayed data + rule enable.
- **NOT OCSF-specific** — filed outside NAN-1241.

### F10 [P2] cloud-overview "accounts" facet silently empty under OCSF (subquery scope; swallowed error)
- **Symptom**: `/api/search/cloud-overview` (6h) → 200, but accounts:[] (0) while risky_principals:8, service_health:10, changes:10 populate. Cloud overview page shows no accounts.
- **CH error (swallowed)**: search.log `cloud_overview subquery "cloud_overview.accounts" error Code 47: Unknown identifier actor.user.name in scope SELECT cloud.account.uid AS account_id, ..., uniqIf(if(actor.user.name!='',actor.user.name,user.name),...) AS principals ... FROM (<inner agg produces cnt grouped by account/provider>)`. The outer SELECT aggregates actor.user.name/user.name/cloud.region but the inner subquery doesn't project them → Code 47. Endpoint catches the subquery stream error → returns accounts:[] (silent partial failure).
- **Location**: nanosiem-core/src/search/service/cloud_overview.rs (accounts subquery builder). Same scope-resolution class as NAN-1301.
- **Fix**: project actor.user.name/user.name/cloud.region into the inner aggregation (or single-level aggregate) so the outer principals/regions aggregations resolve. Consider surfacing subquery errors instead of silently empty.

### lateral / cloud commands [OK / expected guards]
- `| cloud` 400 = intentional 6h-window limit (works within 6h: `* | cloud` 6h → 200, display=cloud). `* | lateral` 400 = "no seed entity" parse error (sample events don't populate seed fields); scoped `windows_event | lateral` → 200, 4552 rows, lateral graph ✓. Minor cosmetic: the lateral no-seed error lists UDM field names (src_host/dest_host/src_ip/dest_ip/user) under OCSF.
- Incidents: 0 exist — untested (no data).

### Shadow investigation hunt queries [OBSERVED, not filed]
- Shadow investigation runs (calls workers-ai/@cf/google/gemma) but the provider returns "Empty response from model" → verdict/NAN-1297 untestable locally.
- Two hunt queries failed in run_investigation: (a) Code 43 `lower(UInt64)` from a truncated `eval cmd_len=len(actor.process.cmd_line) | where cmd_len > …` query — could NOT reproduce in isolation (all `eval numeric | where numeric` variants return 200); likely a specific AI-generated query shape, needs exact query to pin. (b) PARSE_ERROR on `sequence by device.hostname … fields(actor.process.name) | table … step1_actor.process.name` — AI-generated invalid nPL (`fields(...)` as a function). Both gated by the dead AI provider; treat as AI-gen quality, not core codegen bugs.

### Log scan triage [COMPLETE]
- All Code 47 errors map to filed bugs: src_ip/src_host/dest_ip (NAN-1299), process.file.hashes.sha256 (NAN-1301), actor.user.name (NAN-1306). Code 392=DDL-prohibited (dev env, no admin creds — real-time MV). Code 202=too-many-queries (my load). Code 6=my quoted is_private_ip test. Code 43=unreproducible shadow-hunt query (above).

### NAN-1259 subsystems [VERIFIED OK under OCSF]
- siem-health: report computes correctly — "166213 events/24h, 6 source types, 0 high-ext-usage" (reads ocsf_logs + event-JSON paths). overall_score 83/healthy. (AI summary is the "AI unavailable" fallback — provider dead — but metrics are right.)
- GDPR anonymization: preview estimated_logs=682 EXACTLY matches CH (user.name OR actor.user.name = jsmith). service.rs uses active_logs_table() + double-quotes dotted OCSF columns. Created one pending test request (8dd84085…, never executed) during verification.

### nPL command + JSON-tail coverage [VERIFIED OK]
- Commands: top(85240), rare, sort/head, transaction(916 filtered), eval defang/extract_domain — all work under OCSF. dedup 400 = intentional unfiltered-guard.
- JSON-tail (non-promoted OCSF fields): `class_uid=2004 unmapped.risk_entity="jsmith"` → 18 = exact CH match; `stats by unmapped.risk_entity` → 49 groups. Non-promoted fields resolve via JSONExtract correctly.
- eval security funcs (defang, extract_domain, is_private_ip, len, if) all work over OCSF dotted fields (unquoted).

### Case entity extraction [VERIFIED OK] + incident rollup (implicit)
- case_entities under OCSF: ip 64, url 60, host 37, user 9. Host entities are real device.hostnames (ws-eng-001, ws-fin-007, lt-mkt-043, …) — 0 "unknown"/empty/'-' out of 170. All 7 host-grouped cases carry a host entity.
- KEY CONTRAST w/ NAN-1302: the CASE-path entity extraction (EntityExtractor + grouping, fixed by NAN-1287/91/96) gets device.hostname RIGHT; the RISK-calculator path (OCSF_ENTITY_EXTRACTION_ORDER) does NOT → fix = align risk order with the case path.
- Incidents: 0 exist, but rollup aggregates case_entities (correct) → implicitly OK. Matches API returns matches+events; entity resolution is client-side (helpers.ts, NAN-1287-fixed).

### NAN-1297 auto-escalation [VERIFIED END-TO-END under OCSF] ✅
- Setup: flipped local case_autonomy_mode→auto_close, floor 0.80; blaster baseline + injector --quick for case volume.
- Case 50 (encoded_powershell_execution): verdict TP/conf 1.0/recommended=critical (base high) → maybe_auto_escalate fired: severity high→critical, priority→4 (critical-derived), audit wall entry written ("Auto-escalated by AI Tier-1 triage: severity high → critical (confidence 100%)..."). severity==recommended confirmed.
- gemma verdict quality on this case was GOOD: decoded -EncodedCommand, identified multi-user coordinated PS, caught msedge→powershell parent/child anomaly. Verdict judgment is solid; soft spots remain structured-output reliability + hunt-query nPL gen.
- Earlier: recommend_only correctly persisted recommendation WITHOUT mutating (case 45 TP/critical stayed high). Both autonomy modes validated.

### "--quick fires no rules" [RESOLVED — not a bug]
- Root cause: log-blaster wasn't running (no continuous multi-host baseline → aggregate rules had no volume; injector's 9 events on one host insufficient + lateral-recon techniques not in rule set). With blaster running (~5k eps), rules fire normally and injector IOC steps create cases. Ingestion/detection pipeline healthy. Vector "unhealthy" = cosmetic (healthcheck GETs /health → 405); ingestion works.

## LOCAL STACK CHANGES MADE (revert if needed)
- system_settings.case_autonomy_mode: recommend_only → auto_close; case_auto_close_min_confidence: 0.85 → 0.80.
- 1 pending GDPR anonymization request (8dd84085…, never executed).

### AI "Empty response from model" — ROOT CAUSE: max-output truncation of reasoning models (not model quality, not OCSF)
- Switched gemma → kimi-k2.6 (workers-ai/@cf/moonshotai/kimi-k2.6, confirmed live). Kimi ALSO "empty-responses".
- Smoking gun: kimi usage = prompt_tokens=5048, **completion_tokens=4096** (a hard cap) → the model generated a FULL 4096 tokens but the structured verdict was TRUNCATED → parser reports "Response parsing error: Empty response from model". NOT empty — truncated.
- Mechanism: kimi is a REASONING model; reasoning tokens consume the 4096 output budget before the JSON/tool verdict finishes → unparseable. gemma succeeded more often only because its lighter reasoning fit under 4096.
- Implication: switching models won't fix it; the verdict/structured-output calls need a HIGHER max-output budget (or reasoning excluded / handled in parsing), and Workers-AI may hard-cap output at 4096 for these models (would make reasoning-model + structured-verdict infeasible via that gateway → use Moonshot-direct or raise the cap).
- Kimi verdict QUALITY still UNOBSERVED (every attempt truncated); can't judge until the token budget is fixed.

### Kimi k2.6 re-test (after max_tokens→32768) [VERIFIED GOOD]
- 32768 budget fixed the truncation: 3/3 cases triaged with verdicts in 10 min, 0 new empty-responses. Root cause confirmed = output-token cap (4096) strangling a reasoning model, NOT model quality / not OCSF.
- Kimi verdict QUALITY is strong + evidence-grounded:
  - case 52 encoded_powershell→needs_investigation/medium: recognized 742 action=Load events with NO encoded payloads (rule noise), but flagged a lone RDP(3389)-to-external-IP as un-clearable → needs_investigation. Sharp.
  - case 53 proxy→FP/low: IDs normal browsing (amazon/stackoverflow/cnn 443/80), notes one high-entropy domain.
  - case 54 encoded_powershell→benign/low: 8249 sysmon events routine Load/Create/Set.
  - All cite OCSF-native evidence (action=Load, device.hostname, IPs/ports/counts). Consistent w/ gemma's TP/critical on case 50 (a REAL multi-host PS attack) — both correct per case; Kimi more grounded.
- De-escalation recommendations (high→medium/low) are surfaced but NOT auto-applied by maybe_auto_escalate (escalate-only by design); auto-close path handles FP/benign. No wrong-dismissal of real attacks observed.
- Net: Kimi viable as the investigation model once token budgets are sized for reasoning (the 5 low agents bumped to 32768).
