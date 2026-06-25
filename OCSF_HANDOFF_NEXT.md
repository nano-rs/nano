# OCSF — session handoff (where we're at)

## Status: OCSF read+write path is conformant & working; one open data issue (enrichment coverage)

### Code locations
- **nanosiem** branch `feat/NAN-1241-ocsf-schema-support` (PR #1909). Today's fixes are **committed locally, NOT pushed** — the dev startup script builds from the local checkout, so rebuild picks them up.
- **parsers** repo `nano-rs/parsers` **main** — all OCSF parser fixes merged (PRs #9–#13). **Re-sync the parser repo** to pull them.
- `clickhouse/ocsf/init.sql` — OCSF table. ⚠️ `CREATE TABLE IF NOT EXISTS` won't ALTER; on any schema change **recreate**: drop the 3 `ocsf_*_prevalence_summary_mv` + `ocsf_logs`, re-run `init.sql` (admin creds `nanosiem_admin`/`nanosiem_admin_secret`; `nanosiem` user is DDL-prohibited). Already recreated with all of today's columns.

### Done today (all local commits on the branch unless noted)
- Parser OCSF conformance (process=subject/actor.process=parent; HTTP url→http_request.url; EID7→Module 1005; EID12/13→Registry 201001/201002; 4672→Authorize Session 3003; file/reg_value required attrs) — **shipped to parsers main**.
- NAN-1266 profile-aware repo sync (parsers-ocsf/ + rules-ocsf/); NAN-1270 batch-import wires dispatch+routing rule; NAN-1271 routing fallback always last; NAN-1275 deploy marks all enabled sources deployed; NAN-1277 OCSF key-field chips in slim projection; promoted process/module image-path columns; Extended-vs-Unmapped split + event-leaf expansion (frontend); NAN-1278 dual-mode enrichment.
- Linear epic **NAN-1241**; issues 1266/1268/1270/1271/1275/1277/1278 In Review.

## OPEN ISSUE — enrichment coverage (NOT an OCSF bug)
- OCSF enrichment **works**: dual-mode columns (`src/dst_endpoint.location.*`, `autonomous_system.*`, `enrichments.ioc_*/custom_*`) = `if(event-native, native, dictGet(...))`. Verified live: `198.51.100.x→US/ASN64500`, `18.165.83.x→Amazon`, `8.8.8.8→US`, native-wins.
- **The gap:** `ip_enrichment_dict` (shared with UDM) source table `nanosiem.ip_enrichments` has only **75,001 rows** (LOADED, Trie). That's a partial/sample `ipinfo_lite` load — a full IPinfo Lite set is far larger. So most real IPs miss (`40.213.87.216` Azure, `52.95.110.1` AWS → MISS); only ranges in the 75k resolve.
- **Same dict as UDM** → UDM misses the same IPs. So OCSF mapping is correct; the bottleneck is the data.
- **Next:** investigate the native **IPinfo Lite loader** (MMDB bulk-copy job; see memory `project_ipinfo_lite_stays_native`) — why `nanosiem.ip_enrichments` only has 75,001 ranges in this instance. Fix loads full coverage for both UDM + OCSF. Not OCSF-scoped.

## To test OCSF after a rebuild
Rebuild api/search (host, dev script) + web; re-sync parsers; blast log-blaster. Search uses OCSF field names (`source_type=conduit_proxy dst_endpoint.location.country=US`) — bare `aws_cloudtrail` is a keyword search (0 hits). Local CH: `:8123` nanosiem/nanosiem.
