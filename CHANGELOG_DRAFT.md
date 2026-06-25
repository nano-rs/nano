# Changelog draft — May 2026

Curated from 150 completed Nanos-sh issues over the last ~31 days (~47 user-facing).
Paste each into the Emdash admin → Changelog collection → New entry.
Set `change_type` and (optionally) `version_tag`. Body is plain prose, no em-dashes.
The `Refs:` line is for your tracking only — do NOT put NAN-ids in the published body.

---

## Recommended handful (7)

### 1. Search across all your cases
- **type:** feature
- **body:** Cases now has a dedicated search surface. Query every case at once with a faceted sidebar, a results histogram, an AND/OR filter builder, and a detail peek, all without leaving the list. Searches run server-side against real alert content, and you can save the ones you run often. Switch between structured and free-text modes depending on how you hunt.
- **Refs:** NAN-1071, NAN-1072, NAN-1074, NAN-1075, NAN-1076, NAN-1081

### 2. AI re-investigates a case as it grows
- **type:** feature
- **body:** When new alerts land on an existing case, the AI triage pass now re-runs automatically and frames its findings as a follow-up. Your investigation narrative stays current as the case evolves, instead of reflecting only the first alert that opened it.
- **Refs:** NAN-1059, NAN-1061, NAN-1062

### 3. Hunt across any JSON field, even unindexed ones
- **type:** feature
- **body:** The ext JSON column is now text-indexed, so you can run fast, granule-skipping searches over arbitrary log fields without knowing the key in advance. Free-text hunting now reaches the structured data you have not explicitly mapped to a UDM column.
- **Refs:** NAN-1022

### 4. Keyword searches got dramatically faster
- **type:** improvement
- **body:** A piped keyword step now uses the message text index instead of scanning the full table. On large hunts that cuts I/O by roughly 100x and avoids the out-of-memory failures that wide keyword searches used to hit.
- **Refs:** NAN-1153

### 5. Triage alerts without leaving the alert
- **type:** feature
- **body:** Acknowledge, assign, close, and escalate now work directly from the alert detail page, so the full first-response loop lives in one place.
- **Refs:** NAN-967, NAN-1067

### 6. Search correctness: fragments, Windows paths, and counts
- **type:** fix
- **body:** We fixed a set of quiet search bugs. Substring matches now behave as expected (src_host=/dc/ matches srv-dc01), Windows backslash paths match in both keyword and CONTAINS searches, and result counts are now correct on multi-stage and small-limit queries.
- **Refs:** NAN-1026, NAN-1158, NAN-1159, NAN-1160, NAN-1161, NAN-1027

### 7. A failed enrichment can no longer drop your logs
- **type:** fix
- **body:** Enrichment lookups are hardened so a single failing ClickHouse dictionary or identity source can no longer silently drop incoming logs. Ingestion keeps flowing even when one enrichment path has a bad day.
- **Refs:** NAN-1116, NAN-1114, NAN-1102, NAN-1120

---

## Optional extras (if you want 8 to 10)

### 8. Resolved identities are now searchable
- **type:** improvement
- **body:** Resolved-identity enrichment fields (user, source-user, and destination-user) are now visible and filterable across search, matching how geo and ASN enrichment already worked.
- **Refs:** NAN-1155, NAN-1151

### 9. See which log sources are healthy at a glance
- **type:** feature
- **body:** Source Configuration now surfaces bytes per day, last-event time, and per-rule fire counts, so you can tell which sources are active and pulling their weight.
- **Refs:** NAN-531

### 10. Real-time detections no longer silently miss
- **type:** fix
- **body:** The real-time materialized-view detection path was rebuilt to share the same query generator as scheduled rules, so a rule running in real-time mode now matches exactly what it matches on a schedule.
- **Refs:** NAN-1142

---

## Notes
- All entries will group under **May 2026** if published now (changelog groups by published_at month). The page has not been updated since April, so this fills the gap.
- `version_tag` left blank intentionally: I can't accurately map each feature to a release version. If you want versions shown (the page renders `v{tag}`), add them per entry, otherwise leave blank.
- Spread `published_at` across May if you'd rather they not all share one date.
