# Handoff — Observability convergence (NAN-1528 follow-on)

_Refreshed 2026-06-25. NAN-1555 (the convergence query plane) is **built and validated** on branch `feat/NAN-1555-npl-search-spans`._

## Status: NAN-1555 spans + metrics nPL — COMPLETE on the feature branch

All committed on `feat/NAN-1555-npl-search-spans`. Commits:

- **Phase 1 spans** — `/search?dataset=spans` runs nPL over `otel_spans`. `SpansProfile` + `SchemaId::Spans` + `FieldResolution::MapKey` (the `attributes['http.method']` Map tail with `resource_attributes` fallback); promoted span columns first-class; `service_name` stays itself (no UDM `cloud_service` alias); `duration_ns` numeric; keyword → `span_name` (idx_span_words); time → `start_time`. All generator seams gated so logs are byte-identical.
- **Spans polish** — dropped the spurious `cloud_service` stage_0 column (profile-aware field collection, `canon_collect`); `| join` subsearch orders on `start_time`.
- **Phase 2 metrics foundation** — `/search?dataset=metrics` over `otel_metrics`. `MetricsProfile` + `SchemaId::Metrics`; `value`/`count`/`sum` numeric; tag Map tail; `metric_name`/`service_name` lowercased-at-ingest for the set-index/sort-key prune.
- **Generic rollup (migration 144)** — `otel_metrics_1m`/`_1h` AggregatingMergeTree keyed `(metric_name, service_name, bucket)` (DateTime64 bucket), value_sum/count/min/max + quantilesTDigest state, MV-fed + backfilled. Rollup ≡ raw within 0.0002% (avg/p95/min/max).
- **Metrics query model** — gap-fill (`WITH FILL FROM..TO` full-window on metrics timechart); counter-reset-aware `rate()` (positive-delta sum of time-ordered values); **resolution routing** (`metrics_routing.rs`, conservative) onto the rollup for wide-window aggregate queries, with `rollup_value_agg` emitting the merged-state forms.

**Validation:** all 5 spans + full metrics acceptance queries executed against live CH; a 41-query matrix (spans/metrics/rollup/logs × keyword/filter/where/stats/timechart/in-list/tag/eval/sort/head) runs with **zero** runtime errors; rollup↔raw parity confirmed. Tests: `spans_codegen.rs` (13), `metrics_codegen.rs` (13), `metrics_routing.rs` (4), `schema::{spans,metrics}` units, + 116 in-crate generator tests (logs/spans/UDM byte-identity gates) all green. The only failing core-lib tests (6) are pre-existing disk-dependent `source_configs`/`audit` cases on `main`, unrelated.

Two `codex` adversarial passes during the build caught 4 real bugs (multi-stage attribute passthrough, IN-list MapKey, timechart/sparkline time column) — all fixed + test-guarded. A final multi-agent adversarial-review workflow ran before push.

The NAN-1534 scaffolding (dataset selector UI, `SearchRequest.dataset` + OpenAPI, per-query threading) was already present but non-functional — this work activates it end-to-end.

## Open backlog (filed, scoped)
- **NAN-1556** — OTLP-logs envelope→column mapping (severity/service/timestamp); one deterministic map extending `otlp_logs_prep`.
- **NAN-1554** — alert reopen endpoint (deferred; backend + OpenAPI + lifecycle).
- **Credibility gaps** — service dependency map, error-tracking inbox, metric→trace exemplars. Don't chase Datadog breadth.

## Carry-forward context (the thesis)
- **The moat is convergence**, not observability breadth: logs/spans/metrics/RUM in one CH store + shared entity overlay (`src_ip`/`user`/`host`), one query language (nPL), pivoting to security detections. Compete on "your client error → the trace → the auth log → the detection that fired on that IP, one query."
- **Datasets are orthogonal to the UDM/OCSF logs choice.** UDM-vs-OCSF governs ONLY logs. Spans/metrics are separate datasets with fixed OTel profiles — never "OCSF-unmapped." The bridge is **entities, not schemas**.
- **Validation discipline:** local CH validates correctness (codegen-blind is the recurring bug class — validate the EXACT generated multi-stage SQL, not a simplified version); re-run perf-sensitive queries at Saturn scale.
