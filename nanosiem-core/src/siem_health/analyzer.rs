// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rules-based SIEM-health analysis (open core).
//!
//! Produces a deterministic `AnalysisResult` from collected metrics without
//! invoking AI. Used as a fallback when AI is not configured or fails: see
//! `super::scheduler::run_health_check_with_trigger`, which calls the
//! `SiemHealthAiAnalyzer` extension trait first and falls through to
//! [`fallback_report`] on `Err`.
//!
//! The AI-driven path (system prompt + AI invocation + JSON parsing) lives
//! in `nanosiem-enterprise::siem_health::ai_analyzer` (lifted in Phase 3.6
//! of NAN-744).

use super::types::*;

/// Lightweight view of a suppression that can be injected into AI prompts
/// or matched against fallback findings. Defined here so neither the
/// scheduler nor the enterprise AI analyzer needs to depend on the
/// suppressions DB layer; `scheduler` maps repository rows into this shape.
#[derive(Debug, Clone)]
pub struct SuppressedFinding {
    pub title: String,
    pub reason: String,
}

/// Produce a fallback report when AI is unavailable or fails.
///
/// First classifies the deployment (Fresh / Stalled / Live) and short-circuits
/// to a tailored report for the empty-deployment cases (NAN-617). For Live
/// deployments, runs the per-dimension heuristic scorers.
pub fn fallback_report(metrics: &CollectedMetrics) -> AnalysisResult {
    // NAN-616 / NAN-617: zero events in the last 48h means one of two very
    // different things — and confusing them was the bug NAN-617 fixed. A
    // fresh deployment with no setup is fine; a configured tenant whose
    // ingestion stopped is a critical outage.
    //
    // NAN-1405: a firing hard-critical insert-integrity signal bypasses BOTH
    // shortcircuits. A FAILED logs dict discards every insert, so a tenant
    // whose first events all bounced still has zero stored events — Fresh
    // would report 100/healthy while data is actively being lost, and
    // Stalled's generic report would bury the precise dictionary pointer the
    // Live-path scorer and recommendations carry.
    if !has_critical_insert_integrity(&metrics.ingestion.insert_integrity) {
        match deployment_state(metrics) {
            DeploymentState::Fresh => return fresh_deployment_report(),
            DeploymentState::Stalled => return stalled_ingestion_report(metrics),
            DeploymentState::Live => {}
        }
    }

    // Simple heuristic scoring without AI
    let ingestion_score = score_ingestion(&metrics.ingestion);
    let parsing_score = score_parsing(&metrics.parsing);
    let enrichment_score = score_enrichment(&metrics.enrichment);
    let detection_score = score_detection(&metrics.detection);
    let alerting_score = score_alerting(&metrics.alerting, &metrics.detection);
    let overall_score = (ingestion_score as f64 * 0.25
        + parsing_score as f64 * 0.20
        + enrichment_score as f64 * 0.15
        + detection_score as f64 * 0.25
        + alerting_score as f64 * 0.15) as i32;

    let alerting_summary_total: i64 = metrics.alerting.total_alerts_24h;

    AnalysisResult {
        overall_score,
        ingestion_score,
        parsing_score,
        enrichment_score,
        detection_score,
        alerting_score,
        summary: format!(
            "**Automated health check** (AI unavailable)\n\n\
             - **Ingestion**: {} source types active, {} events in last 24h, {} silent sources\n\
             - **Parsing**: {} source types analyzed, {} with high ext usage\n\
             - **Enrichment**: GeoIP {:.0}% · ASN {:.0}% · IOC {:.0}% · identity {:.0}%\n\
             - **Detection**: {} enabled rules, {} stale, {} noisy\n\
             - **Alerting**: {} alerts in 24h, {} active webhooks, {} routing rules",
            metrics.ingestion.source_volumes.len(),
            metrics.ingestion.total_events_24h,
            metrics.ingestion.silent_sources.len(),
            metrics.parsing.field_coverage.len(),
            metrics.parsing.high_ext_sources.len(),
            metrics.enrichment.geoip_fill_pct,
            metrics.enrichment.asn_fill_pct,
            metrics.enrichment.ioc_hit_pct,
            metrics.enrichment.identity_fill_pct,
            metrics.detection.total_enabled_rules,
            metrics.detection.stale_rules.len(),
            metrics.detection.noisy_rules.len(),
            alerting_summary_total,
            metrics.alerting.active_webhooks,
            metrics.alerting.active_routing_rules,
        ),
        // NAN-1405: fired insert-integrity signals become explicit critical/high
        // recommendations even without AI — silent ingestion loss must never
        // depend on an LLM being reachable to surface.
        // NAN-1643: same posture for ingest-lowercase invariant drift — silent
        // query divergence must not depend on an LLM either.
        recommendations: {
            let mut recs =
                insert_integrity_recommendations(&metrics.ingestion.insert_integrity);
            recs.extend(lowercase_invariant_recommendations(&metrics.parsing));
            recs
        },
        dimension_details: DimensionDetails {
            ingestion: "AI analysis unavailable".to_string(),
            parsing: "AI analysis unavailable".to_string(),
            enrichment: "AI analysis unavailable".to_string(),
            detection: "AI analysis unavailable".to_string(),
            alerting: "AI analysis unavailable".to_string(),
        },
    }
}

/// Three high-level deployment states the heuristic recognizes before
/// falling through to per-dimension scoring (NAN-617).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentState {
    /// No events anywhere AND no operator setup yet — fresh install. Score
    /// 100, no findings: nothing to assess.
    Fresh,
    /// No events in the last 48h but the tenant HAS setup (rules, routing,
    /// or webhooks configured). Ingestion has stalled — critical.
    Stalled,
    /// Events are flowing; run the normal heuristic.
    Live,
}

fn deployment_state(metrics: &CollectedMetrics) -> DeploymentState {
    let no_events = metrics.ingestion.total_events_24h == 0
        && metrics.ingestion.total_events_prior_24h == 0
        && metrics.enrichment.total_events_24h == 0;
    if !no_events {
        return DeploymentState::Live;
    }
    // "Configured" = the operator has done meaningful setup. Any of these
    // signals indicates this is not a brand-new tenant: enabled detection
    // rules, queue routing rules, or webhook destinations.
    let configured = metrics.detection.total_enabled_rules > 0
        || metrics.alerting.active_routing_rules > 0
        || metrics.alerting.active_webhooks > 0;
    if configured {
        DeploymentState::Stalled
    } else {
        DeploymentState::Fresh
    }
}

/// Heuristic response for a brand-new deployment with no operator setup
/// and no events. Score 100; nothing to assess yet.
fn fresh_deployment_report() -> AnalysisResult {
    AnalysisResult {
        overall_score: 100,
        ingestion_score: 100,
        parsing_score: 100,
        enrichment_score: 100,
        detection_score: 100,
        alerting_score: 100,
        summary: "**Fresh deployment.** No events have been ingested yet \
                  and no detection rules, routing rules, or webhooks are \
                  configured. The platform is idle — connect a log source \
                  and the next health check will produce a real assessment."
            .to_string(),
        recommendations: vec![],
        dimension_details: DimensionDetails {
            ingestion: "No events ingested yet — this is a fresh deployment."
                .to_string(),
            parsing: "No events to parse.".to_string(),
            enrichment: "No events to enrich.".to_string(),
            detection: "No detection rules configured yet.".to_string(),
            alerting: "No alerts because no detections fired.".to_string(),
        },
    }
}

/// Heuristic response for a configured tenant whose ingestion has stalled.
/// This is a critical outage: agents stopped, Vector died, network gateway
/// blocked, or upstream filtering is dropping everything. The operator
/// almost always wants to know about it loudly.
fn stalled_ingestion_report(metrics: &CollectedMetrics) -> AnalysisResult {
    let rules = metrics.detection.total_enabled_rules;
    let routing = metrics.alerting.active_routing_rules;
    let webhooks = metrics.alerting.active_webhooks;

    let mut configured_bits = Vec::new();
    if rules > 0 {
        configured_bits.push(format!("{rules} detection rule(s) enabled"));
    }
    if routing > 0 {
        configured_bits.push(format!("{routing} routing rule(s) configured"));
    }
    if webhooks > 0 {
        configured_bits.push(format!("{webhooks} webhook(s) configured"));
    }
    let configured_summary = configured_bits.join(", ");

    AnalysisResult {
        // Treat ingestion as down (0) and the rest as unknown — without events
        // there's nothing to score positively. Overall lands deep in the red.
        overall_score: 10,
        ingestion_score: 0,
        parsing_score: 0,
        enrichment_score: 0,
        detection_score: 50,
        alerting_score: 50,
        summary: format!(
            "**Ingestion has stalled.** No events received in the last 48h, \
             but this tenant is configured ({configured_summary}). Detection \
             rules cannot fire on data that isn't arriving — this is a \
             critical outage, not an idle deployment. Investigate log \
             sources, Vector / agent connectivity, and upstream filtering."
        ),
        recommendations: vec![Recommendation {
            title: "Investigate stalled ingestion: zero events in the last 48h"
                .to_string(),
            description: format!(
                "This tenant has {configured_summary} but no events have \
                 been ingested in the last 48 hours. Check that Vector and \
                 any forwarders are running, that log sources are still \
                 enabled, and that upstream filtering / network gateways \
                 are not dropping traffic. Until events resume, no \
                 detection rule can fire and no alerts will be generated."
            ),
            priority: "critical".to_string(),
        }],
        dimension_details: DimensionDetails {
            ingestion: "**No events in the last 48h.** This tenant is \
                        configured (rules / routing / webhooks present), so \
                        empty ingestion is an outage, not a fresh-install \
                        idle state."
                .to_string(),
            parsing: "No events flowing means nothing to parse.".to_string(),
            enrichment: "No events flowing means nothing to enrich.".to_string(),
            detection: format!(
                "{rules} rule(s) are enabled but cannot fire without \
                 ingestion."
            ),
            alerting: "No alerts will be generated until ingestion resumes."
                .to_string(),
        },
    }
}

/// NAN-1405: true when an insert-integrity signal proves rows are being
/// discarded right now — a FAILED dict referenced by the logs MATERIALIZED
/// columns (every flush THROWs), or INSERTs finishing for an hour with ZERO
/// new parts reaching disk (the exact NAN-1404 correlation that diagnosed
/// Saturn). The >=10 floor keeps a quiet tenant's trickle from alarming on a
/// thin window. Shared by the scorer, the recommendations, and the
/// deployment-state bypass in `fallback_report`.
fn has_critical_insert_integrity(ii: &InsertIntegrityMetrics) -> bool {
    !ii.failed_logs_dictionaries.is_empty()
        // NAN-1461: require the part_log probe to have actually run — a missing
        // system.part_log grant leaves new_parts_1h at its default 0 while
        // query_log inserts read fine, which otherwise reads as "data loss".
        || (ii.new_parts_probe_ok && ii.logs_inserts_1h >= 10 && ii.new_parts_1h == 0)
}

// Simple heuristic scorers for fallback mode
fn score_ingestion(m: &IngestionMetrics) -> i32 {
    // NAN-1405: insert-path integrity first — these signals mean rows are
    // being discarded RIGHT NOW, regardless of what the 24h volume windows
    // show (during the first hours of a NAN-1404-style outage the 24h totals
    // still look normal). Checked before the empty-source-volumes early
    // return: a long-dead pipeline can have empty volumes AND a FAILED dict.
    let ii = &m.insert_integrity;
    if has_critical_insert_integrity(ii) {
        return 5;
    }

    if m.source_volumes.is_empty() {
        return 50;
    }
    let silent_penalty = (m.silent_sources.len() as i32) * 15;
    let volume_change = if m.total_events_prior_24h > 0 {
        let pct = (m.total_events_24h as f64 - m.total_events_prior_24h as f64)
            / m.total_events_prior_24h as f64;
        if pct < -0.5 {
            30
        } else if pct < -0.2 {
            15
        } else {
            0
        }
    } else {
        0
    };
    // Secondary integrity tells: not proof of loss on their own, but the
    // NAN-1404 collateral signatures — worth dragging the score down.
    let mut integrity_penalty = 0;
    if ii.async_insert_failures_1h.unwrap_or(0) > 0 {
        integrity_penalty += 30;
    }
    if ii.memory_limit_errors > 0 {
        integrity_penalty += 20;
    }
    if ii.cache_dictionary_update_fails > 0 {
        integrity_penalty += 15;
    }
    // NAN-1407: a failing/stale dict-staging refresh degrades ENRICHMENT
    // freshness, not ingestion — rows keep landing with the last good
    // snapshot (that's the entire point of the staging indirection). Worth a
    // visible drag, never the critical floor.
    if !ii.stale_dict_refreshes.is_empty() {
        integrity_penalty += 15;
    }
    (100 - silent_penalty - volume_change - integrity_penalty).clamp(0, 100)
}

/// Recommendations for fired insert-integrity signals (NAN-1405). Used by the
/// heuristic fallback path; the enterprise AI analyzer sees the same metrics
/// JSON and produces its own. Each maps a signal to the diagnostic recipe
/// proven during NAN-1404 (dict status → part_log → system.errors).
fn insert_integrity_recommendations(ii: &InsertIntegrityMetrics) -> Vec<Recommendation> {
    let mut recs = Vec::new();
    if !ii.failed_logs_dictionaries.is_empty() {
        let dicts = ii
            .failed_logs_dictionaries
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        recs.push(Recommendation {
            title: format!("Unhealthy enrichment dictionary is halting ingestion: {dicts}"),
            description: format!(
                "The logs table's MATERIALIZED columns call dictGetOrDefault on {dicts}, and an \
                 unhealthy dictionary makes that call THROW on every insert flush — all incoming \
                 batches are being discarded while every upstream ACK stays green (NAN-1404). \
                 This is either FAILED status OR a degraded CACHE dict (e.g. a prevalence dict) \
                 that reports LOADED while its source errors and every lookup throws (NAN-1667). \
                 Inspect system.dictionaries.last_exception, fix the dictionary source, then \
                 SYSTEM RELOAD DICTIONARY to restore ingestion."
            ),
            priority: "critical".to_string(),
        });
    }
    if ii.new_parts_probe_ok && ii.logs_inserts_1h >= 10 && ii.new_parts_1h == 0 {
        recs.push(Recommendation {
            title: format!(
                "{} log INSERTs in the last hour produced ZERO new parts on disk",
                ii.logs_inserts_1h
            ),
            description: "INSERTs into the logs table keep finishing (the ingest chain is \
                 ACKing), but part_log shows no new parts reaching storage — async-insert \
                 flushes are discarding every batch (the NAN-1404 silent-loss fingerprint). \
                 Check system.dictionaries for FAILED dictionaries, system.errors for \
                 MEMORY_LIMIT_EXCEEDED, and system.asynchronous_insert_log for flush \
                 exceptions."
                .to_string(),
            priority: "critical".to_string(),
        });
    }
    if ii.async_insert_failures_1h.unwrap_or(0) > 0 {
        let failures = ii.async_insert_failures_1h.unwrap_or(0);
        recs.push(Recommendation {
            title: format!("{failures} async-insert flush failures in the last hour"),
            description: format!(
                "system.asynchronous_insert_log recorded {failures} non-Ok flush entries — \
                 those batches were ACKed to the sender and then dropped. Last exception: {}",
                ii.last_async_insert_error.as_deref().unwrap_or("(none)")
            ),
            priority: "critical".to_string(),
        });
    }
    if ii.memory_limit_errors > 0 {
        recs.push(Recommendation {
            title: "ClickHouse is hitting its memory limit".to_string(),
            description: format!(
                "system.errors shows {} MEMORY_LIMIT_EXCEEDED occurrences with activity in the \
                 last 24h. On a memory-capped deployment this is the NAN-1404 trigger: \
                 dictionary loads / insert flushes OOM and ingestion fails. Check dictionary \
                 source queries and merge pressure before it escalates.",
                ii.memory_limit_errors
            ),
            priority: "high".to_string(),
        });
    }
    if ii.cache_dictionary_update_fails > 0 {
        recs.push(Recommendation {
            title: "Cache dictionary updates are failing".to_string(),
            description: format!(
                "system.errors shows {} CACHE_DICTIONARY_UPDATE_FAIL occurrences with activity \
                 in the last 24h — a cache-layout dictionary (e.g. hash_prevalence_dict) cannot \
                 refresh from its source. Inspect system.dictionaries.last_exception for the \
                 failing dictionary.",
                ii.cache_dictionary_update_fails
            ),
            priority: "high".to_string(),
        });
    }
    if !ii.stale_dict_refreshes.is_empty() {
        let views = ii
            .stale_dict_refreshes
            .iter()
            .map(|r| r.view.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let detail = ii
            .stale_dict_refreshes
            .iter()
            .find(|r| !r.exception.is_empty())
            .map(|r| format!(" Last refresh exception: {}", r.exception))
            .unwrap_or_default();
        recs.push(Recommendation {
            title: format!("Enrichment dictionary refresh is failing or stale: {views}"),
            description: format!(
                "The dictionary-staging refresh views ({views}) are failing, disabled, or \
                 overdue past their refresh schedule (system.view_refreshes). Ingestion is NOT \
                 affected — the dictionaries keep serving the last good staging snapshot \
                 (NAN-1407) — but enrichment values (GeoIP/IOC/identity/prevalence) are \
                 drifting stale. Inspect system.view_refreshes.exception, fix the \
                 underlying source query/table, then SYSTEM REFRESH VIEW to catch up.{detail}"
            ),
            priority: "high".to_string(),
        });
    }
    recs
}

/// NAN-1643: recommendation for fired ingest-lowercase invariant violations.
/// High, not critical, per the house line: critical is reserved for proven
/// data LOSS (NAN-1405); this is data landing but silently invisible to
/// raw-compare queries — a correctness degradation with the rows still
/// recoverable once the lane is fixed.
fn lowercase_invariant_recommendations(p: &ParsingMetrics) -> Vec<Recommendation> {
    if p.lowercase_invariant_violations.is_empty() {
        return vec![];
    }
    let columns = p
        .lowercase_invariant_violations
        .iter()
        .map(|v| format!("{} ({} rows)", v.column, v.violation_count))
        .collect::<Vec<_>>()
        .join(", ");
    vec![Recommendation {
        title: format!(
            "Ingest-lowercase invariant broken: mixed-case values landing in {}",
            p.lowercase_invariant_violations
                .iter()
                .map(|v| v.column.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        description: format!(
            "In the last hour, rows landed with mixed-case values in ingest-lowercased \
             column(s): {columns}. The query engine compares these columns RAW (no lower() \
             wrapper) so their bloom/primary-key indexes prune — equality searches and \
             detection rules on these fields will silently MISS the mixed-case rows \
             (case-sensitive divergence, no error). Find the ingest lane writing them \
             (a new source, a backfill, or a parser regression that skips the Vector \
             downcase stage) and restore lowercase normalization; existing mixed-case \
             rows should be rewritten or re-ingested."
        ),
        priority: "high".to_string(),
    }]
}

fn score_parsing(m: &ParsingMetrics) -> i32 {
    // NAN-1643: active ingest-lowercase invariant drift means raw-compare
    // queries are silently missing rows RIGHT NOW — a hard drag on the score
    // regardless of how good field coverage looks, and applied even on the
    // low-volume early return (a single mixed-case lane can predate coverage).
    let invariant_penalty = if m.lowercase_invariant_violations.is_empty() {
        0
    } else {
        30
    };
    if m.field_coverage.is_empty() {
        return (50 - invariant_penalty).clamp(0, 100);
    }
    let avg_coverage: f64 = m
        .field_coverage
        .iter()
        .map(|f| {
            (f.src_ip_filled_pct
                + f.user_filled_pct
                + f.event_type_filled_pct
                + f.message_filled_pct)
                / 4.0
        })
        .sum::<f64>()
        / m.field_coverage.len() as f64;
    let ext_penalty = (m.high_ext_sources.len() as i32) * 10;
    (avg_coverage as i32 - ext_penalty - invariant_penalty).clamp(0, 100)
}

fn score_enrichment(m: &EnrichmentMetrics) -> i32 {
    if m.total_events_24h == 0 {
        // No events yet — don't penalize an empty deployment.
        return 50;
    }
    // Score on GeoIP + ASN, the universally-applicable network enrichments,
    // now measured over geo-eligible rows (NAN-1178). Identity enrichment and
    // IOC hit rate are informational, not scoring signals: most deployments
    // never populate a user registry, so weighting identity (the old 0.2)
    // dragged otherwise-healthy enrichment into the Warning band.
    let weighted = m.geoip_fill_pct * 0.6 + m.asn_fill_pct * 0.4;
    weighted.clamp(0.0, 100.0) as i32
}

fn score_detection(m: &DetectionMetrics) -> i32 {
    if m.total_enabled_rules == 0 {
        return 0;
    }
    let stale_pct = m.stale_rules.len() as f64 / m.total_enabled_rules as f64;
    let stale_penalty = if stale_pct > 0.5 {
        50
    } else if stale_pct > 0.25 {
        25
    } else {
        (stale_pct * 40.0) as i32
    };
    let noise_penalty = (m.noisy_rules.len() as i32) * 5;
    (100 - stale_penalty - noise_penalty).clamp(0, 100)
}

fn score_alerting(m: &AlertingMetrics, d: &DetectionMetrics) -> i32 {
    // Detections-only posture: when no rule is in Alerting mode, zero alerts is
    // correct *by design*. Per the Staging → Live → Alerting lifecycle, Live-mode
    // rules count matches and log signals but never raise alerts. Many
    // deployments run this way deliberately. Flagging it as a pipeline outage
    // (the old behaviour) was a false alarm — NAN-1178.
    let alerting_mode_rules: i64 = d
        .rules_by_mode
        .iter()
        .filter(|r| r.mode.eq_ignore_ascii_case("alerting"))
        .map(|r| r.count)
        .sum();

    if alerting_mode_rules == 0 {
        // Engine actively firing detections, just not wired to alert → healthy.
        // Otherwise nothing is matching either → mild warning, not critical.
        return if d.total_matches_24h > 0 { 90 } else { 70 };
    }

    // At least one rule is in Alerting mode → alerts ARE expected here. Run the
    // health heuristic, including the genuine outage signal.
    let mut score: i32 = 80;

    // Volume signal — alerts stopped despite alerting-mode rules that fired
    // yesterday is a real outage. Now correctly gated on alerting-mode rules.
    if m.total_alerts_24h == 0 && m.total_alerts_prior_24h > 0 {
        score -= 50;
    }

    // MTTA signal: reward fast acks, penalize slow ones.
    if let Some(mtta) = m.mean_mtta_minutes {
        if mtta > 240.0 {
            score -= 20;
        } else if mtta > 60.0 {
            score -= 10;
        } else if mtta < 15.0 {
            score += 10;
        }
    }

    // Webhook delivery health.
    if let Some(success_pct) = m.webhook_success_pct {
        if success_pct < 80.0 {
            score -= 20;
        } else if success_pct < 95.0 {
            score -= 5;
        }
    }

    // No webhooks AND no routing rules = no alerting plumbing.
    if m.active_webhooks == 0 && m.active_routing_rules == 0 {
        score -= 15;
    }

    score.clamp(0, 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-617: a fresh install with no operator setup and no events yet
    /// must score 100/healthy with an empty recommendations list. Otherwise
    /// the page yellow-flags every brand-new deployment.
    #[test]
    fn fresh_deployment_returns_100s() {
        let metrics = base_zero_metrics_fixture();
        // No rules, no routing, no webhooks → fresh
        assert_eq!(deployment_state(&metrics), DeploymentState::Fresh);

        let report = fallback_report(&metrics);
        assert_eq!(report.overall_score, 100);
        assert_eq!(report.ingestion_score, 100);
        assert!(report.recommendations.is_empty());
        assert!(
            report.summary.contains("Fresh deployment"),
            "summary should explain the deployment is fresh, not faulty"
        );
    }

    /// NAN-617: a configured tenant (rules / routing / webhooks present)
    /// with zero events for 48h is a critical outage, NOT a healthy idle
    /// deployment. This is the bug the user hit: 4 rules + 2 routing rules
    /// + 0 events scored 100/healthy under NAN-616.
    #[test]
    fn stalled_ingestion_returns_critical() {
        let mut metrics = base_zero_metrics_fixture();
        metrics.detection.total_enabled_rules = 4;
        metrics.alerting.active_routing_rules = 2;
        assert_eq!(deployment_state(&metrics), DeploymentState::Stalled);

        let report = fallback_report(&metrics);
        assert_ne!(
            report.overall_score, 100,
            "stalled ingestion must NOT score 100 — that was the NAN-617 bug"
        );
        assert!(report.overall_score < 50, "stalled ingestion is critical");
        assert_eq!(report.ingestion_score, 0);
        assert!(
            !report.recommendations.is_empty(),
            "stalled ingestion must surface a recommendation, not stay silent"
        );
        let rec = &report.recommendations[0];
        assert_eq!(rec.priority, "critical");
        assert!(
            rec.title.to_lowercase().contains("stalled"),
            "recommendation title must reference stalled ingestion, got: {}",
            rec.title
        );
        assert!(
            report.summary.contains("stalled") || report.summary.contains("Ingestion has stalled"),
            "summary must lead with stalled-ingestion language"
        );
    }

    /// Even a single configured webhook flips fresh → stalled. Don't let
    /// the only-rules-count check sneak past the guard.
    #[test]
    fn webhook_alone_is_enough_to_flip_fresh_to_stalled() {
        let mut metrics = base_zero_metrics_fixture();
        metrics.alerting.active_webhooks = 1;
        assert_eq!(deployment_state(&metrics), DeploymentState::Stalled);
    }

    /// Sanity: when events ARE flowing, neither shortcut fires and the
    /// per-dimension heuristics run. Asserts the early-return doesn't eat
    /// real traffic.
    #[test]
    fn live_deployment_runs_normal_heuristic() {
        let mut metrics = base_zero_metrics_fixture();
        metrics.ingestion.total_events_24h = 100_000;
        metrics.ingestion.total_events_prior_24h = 95_000;
        metrics.enrichment.total_events_24h = 100_000;
        metrics.enrichment.geoip_fill_pct = 80.0;
        metrics.enrichment.asn_fill_pct = 70.0;
        assert_eq!(deployment_state(&metrics), DeploymentState::Live);

        let report = fallback_report(&metrics);
        // Not the shortcut output (no "Fresh" / "stalled" verbiage).
        assert!(!report.summary.contains("Fresh deployment"));
        assert!(!report.summary.contains("stalled"));
    }

    /// If 24h is empty but prior-24h had events, the deployment is in
    /// transition (a real volume drop), not stalled-since-forever — must
    /// fall through to the per-dimension heuristic so the existing volume
    /// scoring catches it.
    #[test]
    fn prior_24h_events_keeps_us_in_live_state() {
        let mut metrics = base_zero_metrics_fixture();
        metrics.ingestion.total_events_prior_24h = 1_000;
        assert_eq!(deployment_state(&metrics), DeploymentState::Live);
    }

    /// Base fixture with everything at zero — tests above tweak fields to
    /// exercise specific deployment_state branches.
    fn base_zero_metrics_fixture() -> CollectedMetrics {
        CollectedMetrics {
            ingestion: IngestionMetrics {
                source_volumes: vec![],
                total_events_24h: 0,
                total_events_prior_24h: 0,
                silent_sources: vec![],
                insert_integrity: Default::default(),
            },
            parsing: ParsingMetrics {
                field_coverage: vec![],
                high_ext_sources: vec![],
                lowercase_invariant_violations: vec![],
            },
            enrichment: EnrichmentMetrics {
                total_events_24h: 0,
                geoip_fill_pct: 0.0,
                asn_fill_pct: 0.0,
                ioc_hit_pct: 0.0,
                identity_fill_pct: 0.0,
                identity_fill_prior_pct: 0.0,
                per_source_coverage: vec![],
                providers: vec![],
            },
            detection: DetectionMetrics {
                total_enabled_rules: 0,
                total_matches_24h: 0,
                rules_by_mode: vec![],
                stale_rules: vec![],
                noisy_rules: vec![],
                alerts_24h_by_severity: vec![],
            },
            alerting: AlertingMetrics {
                total_alerts_24h: 0,
                total_alerts_prior_24h: 0,
                by_status: vec![],
                mean_mtta_minutes: None,
                active_webhooks: 0,
                webhook_deliveries_24h: 0,
                webhook_success_pct: None,
                active_routing_rules: 0,
            },
            collected_at: chrono::Utc::now(),
        }
    }

    fn detection_with(alerting_rules: i64, matches: i64) -> DetectionMetrics {
        let mut rules_by_mode = vec![RulesByMode {
            mode: "live".to_string(),
            count: 26,
        }];
        if alerting_rules > 0 {
            rules_by_mode.push(RulesByMode {
                mode: "alerting".to_string(),
                count: alerting_rules,
            });
        }
        DetectionMetrics {
            total_enabled_rules: 26 + alerting_rules,
            total_matches_24h: matches,
            rules_by_mode,
            stale_rules: vec![],
            noisy_rules: vec![],
            alerts_24h_by_severity: vec![],
        }
    }

    fn alerting_zeroed() -> AlertingMetrics {
        AlertingMetrics {
            total_alerts_24h: 0,
            total_alerts_prior_24h: 0,
            by_status: vec![],
            mean_mtta_minutes: None,
            active_webhooks: 0,
            webhook_deliveries_24h: 0,
            webhook_success_pct: None,
            active_routing_rules: 0,
        }
    }

    /// NAN-1178: detections-only deployment — Live-mode rules firing thousands
    /// of matches, no rule in Alerting mode, zero alerts. That is correct by
    /// design and must score Healthy, NOT flag an outage.
    #[test]
    fn detections_only_with_matches_is_healthy() {
        let det = detection_with(0, 8_778);
        let score = score_alerting(&alerting_zeroed(), &det);
        assert!(
            score >= 80,
            "detections firing + no alerting-mode rules must be Healthy, got {score}"
        );
    }

    /// No alerting-mode rules AND nothing matching → mild Warning, not critical.
    #[test]
    fn detections_only_but_quiet_is_warning_not_critical() {
        let det = detection_with(0, 0);
        let score = score_alerting(&alerting_zeroed(), &det);
        assert!(
            (50..80).contains(&score),
            "no alerting rules + no matches should be Warning band, got {score}"
        );
    }

    /// A genuine outage — a rule IS in Alerting mode and alerts fired yesterday
    /// but stopped today — must still be penalized into the critical band.
    #[test]
    fn alerting_mode_rule_gone_silent_is_critical() {
        let det = detection_with(3, 5_000);
        let mut alerting = alerting_zeroed();
        alerting.total_alerts_prior_24h = 40; // fired yesterday, zero today
        let score = score_alerting(&alerting, &det);
        assert!(
            score < 50,
            "alerting-mode rule that went silent must be critical, got {score}"
        );
    }

    /// NAN-1178: enrichment is scored on GeoIP + ASN only; a deployment with
    /// healthy network enrichment but no user-registry (identity 0%) must not
    /// be dragged into the Warning band by the missing identity signal.
    #[test]
    fn enrichment_healthy_geo_asn_scores_healthy_without_identity() {
        let mut m = EnrichmentMetrics {
            total_events_24h: 1_000_000,
            geoip_fill_pct: 95.0,
            asn_fill_pct: 90.0,
            ioc_hit_pct: 0.0,
            identity_fill_pct: 0.0,
            identity_fill_prior_pct: 0.0,
            per_source_coverage: vec![],
            providers: vec![],
        };
        assert!(
            score_enrichment(&m) >= 80,
            "healthy geo+asn must score Healthy regardless of identity"
        );
        // And a real geo gap still drags the score down.
        m.geoip_fill_pct = 10.0;
        m.asn_fill_pct = 10.0;
        assert!(score_enrichment(&m) < 50, "genuinely low geo/asn is still bad");
    }

    /// NAN-1405: a healthy ingestion fixture for the insert-integrity tests —
    /// volumes that would score Healthy without the integrity signals.
    fn healthy_ingestion() -> IngestionMetrics {
        IngestionMetrics {
            source_volumes: vec![SourceVolumeMetric {
                source_type: "windows_event".to_string(),
                count_24h: 1_000_000,
                count_prior_24h: 1_000_000,
                change_pct: 0.0,
            }],
            total_events_24h: 1_000_000,
            total_events_prior_24h: 1_000_000,
            silent_sources: vec![],
            insert_integrity: InsertIntegrityMetrics {
                probes_available: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn failed_logs_dict_forces_critical_ingestion_score() {
        // NAN-1405: a FAILED dict referenced by the logs MATERIALIZED columns
        // is a guaranteed total ingestion halt — must score critical even
        // when the 24h volume windows still look perfectly healthy (Saturn
        // looked "healthy" for 36 hours).
        let mut m = healthy_ingestion();
        m.insert_integrity.failed_logs_dictionaries = vec![FailedDictionary {
            name: "nanosiem.ip_enrichment_dict".to_string(),
            last_exception: "MEMORY_LIMIT_EXCEEDED".to_string(),
        }];
        assert!(
            score_ingestion(&m) < 50,
            "FAILED logs dict must be critical (got {})",
            score_ingestion(&m)
        );
        let recs = insert_integrity_recommendations(&m.insert_integrity);
        assert!(
            recs.iter()
                .any(|r| r.priority == "critical" && r.title.contains("ip_enrichment_dict")),
            "must raise a critical recommendation naming the dict; got {recs:?}"
        );
    }

    #[test]
    fn inserts_without_new_parts_force_critical_ingestion_score() {
        // The exact NAN-1404 correlation: INSERTs keep finishing (ACK layer
        // green) while zero new parts reach disk. NOTE deliberately NOT keyed
        // on written_rows — per-query async entries read written_rows=0 even
        // when healthy (791/795 on a healthy node, verified live).
        let mut m = healthy_ingestion();
        m.insert_integrity.logs_inserts_1h = 452;
        m.insert_integrity.new_parts_1h = 0;
        m.insert_integrity.new_parts_probe_ok = true; // we actually measured 0
        assert!(
            score_ingestion(&m) < 50,
            "inserts-without-parts must be critical (got {})",
            score_ingestion(&m)
        );
        let recs = insert_integrity_recommendations(&m.insert_integrity);
        assert!(
            recs.iter()
                .any(|r| r.priority == "critical" && r.title.contains("ZERO new parts")),
            "must raise a critical inserts-without-parts recommendation; got {recs:?}"
        );

        // NAN-1461: 0 parts because the part_log probe COULDN'T run (missing
        // grant) must NOT alarm — query_log inserts read fine while new_parts
        // defaults to 0. This is the Saturn false positive.
        let mut no_probe = healthy_ingestion();
        no_probe.insert_integrity.logs_inserts_1h = 481;
        no_probe.insert_integrity.new_parts_1h = 0;
        no_probe.insert_integrity.new_parts_probe_ok = false;
        assert!(
            score_ingestion(&no_probe) >= 80,
            "missing part_log probe must not read as data loss (got {})",
            score_ingestion(&no_probe)
        );
        assert!(
            !insert_integrity_recommendations(&no_probe.insert_integrity)
                .iter()
                .any(|r| r.title.contains("ZERO new parts")),
            "must not raise inserts-without-parts when the probe didn't run"
        );

        // ...but a quiet tenant's trickle must NOT page on a thin window.
        let mut quiet = healthy_ingestion();
        quiet.insert_integrity.logs_inserts_1h = 3;
        quiet.insert_integrity.new_parts_1h = 0;
        quiet.insert_integrity.new_parts_probe_ok = true;
        assert!(
            score_ingestion(&quiet) >= 80,
            "below the floor, a thin window is not an alarm"
        );

        // ...and inserts with parts landing is healthy operation.
        let mut healthy = healthy_ingestion();
        healthy.insert_integrity.logs_inserts_1h = 452;
        healthy.insert_integrity.new_parts_1h = 6;
        assert!(
            score_ingestion(&healthy) >= 80,
            "parts landing means storage is receiving data"
        );
    }

    #[test]
    fn secondary_integrity_tells_drag_score_down() {
        // Flush failures + OOM counters: not the hard-critical path, but the
        // score must reflect that the insert path is degrading.
        let mut m = healthy_ingestion();
        m.insert_integrity.async_insert_failures_1h = Some(7);
        m.insert_integrity.memory_limit_errors = 204;
        let score = score_ingestion(&m);
        assert!(
            score < 80,
            "flush failures + OOM must not score Healthy (got {score})"
        );
        let recs = insert_integrity_recommendations(&m.insert_integrity);
        assert!(
            recs.iter().any(|r| r.priority == "critical"
                && r.title.contains("flush failures")),
            "flush failures are confirmed loss — critical; got {recs:?}"
        );
        assert!(
            recs.iter()
                .any(|r| r.priority == "high" && r.title.contains("memory limit")),
            "OOM counter is a high-priority tell; got {recs:?}"
        );
    }

    #[test]
    fn stale_dict_refresh_is_high_priority_not_critical() {
        // NAN-1407: a failing dict-staging refresh degrades ENRICHMENT
        // freshness — rows still land with the last good snapshot (that is
        // the entire point of the staging indirection). It must drag the
        // score and raise a high-priority recommendation, but must NOT trip
        // the hard-critical path reserved for proven data loss.
        let mut m = healthy_ingestion();
        m.insert_integrity.stale_dict_refreshes = vec![StaleDictRefresh {
            view: "ip_enrichment_dict_refresh".to_string(),
            exception: "Code: 241. DB::Exception: MEMORY_LIMIT_EXCEEDED".to_string(),
            last_success_age_secs: 7200,
        }];
        let score = score_ingestion(&m);
        assert!(
            (50..90).contains(&score),
            "stale refresh drags the score without hitting the critical floor (got {score})"
        );
        let recs = insert_integrity_recommendations(&m.insert_integrity);
        let rec = recs
            .iter()
            .find(|r| r.title.contains("ip_enrichment_dict_refresh"))
            .expect("must raise a recommendation naming the stale refresh view");
        assert_eq!(
            rec.priority, "high",
            "staleness is degradation, not loss — never critical"
        );
        assert!(
            rec.description.contains("Ingestion is NOT affected"),
            "the rec must say rows keep landing: {}",
            rec.description
        );
    }

    /// NAN-1643: ingest-lowercase invariant drift must drag the parsing score
    /// and raise a high-priority recommendation naming the offending columns
    /// and counts — the consequence (raw-compare queries silently missing
    /// rows) must never depend on an LLM being reachable to surface.
    #[test]
    fn lowercase_invariant_violations_drag_parsing_and_recommend() {
        let clean = ParsingMetrics {
            field_coverage: vec![],
            high_ext_sources: vec![],
            lowercase_invariant_violations: vec![],
        };
        assert!(lowercase_invariant_recommendations(&clean).is_empty());
        let clean_score = score_parsing(&clean);

        let mut drifting = clean.clone();
        drifting.lowercase_invariant_violations = vec![
            LowercaseInvariantViolation {
                column: "src_ip".to_string(),
                violation_count: 1_842,
            },
            LowercaseInvariantViolation {
                column: "user".to_string(),
                violation_count: 12,
            },
        ];
        assert!(
            score_parsing(&drifting) < clean_score,
            "active invariant drift must drag the parsing score"
        );

        let recs = lowercase_invariant_recommendations(&drifting);
        assert_eq!(recs.len(), 1, "one finding covering all columns");
        let rec = &recs[0];
        assert_eq!(
            rec.priority, "high",
            "divergence is degradation, not proven loss — high, not critical"
        );
        assert!(
            rec.title.contains("src_ip") && rec.title.contains("user"),
            "finding must name the offending columns: {}",
            rec.title
        );
        assert!(
            rec.description.contains("1842 rows") && rec.description.contains("12 rows"),
            "finding must carry per-column counts: {}",
            rec.description
        );
        assert!(
            rec.description.to_lowercase().contains("miss"),
            "finding must explain the consequence (raw-compare queries miss rows): {}",
            rec.description
        );

        // ...and it survives into the fallback report on a live deployment.
        let mut metrics = base_zero_metrics_fixture();
        metrics.ingestion.total_events_24h = 100_000;
        metrics.enrichment.total_events_24h = 100_000;
        metrics.parsing = drifting;
        let report = fallback_report(&metrics);
        assert!(
            report
                .recommendations
                .iter()
                .any(|r| r.priority == "high" && r.title.contains("Ingest-lowercase")),
            "invariant finding must survive into the fallback report; got {:?}",
            report.recommendations
        );
    }

    #[test]
    fn healthy_integrity_raises_nothing() {
        let m = healthy_ingestion();
        assert!(score_ingestion(&m) >= 90, "healthy fixture scores healthy");
        assert!(
            insert_integrity_recommendations(&m.insert_integrity).is_empty(),
            "no integrity signals → no recommendations"
        );
        // async_insert_failures_1h == Some(0) (log enabled, zero failures) is
        // healthy, distinct from None (log not enabled).
        let mut with_log = healthy_ingestion();
        with_log.insert_integrity.async_insert_failures_1h = Some(0);
        assert!(insert_integrity_recommendations(&with_log.insert_integrity).is_empty());
    }

    #[test]
    fn critical_insert_integrity_bypasses_fresh_and_stalled_shortcircuits() {
        // NAN-1405: a tenant whose FIRST events all bounced off a FAILED dict
        // has zero stored events and (often) no rules yet — deployment_state
        // calls that Fresh and NAN-617's shortcircuit would report 100/healthy
        // while data is actively being lost. The integrity-critical bypass
        // must route it to the Live scorer instead.
        let mut metrics = base_zero_metrics_fixture();
        metrics.ingestion.insert_integrity = InsertIntegrityMetrics {
            probes_available: true,
            failed_logs_dictionaries: vec![FailedDictionary {
                name: "nanosiem.ip_enrichment_dict".to_string(),
                last_exception: "MEMORY_LIMIT_EXCEEDED".to_string(),
            }],
            ..Default::default()
        };
        let report = fallback_report(&metrics);
        assert!(
            report.ingestion_score < 50,
            "FAILED dict on a zero-event deployment must not report healthy (got {})",
            report.ingestion_score
        );
        assert!(
            report
                .recommendations
                .iter()
                .any(|r| r.priority == "critical" && r.title.contains("ip_enrichment_dict")),
            "the dict pointer must survive into the report; got {:?}",
            report.recommendations
        );
    }

    #[test]
    fn pre_nan1405_reports_deserialize_without_insert_integrity() {
        // Reports stored before NAN-1405 lack the insert_integrity key — the
        // serde(default) must keep them loadable.
        let old_json = r#"{
            "source_volumes": [],
            "total_events_24h": 5,
            "total_events_prior_24h": 7,
            "silent_sources": []
        }"#;
        let m: IngestionMetrics =
            serde_json::from_str(old_json).expect("pre-NAN-1405 report deserializes");
        assert!(!m.insert_integrity.probes_available);
        assert!(m.insert_integrity.async_insert_failures_1h.is_none());
    }
}
