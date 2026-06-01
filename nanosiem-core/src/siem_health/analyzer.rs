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
    match deployment_state(metrics) {
        DeploymentState::Fresh => return fresh_deployment_report(),
        DeploymentState::Stalled => return stalled_ingestion_report(metrics),
        DeploymentState::Live => {}
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
        recommendations: vec![],
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

// Simple heuristic scorers for fallback mode
fn score_ingestion(m: &IngestionMetrics) -> i32 {
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
    (100 - silent_penalty - volume_change).clamp(0, 100)
}

fn score_parsing(m: &ParsingMetrics) -> i32 {
    if m.field_coverage.is_empty() {
        return 50;
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
    (avg_coverage as i32 - ext_penalty).clamp(0, 100)
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
            },
            parsing: ParsingMetrics {
                field_coverage: vec![],
                high_ext_sources: vec![],
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
}
