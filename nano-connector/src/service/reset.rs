//! NAN-3490 / NAN-3697: re-anchor one stream of a feed point-forward.
//!
//! A reset replaces the stream's checkpoint so the engine resumes the time
//! window walk at the reset's anchor, `now − INITIAL_CURSOR_OVERLAP_SECS`
//! ([`crate::point_forward::initial_cursor`]), exactly where a newly
//! activated stream starts, with the stream's `initial_state`. It records a
//! fresh `point_forward` activation (`activated_at` = the reset time,
//! `initial_cursor` = the anchor) so the stream's status shows the re-anchor.
//! It does not touch any other stream.
//!
//! A reset never backfills: there is no way to rewind a stream earlier than
//! the anchor (bounded backfill needs an explicit product decision, and is
//! off). A window's `max_backfill_secs` / `initial_lookback_secs` do not
//! widen anything. The optional `since` exists for clients that send one:
//! it must lie in `[anchor, now]`, anything earlier (a backfill) or later
//! (the future) is refused, never clamped; an accepted `since` does not move
//! the anchor.
//!
//! Only time-window streams without fan-out can be reset: their position is
//! a time, so "start at the anchor" has one meaning for every connector. A
//! cursor/iterator stream's position is vendor state (an opaque token, an
//! offset, a server-side iterator), which has no time to rewind to.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::point_forward::{self, INITIAL_CURSOR_OVERLAP_SECS, POINT_FORWARD_KEY, PointForward};
use crate::spec::ConnectorSpec;

#[derive(Debug, thiserror::Error)]
pub enum ResetError {
    #[error("unknown stream for this feed; expected one of: {0}")]
    UnknownStream(String),
    #[error("stream `{0}` has no time window; its position cannot be reset to a time")]
    Unsupported(String),
    #[error(
        "since must be between {earliest} and {latest}: a reset never backfills, it re-anchors the stream at now − {max_lookback_secs} s"
    )]
    OutOfRange { earliest: String, latest: String, max_lookback_secs: u64 },
    #[error("the feed's pinned connector spec cannot be read")]
    Spec,
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

/// What to write for one stream reset.
#[derive(Debug, Clone, PartialEq)]
pub struct ResetPlan {
    pub stream: String,
    /// Where the stream's next pass starts: `now − INITIAL_CURSOR_OVERLAP_SECS`.
    pub anchor: DateTime<Utc>,
    /// How far before `now` the anchor sits (always the point-forward
    /// overlap, 300 s).
    pub max_lookback_secs: u64,
    pub checkpoint: Value,
}

/// Validate `stream` (and `since`, when given) against the feed's pinned
/// spec and build the checkpoint to write: window resume at the anchor plus
/// a fresh `point_forward` record.
pub fn plan_reset(
    spec_yaml: &str,
    stream: &str,
    since: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<ResetPlan, ResetError> {
    let spec = ConnectorSpec::from_yaml(spec_yaml).map_err(|_| ResetError::Spec)?;
    let Some(s) = spec.streams.iter().find(|s| s.id == stream) else {
        let ids: Vec<&str> = spec.streams.iter().map(|s| s.id.as_str()).collect();
        return Err(ResetError::UnknownStream(ids.join(", ")));
    };
    if !matches!((&s.window, &s.fanout), (Some(_), None)) {
        return Err(ResetError::Unsupported(s.id.clone()));
    }
    let anchor = point_forward::initial_cursor(now);
    let max_lookback_secs = INITIAL_CURSOR_OVERLAP_SECS.unsigned_abs();
    if since.is_some_and(|since| since < anchor || since > now) {
        return Err(ResetError::OutOfRange {
            earliest: point_forward::fmt_rfc3339(anchor),
            latest: point_forward::fmt_rfc3339(now),
            max_lookback_secs,
        });
    }
    let mut checkpoint = crate::engine::window_rewind_checkpoint(anchor);
    checkpoint[POINT_FORWARD_KEY] = PointForward { initial_cursor: anchor, activating: false }.record(now);
    Ok(ResetPlan { stream: s.id.clone(), anchor, max_lookback_secs, checkpoint })
}

/// The shape of a checkpoint, never its contents (which can hold vendor
/// tokens or ids): for audit.
pub fn checkpoint_kind(state: Option<&Value>) -> &'static str {
    let Some(v) = state else { return "none" };
    if v.get("items").is_some() {
        "fanout"
    } else if v.pointer("/window/resume").is_some() {
        "window_resume"
    } else if v.pointer("/window/watermark").is_some() {
        "window_watermark"
    } else if v.get("state").is_some() {
        "state"
    } else {
        "other"
    }
}

/// The result of [`reset_stream_checkpoint`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResetOutcome {
    pub stream: String,
    pub prior_checkpoint: bool,
    pub prior_kind: &'static str,
    /// The window start the next run resumes at (`now − 300 s`).
    pub anchor: DateTime<Utc>,
    pub max_lookback_secs: u64,
    pub next_run_at: DateTime<Utc>,
}

/// Reset one stream of `feed_id` in the caller's (tenant-scoped, signed)
/// transaction. `Ok(None)` when the feed is not visible to it.
///
/// Fencing: the feed row is locked, its `lease_generation` bumped and its
/// lease cleared (the `enable` / uninstall pattern). A run holding the older
/// generation then fails its fenced checkpoint write (`save_checkpoint` locks
/// the feed row FOR SHARE and requires its generation) and its `finish`, so
/// it can never commit a cursor over the reset. The checkpoint row is
/// replaced in the same transaction, stamped with the new generation.
///
/// Repeatable: each reset writes the same shape anchored at its own `now`
/// (`now − 300 s`), so a repeat re-anchors again and can never move the
/// stream earlier than five minutes before the latest reset (the generation
/// moves again, which only fences a run started in between).
pub async fn reset_stream_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    feed_id: Uuid,
    stream: &str,
    since: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    actor: Option<Uuid>,
) -> Result<Option<ResetOutcome>, ResetError> {
    let Some(row) = sqlx::query("SELECT spec_yaml FROM public.connector_feeds WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(tenant_id)
        .bind(feed_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let spec_yaml: String = row.try_get("spec_yaml")?;
    let plan = plan_reset(&spec_yaml, stream, since, now)?;
    let prior: Option<Value> = sqlx::query_scalar(
        "SELECT state FROM public.connector_feed_checkpoints WHERE tenant_id = $1 AND feed_id = $2 AND stream_id = $3",
    )
    .bind(tenant_id)
    .bind(feed_id)
    .bind(&plan.stream)
    .fetch_optional(&mut **tx)
    .await?;
    let (generation, next_run_at): (i64, DateTime<Utc>) = sqlx::query_as(
        "UPDATE public.connector_feeds
            SET lease_generation = lease_generation + 1, lease_owner = NULL, lease_expires_at = NULL,
                next_run_at = now(), revision = revision + 1, updated_at = now(), updated_by = COALESCE($3, updated_by)
          WHERE tenant_id = $1 AND id = $2
          RETURNING lease_generation, next_run_at",
    )
    .bind(tenant_id)
    .bind(feed_id)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO public.connector_feed_checkpoints (tenant_id, feed_id, stream_id, state, lease_generation, run_id)
         VALUES ($1, $2, $3, $4, $5, NULL)
         ON CONFLICT (tenant_id, feed_id, stream_id) DO UPDATE
            SET state = EXCLUDED.state, lease_generation = EXCLUDED.lease_generation, run_id = NULL,
                commits = public.connector_feed_checkpoints.commits + 1, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(feed_id)
    .bind(&plan.stream)
    .bind(&plan.checkpoint)
    .bind(generation)
    .execute(&mut **tx)
    .await?;
    Ok(Some(ResetOutcome {
        stream: plan.stream,
        prior_checkpoint: prior.is_some(),
        prior_kind: checkpoint_kind(prior.as_ref()),
        anchor: plan.anchor,
        max_lookback_secs: plan.max_lookback_secs,
        next_run_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OKTA: &str = include_str!("../../tests/fixtures/specs/okta_system_log.yaml");
    const GWS: &str = include_str!("../../tests/fixtures/specs/google_workspace.yaml");

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn reset_anchors_at_now_minus_overlap_and_never_backfills() {
        let now = t("2026-10-12T12:00:00Z");
        let anchor = t("2026-10-12T11:55:00Z");
        let expected = json!({
            "window": {"resume": anchor.timestamp_millis()},
            "point_forward": {"activated_at": "2026-10-12T12:00:00Z", "initial_cursor": "2026-10-12T11:55:00Z", "overlap_secs": 300},
        });
        // No since, or any since in [now − 300 s, now]: the anchor is always now − 300 s.
        for since in [None, Some(anchor), Some(t("2026-10-12T11:58:00Z")), Some(now)] {
            let p = plan_reset(OKTA, "system_log", since, now).unwrap();
            assert_eq!((p.anchor, p.max_lookback_secs), (anchor, 300), "{since:?}");
            assert_eq!(p.checkpoint, expected, "{since:?}");
        }
        assert_eq!(point_forward::initial_cursor(now), anchor);
        // Earlier than the anchor (a backfill) or in the future: refused, never clamped.
        for bad in ["2026-10-12T11:54:59Z", "2026-10-12T12:00:01Z", "2025-01-01T00:00:00Z"] {
            let e = plan_reset(OKTA, "system_log", Some(t(bad)), now).unwrap_err();
            assert!(matches!(e, ResetError::OutOfRange { .. }), "{bad}");
            assert!(e.to_string().contains("never backfills"), "{e}");
        }
        // A declared max_backfill_secs (or a long initial_lookback_secs) no longer widens the bound.
        let wide = OKTA.replace("initial_lookback_secs: 300", "initial_lookback_secs: 86400\n      max_backfill_secs: 86400");
        assert_ne!(wide, OKTA, "fixture shape changed");
        let p = plan_reset(&wide, "system_log", None, now).unwrap();
        assert_eq!((p.anchor, p.max_lookback_secs), (anchor, 300));
        for bad in ["2026-10-11T12:00:00Z", "2026-10-12T11:00:00Z"] {
            assert!(matches!(plan_reset(&wide, "system_log", Some(t(bad)), now), Err(ResetError::OutOfRange { .. })), "{bad}");
        }
    }

    #[test]
    fn the_reset_record_is_what_the_engine_reads_back() {
        let now = t("2026-10-12T12:00:00Z");
        let p = plan_reset(OKTA, "system_log", None, now).unwrap();
        // A later run keeps the recorded anchor and is not a new activation.
        let pf = PointForward::from_saved(&p.checkpoint, t("2026-10-12T13:00:00Z"));
        assert_eq!((pf.initial_cursor, pf.activating), (p.anchor, false));
        assert_eq!(checkpoint_kind(Some(&p.checkpoint)), "window_resume");
    }

    #[test]
    fn unknown_fanout_and_cursor_streams_are_refused() {
        let now = Utc::now();
        assert!(matches!(plan_reset(OKTA, "other", None, now), Err(ResetError::UnknownStream(ids)) if ids == "system_log"));
        // The dedicated Google spec fans out per application: no single time.
        assert!(matches!(plan_reset(GWS, "activities", None, now), Err(ResetError::Unsupported(_))));
        let cursor = r#"
version: 1
name: cursor
kind: collector
allow: [{ host: api.example.com }]
streams:
  - id: s
    request: { url: "https://api.example.com/v1/items" }
    pagination: { type: token, from: next, param: page }
"#;
        assert!(matches!(plan_reset(cursor, "s", None, now), Err(ResetError::Unsupported(_))));
        assert!(matches!(plan_reset("not: [a spec", "s", None, now), Err(ResetError::Spec)));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn hosted_google_feed_is_one_window_stream() {
        // The hosted install pins one application per feed (fan-out removed),
        // so its single `activities` stream is resettable, point-forward only:
        // its 1-day initial lookback no longer allows a 1-day rewind.
        let config = json!({"connector_spec": GWS, "connector_spec_sha256": crate::service::feed::spec_sha256(GWS)});
        let plan = crate::service::hosted_plan::plan_stream(Uuid::new_v4(), "google_workspace", &config, "login").unwrap();
        let now = t("2026-10-12T12:00:00Z");
        let p = plan_reset(&plan.spec_yaml, "activities", None, now).unwrap();
        assert_eq!((p.anchor, p.max_lookback_secs), (t("2026-10-12T11:55:00Z"), 300));
        assert!(matches!(
            plan_reset(&plan.spec_yaml, "activities", Some(t("2026-10-11T12:00:00Z")), now),
            Err(ResetError::OutOfRange { .. })
        ));
        assert!(plan_reset(&plan.spec_yaml, "login", None, now).is_err(), "the engine stream id, not the catalog stream");
    }

    #[test]
    fn checkpoint_kind_names_the_shape_only() {
        assert_eq!(checkpoint_kind(None), "none");
        assert_eq!(checkpoint_kind(Some(&json!({"window": {"watermark": 1, "seen": {"secret-uid": 1}}}))), "window_watermark");
        assert_eq!(checkpoint_kind(Some(&json!({"window": {"resume": 1}}))), "window_resume");
        assert_eq!(checkpoint_kind(Some(&json!({"items": {"login": {}}}))), "fanout");
        assert_eq!(checkpoint_kind(Some(&json!({"state": {"cursor": "tok"}}))), "state");
        assert_eq!(checkpoint_kind(Some(&json!({}))), "other");
    }
}
