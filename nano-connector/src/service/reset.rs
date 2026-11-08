// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3490 / NAN-3697: re-anchor one stream of a feed point-forward.
//!
//! A reset replaces the stream's checkpoint so the engine resumes the time
//! window walk at `now − INITIAL_CURSOR_OVERLAP_SECS`
//! ([`crate::point_forward::initial_cursor`]), exactly where a newly
//! activated stream starts, and records a fresh `point_forward` activation so
//! the stream's status shows the re-anchor. It does not touch other streams
//! and never backfills: there is no way to rewind earlier than the anchor.
//!
//! Only time-window streams without fan-out can be reset: their position is
//! a time. A cursor/iterator stream's position is vendor state (an opaque
//! token, an offset, a server-side iterator) with no time to rewind to.
//!
//! NAN-4931: an identity stream (`kind: identity`) can also be reset. Its
//! reset drops the vendor delta cursor so the next run is a FULL directory
//! walk (users missing from it are retired as usual). The previous full
//! run's row count is kept, so the shrink guard still protects that run.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::point_forward::{self, INITIAL_CURSOR_OVERLAP_SECS, POINT_FORWARD_KEY, PointForward};
use crate::spec::ConnectorSpec;

#[derive(Debug, thiserror::Error)]
pub enum ResetError {
    #[error("unknown stream for this feed; expected one of: {0}")]
    UnknownStream(String),
    #[error("stream `{0}` has no single time window and is not an identity stream; its position cannot be reset")]
    Unsupported(String),
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
    pub checkpoint: Value,
    /// An identity stream: the next run is a full directory resync.
    pub full_resync: bool,
}

/// Validate `stream` against the feed's pinned spec and build the
/// checkpoint to write: window resume at the anchor plus a fresh
/// `point_forward` record.
pub fn plan_reset(spec_yaml: &str, stream: &str, now: DateTime<Utc>) -> Result<ResetPlan, ResetError> {
    plan_reset_with_prior(spec_yaml, stream, now, None)
}

/// [`plan_reset`] with the stream's current checkpoint, which an identity
/// reset keeps the shrink-guard baseline from.
pub fn plan_reset_with_prior(spec_yaml: &str, stream: &str, now: DateTime<Utc>, prior: Option<&Value>) -> Result<ResetPlan, ResetError> {
    let spec = ConnectorSpec::from_yaml(spec_yaml).map_err(|_| ResetError::Spec)?;
    let Some(s) = spec.streams.iter().find(|s| s.id == stream) else {
        let ids: Vec<&str> = spec.streams.iter().map(|s| s.id.as_str()).collect();
        return Err(ResetError::UnknownStream(ids.join(", ")));
    };
    if s.identity.is_some() {
        let mut checkpoint = serde_json::json!({});
        if let Some(rows) = prior.and_then(|p| p.get(crate::engine::IDENTITY_LAST_FULL_ROWS)) {
            checkpoint[crate::engine::IDENTITY_LAST_FULL_ROWS] = rows.clone();
        }
        return Ok(ResetPlan { stream: s.id.clone(), anchor: now, checkpoint, full_resync: true });
    }
    if !matches!((&s.window, &s.fanout), (Some(_), None)) {
        return Err(ResetError::Unsupported(s.id.clone()));
    }
    let anchor = point_forward::initial_cursor(now);
    let mut checkpoint = crate::engine::window_rewind_checkpoint(anchor);
    checkpoint[POINT_FORWARD_KEY] = PointForward { initial_cursor: anchor, activating: false }.record(now);
    Ok(ResetPlan { stream: s.id.clone(), anchor, checkpoint, full_resync: false })
}

/// The shape of a checkpoint, never its contents (which can hold vendor
/// tokens or ids): for audit and display.
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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResetOutcome {
    pub stream: String,
    pub prior_checkpoint: bool,
    pub prior_kind: &'static str,
    /// The window start the next run resumes at (`now − 300 s`).
    pub anchor: DateTime<Utc>,
    pub max_lookback_secs: u64,
    pub next_run_at: DateTime<Utc>,
    /// An identity stream was reset: the next run is a full directory resync.
    pub full_resync: bool,
}

/// Reset one stream of `feed_id` in the caller's transaction. `Ok(None)` when
/// the feed does not exist.
///
/// Fencing: the feed row is locked, its `lease_generation` bumped and its
/// lease cleared. A run holding the older generation then fails its fenced
/// checkpoint write and its outcome, so it can never commit a cursor over the
/// reset. The checkpoint row is replaced in the same transaction.
pub async fn reset_stream_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    feed_id: Uuid,
    stream: &str,
    now: DateTime<Utc>,
) -> Result<Option<ResetOutcome>, ResetError> {
    let Some(row) = sqlx::query("SELECT spec_yaml FROM public.connector_feeds WHERE id = $1 FOR UPDATE")
        .bind(feed_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let spec_yaml: String = row.try_get("spec_yaml")?;
    let prior: Option<Value> =
        sqlx::query_scalar("SELECT state FROM public.connector_feed_checkpoints WHERE feed_id = $1 AND stream_id = $2")
            .bind(feed_id)
            .bind(stream)
            .fetch_optional(&mut **tx)
            .await?;
    let plan = plan_reset_with_prior(&spec_yaml, stream, now, prior.as_ref())?;
    let (generation, next_run_at): (i64, DateTime<Utc>) = sqlx::query_as(
        "UPDATE public.connector_feeds
            SET lease_generation = lease_generation + 1, lease_owner = NULL, lease_expires_at = NULL,
                next_run_at = now(), updated_at = now()
          WHERE id = $1
          RETURNING lease_generation, next_run_at",
    )
    .bind(feed_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO public.connector_feed_checkpoints (feed_id, stream_id, state, lease_generation, run_id)
         VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (feed_id, stream_id) DO UPDATE
            SET state = EXCLUDED.state, lease_generation = EXCLUDED.lease_generation, run_id = NULL,
                commits = public.connector_feed_checkpoints.commits + 1, updated_at = now()",
    )
    .bind(feed_id)
    .bind(&plan.stream)
    .bind(&plan.checkpoint)
    .bind(generation.max(1))
    .execute(&mut **tx)
    .await?;
    Ok(Some(ResetOutcome {
        stream: plan.stream,
        prior_checkpoint: prior.is_some(),
        prior_kind: checkpoint_kind(prior.as_ref()),
        anchor: plan.anchor,
        max_lookback_secs: if plan.full_resync { 0 } else { INITIAL_CURSOR_OVERLAP_SECS.unsigned_abs() },
        next_run_at,
        full_resync: plan.full_resync,
    }))
}
