// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4915: live PostgreSQL + ClickHouse proofs for durable search background
//! jobs — completion and paging from the ClickHouse results table, attach to an
//! identical live job, lease reclaim after a lost worker (a search-service
//! restart) with the stale attempt fenced out, attempt exhaustion, cancellation
//! (queued and running), and execution under the stamped source scope.
//!
//! Needs a migrated PostgreSQL at `DATABASE_URL` and a ClickHouse at
//! `CLICKHOUSE_URL` whose schema the `clickhouse_migrator` has brought current
//! (credentials from the usual `CLICKHOUSE_*` env, admin user for seeding).
//! `#[ignore]`d; run with `-- --ignored --test-threads=1`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use nanosiem_core::auth::ScopeSet;
use nanosiem_core::search::SearchJobStatus;
use nanosiem_core::search::background::{
    BackgroundJobConfig, BackgroundSearchJobs, JobErrorKind, JobOrigin, SearchJobRepository,
    SearchJobResultStore,
};
use nanosiem_core::{DualPool, DualPoolConfig, SearchRequest, SearchService, TimeRangeInput};
use uuid::Uuid;

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:8123".to_string())
}

fn ch_admin() -> (String, String) {
    (
        std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".to_string()),
        std::env::var("CLICKHOUSE_ADMIN_PASSWORD")
            .unwrap_or_else(|_| "nanosiem_admin_secret".to_string()),
    )
}

/// Run one statement as the ClickHouse admin (seeding / inspection).
async fn ch_exec(sql: &str) -> String {
    let (user, password) = ch_admin();
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/?async_insert=0&wait_end_of_query=1",
            ch_url()
        ))
        .basic_auth(user, Some(password))
        .body(sql.to_string())
        .send()
        .await
        .expect("clickhouse reachable");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "clickhouse error for `{sql}`: {body}");
    body
}

/// Seed `rows` events of a unique source_type in the last hour. Inserted in
/// bounded chunks: every insert also pushes through the `logs` MVs, which a
/// single multi-million-row block can drive past a small test server's memory.
async fn seed(source_type: &str, rows: u64) {
    const CHUNK: u64 = 250_000;
    let mut start = 0;
    while start < rows {
        let n = CHUNK.min(rows - start);
        ch_exec(&format!(
            "INSERT INTO nanosiem.logs (timestamp, id, source_type, message, src_ip, user) \
             SELECT now64(6) - toIntervalMillisecond(number % 3000000), \
                    generateUUIDv4(), '{source_type}', \
                    concat('nan4915 event ', toString(number)), \
                    IPv4NumToString(toUInt32(167772160 + number % 65536)), \
                    concat('user', toString(number % 97)) \
             FROM numbers({start}, {n})"
        ))
        .await;
        start += n;
    }
}

struct Harness {
    pool: sqlx::PgPool,
    search: Arc<SearchService>,
    dual: DualPool,
}

async fn harness() -> Harness {
    let pool = common::migrated_pool().await;
    let config = DualPoolConfig::from_env().expect("DualPool env");
    let mut dual = DualPool::new(&config).await.expect("connect DualPool");
    dual.refresh_cluster_state(&config.clickhouse_database).await;
    let search = Arc::new(SearchService::with_dual_pool(&dual));
    Harness { pool, search, dual }
}

impl Harness {
    fn jobs(&self, worker: &str, config: BackgroundJobConfig) -> BackgroundSearchJobs {
        self.jobs_with_page_budget(worker, config, None)
    }

    fn jobs_with_page_budget(
        &self,
        worker: &str,
        config: BackgroundJobConfig,
        page_budget: Option<usize>,
    ) -> BackgroundSearchJobs {
        let mut store =
            SearchJobResultStore::new(self.dual.clickhouse().clone(), self.dual.table_names());
        if let Some(bytes) = page_budget {
            store = store.with_page_byte_budget(bytes);
        }
        BackgroundSearchJobs::with_worker_id(
            SearchJobRepository::new(self.pool.clone()),
            store,
            self.search.clone(),
            config,
            worker.to_string(),
        )
    }
}

fn fast_config() -> BackgroundJobConfig {
    BackgroundJobConfig {
        concurrency: 2,
        lease_ttl: Duration::from_secs(2),
        heartbeat_interval: Duration::from_millis(500),
        poll_interval: Duration::from_millis(200),
        result_cap: 100_000,
        max_execution_secs: 120,
        max_attempts: 3,
        interactive_handoff: Duration::from_secs(1),
        max_live_jobs_per_owner: 10,
        result_max_bytes: 256 * 1024 * 1024,
    }
}

fn request(query: &str) -> SearchRequest {
    SearchRequest {
        query: query.to_string(),
        time_range: TimeRangeInput::new(
            Utc::now() - chrono::Duration::hours(2),
            Utc::now() + chrono::Duration::minutes(5),
        ),
        limit: Some(100),
        offset: None,
        include_sql: None,
        skip_histogram: true,
        skip_field_stats: true,
        use_cache: false,
        table_view: false,
        request_id: None,
        async_mode: false,
        priority: None,
        dataset: None,
    }
}

fn marker() -> String {
    format!("nan4915_{}", &Uuid::now_v7().simple().to_string()[20..])
}

/// Drain any runnable jobs other tests left so `run_one` claims ours.
async fn drain(pool: &sqlx::PgPool) {
    sqlx::query("UPDATE search_jobs SET state = 'cancelled' WHERE state IN ('queued', 'running')")
        .execute(pool)
        .await
        .expect("drain");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn job_completes_and_pages_from_clickhouse() {
    let h = harness().await;
    let jobs = h.jobs("worker-a", fast_config());
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 2_500).await;

    let owner = Uuid::now_v7();
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            owner,
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .expect("submit");
    assert!(!outcome.attached);
    assert_eq!(outcome.job.state, SearchJobStatus::Queued);

    assert!(jobs.run_one().await.expect("run"), "the queued job is claimable");
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Completed, "error: {:?}", job.error_message);
    assert_eq!(job.attempt, 1);
    assert_eq!(job.result_attempt, Some(1));
    assert_eq!(job.row_count, Some(2_500), "the job stores the WHOLE result, not the client page");
    assert!(!job.result_truncated);
    assert_eq!(job.result_meta.as_ref().map(|m| m.total_count), Some(2_500));

    // Continuation: pages come from search_job_results, in order, no re-scan.
    let p1 = jobs.results_page(&job, 0, 1_000).await.unwrap();
    assert_eq!(p1.rows.len(), 1_000);
    assert_eq!(p1.next_offset, Some(1_000));
    let p3 = jobs.results_page(&job, 2_000, 1_000).await.unwrap();
    assert_eq!(p3.rows.len(), 500);
    assert_eq!(p3.next_offset, None, "last page");
    for row in p1.rows.iter().chain(p3.rows.iter()) {
        assert_eq!(row["source_type"], st.as_str());
    }
    let stored: u64 = ch_exec(&format!(
        "SELECT count() FROM nanosiem.search_job_results WHERE job_id = '{}'",
        job.id.simple()
    ))
    .await
    .trim()
    .parse()
    .unwrap();
    assert_eq!(stored, 2_500);

    // Inline (legacy-compatible) result = metadata + first N rows.
    let inline = jobs.inline_result(&job, 10).await.unwrap().unwrap();
    assert_eq!(inline.results.len(), 10);
    assert_eq!(inline.total_count, 2_500);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn result_cap_marks_the_job_truncated() {
    let h = harness().await;
    let mut config = fast_config();
    config.result_cap = 300;
    let jobs = h.jobs("worker-cap", config);
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 1_000).await;
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Completed);
    assert_eq!(job.row_count, Some(300));
    assert!(job.result_truncated, "more rows matched than were stored");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn identical_submission_attaches_to_the_live_job() {
    let h = harness().await;
    let jobs = h.jobs("worker-attach", fast_config());
    drain(&h.pool).await;
    let owner = Uuid::now_v7();
    let scope = ScopeSet::unrestricted();
    let req = request("error | stats count by src_ip");

    let first = jobs.submit(&req, owner, &scope, JobOrigin::Escalated).await.unwrap();
    let mut again = req.clone();
    again.request_id = Some("another-click".into());
    again.limit = Some(25);
    let second = jobs.submit(&again, owner, &scope, JobOrigin::Submitted).await.unwrap();
    assert!(second.attached, "identical query+range+scope attaches");
    assert_eq!(second.job.id, first.job.id);
    assert_eq!(second.job.origin, JobOrigin::Escalated, "attach returns the existing job");

    let mut shifted = req.clone();
    shifted.time_range.end += chrono::Duration::seconds(1);
    let third = jobs.submit(&shifted, owner, &scope, JobOrigin::Submitted).await.unwrap();
    assert!(!third.attached, "a different time range is a different search");

    let other_owner = jobs
        .submit(&req, Uuid::now_v7(), &scope, JobOrigin::Submitted)
        .await
        .unwrap();
    assert!(!other_owner.attached, "never attached across principals");

    let restricted = jobs
        .submit(&req, owner, &ScopeSet::from_denied(["okta".to_string()].into()), JobOrigin::Submitted)
        .await
        .unwrap();
    assert!(!restricted.attached, "a different scope is a different search");

    // Once the live job finishes, the same search starts a fresh job.
    assert!(jobs.cancel(first.job.id).await.unwrap());
    let fresh = jobs.submit(&req, owner, &scope, JobOrigin::Submitted).await.unwrap();
    assert!(!fresh.attached);
    assert_ne!(fresh.job.id, first.job.id);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn lapsed_lease_is_reclaimed_and_the_dead_attempt_is_fenced() {
    let h = harness().await;
    let a = h.jobs("worker-dead", fast_config());
    let b = h.jobs("worker-restarted", fast_config());
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 400).await;
    let outcome = a
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();

    // Worker A claims attempt 1 and then "dies" (process restart): it never
    // renews, never completes.
    let (claimed, prev) = a
        .repository()
        .claim_next("worker-dead", Duration::from_secs(2))
        .await
        .unwrap()
        .expect("claim");
    assert_eq!(claimed.id, outcome.job.id);
    assert_eq!(claimed.attempt, 1);
    assert!(prev.is_none());

    // While A's lease is live nobody else can take the job.
    assert!(!b.run_one().await.unwrap(), "a live lease is exclusive");

    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // B (the restarted process) reclaims it as attempt 2 and finishes it.
    assert!(b.run_one().await.unwrap(), "the lapsed lease is reclaimable");
    let job = b.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Completed, "{:?}", job.error_message);
    assert_eq!(job.attempt, 2);
    assert_eq!(job.result_attempt, Some(2));
    assert_eq!(job.row_count, Some(400));

    // The dead attempt waking up late can neither renew nor overwrite.
    let repo = a.repository();
    assert!(!repo
        .renew_lease(job.id, "worker-dead", 1, Duration::from_secs(2), None)
        .await
        .unwrap());
    let meta = job.result_meta.clone().unwrap();
    assert!(!repo.complete(job.id, "worker-dead", 1, 0, false, &meta).await.unwrap());
    assert!(!repo
        .fail(job.id, "worker-dead", 1, JobErrorKind::Internal, "late")
        .await
        .unwrap());
    let after = b.get(job.id).await.unwrap().unwrap();
    assert_eq!(after.state, SearchJobStatus::Completed);
    assert_eq!(after.row_count, Some(400), "the fenced write changed nothing");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn exhausted_attempts_fail_as_worker_lost() {
    let h = harness().await;
    let mut config = fast_config();
    config.max_attempts = 1;
    let jobs = h.jobs("worker-exhaust", config);
    drain(&h.pool).await;
    let outcome = jobs
        .submit(&request("error"), Uuid::now_v7(), &ScopeSet::unrestricted(), JobOrigin::Submitted)
        .await
        .unwrap();
    jobs.repository()
        .claim_next("worker-gone", Duration::from_secs(1))
        .await
        .unwrap()
        .expect("claim");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(!jobs.run_one().await.unwrap(), "no attempts left: not re-claimed");
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Failed);
    assert_eq!(job.error_kind, Some(JobErrorKind::WorkerLost));
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn cancelled_queued_job_is_never_claimed() {
    let h = harness().await;
    let jobs = h.jobs("worker-cancel-q", fast_config());
    drain(&h.pool).await;
    let outcome = jobs
        .submit(&request("error"), Uuid::now_v7(), &ScopeSet::unrestricted(), JobOrigin::Submitted)
        .await
        .unwrap();
    assert!(jobs.cancel(outcome.job.id).await.unwrap());
    assert!(!jobs.cancel(outcome.job.id).await.unwrap(), "second cancel is a no-op");
    assert!(!jobs.run_one().await.unwrap(), "a cancelled job is never claimed");
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Cancelled);
    assert_eq!(job.error_kind, Some(JobErrorKind::Cancelled));
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn cancelling_a_running_job_kills_its_clickhouse_query() {
    let h = harness().await;
    let jobs = h.jobs("worker-cancel-r", fast_config());
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 5_000_000).await;
    // Deliberately expensive: a regex over every message plus a
    // high-cardinality group-by keeps ClickHouse busy for seconds.
    let outcome = jobs
        .submit(
            &request(&format!(
                "source_type=\"{st}\" message=/.*e.*v.*e.*n.*t.*[0-9]+.*/ | stats count by message, user, src_ip"
            )),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    let runner = {
        let jobs = jobs.clone();
        tokio::spawn(async move { jobs.run_one().await })
    };
    // Wait until the attempt's query is visible in system.processes.
    let query_id = format!("{}-a1", outcome.job.id.simple());
    let mut seen = false;
    for _ in 0..100 {
        let n: u64 = ch_exec(&format!(
            "SELECT count() FROM system.processes WHERE query_id = '{query_id}'"
        ))
        .await
        .trim()
        .parse()
        .unwrap_or(0);
        if n > 0 {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "the attempt runs under its stable query id {query_id}");

    assert!(jobs.cancel(outcome.job.id).await.unwrap());
    tokio::time::timeout(Duration::from_secs(15), runner)
        .await
        .expect("the worker stops promptly after cancel")
        .unwrap()
        .unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Cancelled, "cancel is not overwritten by the worker");
    let still_running: u64 = ch_exec(&format!(
        "SELECT count() FROM system.processes WHERE query_id = '{query_id}' AND NOT is_cancelled"
    ))
    .await
    .trim()
    .parse()
    .unwrap_or(0);
    assert_eq!(still_running, 0, "the ClickHouse query was killed");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn job_executes_under_its_stamped_source_scope() {
    let h = harness().await;
    let jobs = h.jobs("worker-scope", fast_config());
    drain(&h.pool).await;
    let allowed = marker();
    let denied = marker();
    seed(&allowed, 50).await;
    seed(&denied, 70).await;
    let scope = ScopeSet::from_denied([denied.clone()].into());
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{allowed}\" OR source_type=\"{denied}\"")),
            Uuid::now_v7(),
            &scope,
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Completed, "{:?}", job.error_message);
    assert_eq!(job.row_count, Some(50), "the denied source never reaches the stored result");
    // And the stored result is hidden from a caller whose scope narrowed.
    assert!(job.result_visible_under(scope.deny_set()));
    assert!(!job.result_visible_under(&[denied.clone(), "m365".to_string()].into()));
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn per_owner_live_job_cap_refuses_new_jobs_but_still_attaches() {
    let h = harness().await;
    let mut config = fast_config();
    config.max_live_jobs_per_owner = 2;
    let jobs = h.jobs("worker-cap-owner", config);
    drain(&h.pool).await;
    let owner = Uuid::now_v7();
    let scope = ScopeSet::unrestricted();
    let req_a = request("a");
    let first = jobs.submit(&req_a, owner, &scope, JobOrigin::Submitted).await.unwrap();
    jobs.submit(&request("b"), owner, &scope, JobOrigin::Submitted).await.unwrap();
    let err = jobs
        .submit(&request("c"), owner, &scope, JobOrigin::Submitted)
        .await
        .expect_err("third live job is refused");
    assert!(matches!(err, nanosiem_core::SearchError::AdmissionDenied(_)), "{err:?}");
    let again = jobs.submit(&req_a, owner, &scope, JobOrigin::Submitted).await.unwrap();
    assert!(again.attached, "attaching to an identical live job is never refused");
    assert_eq!(again.job.id, first.job.id);
    // Another owner is unaffected.
    jobs.submit(&request("c"), Uuid::now_v7(), &scope, JobOrigin::Submitted).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn relative_time_modifiers_are_frozen_at_submission_for_every_attempt() {
    let h = harness().await;
    let jobs = h.jobs("worker-frozen", fast_config());
    drain(&h.pool).await;
    let before = Utc::now();
    let outcome = jobs
        .submit(
            &request("error earliest=-1h latest=now"),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    let after = Utc::now();
    let stored = outcome.job.request.clone();
    assert!(!stored.query.contains("earliest") && !stored.query.contains("latest"), "{}", stored.query);
    assert!(stored.time_range.end >= before && stored.time_range.end <= after, "latest=now captured at submission");
    assert_eq!(stored.time_range.end - stored.time_range.start, chrono::Duration::hours(1));

    // First claim, then a lost worker and a reclaim well after submission: both
    // attempts read the same persisted absolute window.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let (claim1, _) = jobs.repository().claim_next("worker-lost", Duration::from_secs(1)).await.unwrap().unwrap();
    assert_eq!(claim1.request.time_range.start, stored.time_range.start);
    assert_eq!(claim1.request.time_range.end, stored.time_range.end);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let (claim2, _) = jobs.repository().claim_next("worker-reclaim", Duration::from_secs(5)).await.unwrap().unwrap();
    assert_eq!(claim2.attempt, 2);
    assert_eq!(claim2.request.time_range.start, stored.time_range.start);
    assert_eq!(claim2.request.time_range.end, stored.time_range.end);
    assert_eq!(claim2.request.query, stored.query);
}

/// Seed `rows` events whose message is ~`width` bytes.
async fn seed_wide(source_type: &str, rows: u64, width: usize) {
    ch_exec(&format!(
        "INSERT INTO nanosiem.logs (timestamp, id, source_type, message) \
         SELECT now64(6) - toIntervalMillisecond(number), generateUUIDv4(), '{source_type}', \
                concat('wide ', toString(number), ' ', repeat('x', {width})) \
         FROM numbers({rows})"
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn oversized_background_result_fails_query_too_large_not_oom() {
    let h = harness().await;
    let mut config = fast_config();
    config.result_max_bytes = 1024 * 1024; // 1 MiB ceiling
    let jobs = h.jobs("worker-bytes", config);
    drain(&h.pool).await;
    let st = marker();
    seed_wide(&st, 400, 20_000).await; // ~8 MB of message text
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.state, SearchJobStatus::Failed, "{:?}", job.error_message);
    assert_eq!(job.error_kind, Some(JobErrorKind::QueryTooLarge), "{:?}", job.error_message);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn wide_rows_are_paged_within_the_byte_budget() {
    let h = harness().await;
    // 100 KiB page budget, rows ~20 KiB each → ~5 rows per page.
    let jobs = h.jobs_with_page_budget("worker-pagebytes", fast_config(), Some(100 * 1024));
    drain(&h.pool).await;
    let st = marker();
    seed_wide(&st, 60, 20_000).await;
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.row_count, Some(60), "{:?}", job.error_message);

    let mut offset = 0u64;
    let mut seen = 0usize;
    let mut pages = 0;
    loop {
        let page = jobs.results_page(&job, offset, 1_000).await.expect("byte-limited page is a 200");
        assert!(!page.rows.is_empty());
        assert!(page.rows.len() <= 6, "page ignored the byte budget: {} rows", page.rows.len());
        seen += page.rows.len();
        pages += 1;
        match page.next_offset {
            Some(next) => {
                assert_eq!(next, offset + page.rows.len() as u64);
                offset = next;
            }
            None => break,
        }
    }
    assert_eq!(seen, 60, "every stored row is reachable through byte-limited pages");
    assert!(pages >= 10);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn a_page_inconsistent_with_the_stored_row_count_is_refused() {
    let h = harness().await;
    let jobs = h.jobs("worker-consistency", fast_config());
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 30).await;
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.row_count, Some(30));
    assert_eq!(jobs.results_page(&job, 0, 100).await.unwrap().rows.len(), 30);

    // Simulate a replica that has not received every row yet: PG records 40,
    // ClickHouse serves 30. The page must be refused, not returned short.
    sqlx::query("UPDATE search_jobs SET row_count = 40 WHERE id = $1")
        .bind(job.id)
        .execute(&h.pool)
        .await
        .unwrap();
    let lagging = jobs.get(job.id).await.unwrap().unwrap();
    let err = jobs.results_page(&lagging, 0, 100).await.expect_err("short page refused");
    assert!(
        matches!(err, nanosiem_core::SearchError::JobResultsUnavailable(_)),
        "expected retryable JobResultsUnavailable, got {err:?}"
    );
    // Mid-result pages that ARE complete still serve.
    assert_eq!(jobs.results_page(&lagging, 0, 10).await.unwrap().rows.len(), 10);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn a_page_past_the_stored_rows_is_a_contract_error() {
    let h = harness().await;
    let mut config = fast_config();
    config.result_cap = 20;
    let jobs = h.jobs("worker-range", config);
    drain(&h.pool).await;
    let st = marker();
    seed(&st, 50).await;
    let outcome = jobs
        .submit(
            &request(&format!("source_type=\"{st}\"")),
            Uuid::now_v7(),
            &ScopeSet::unrestricted(),
            JobOrigin::Submitted,
        )
        .await
        .unwrap();
    jobs.run_one().await.unwrap();
    let job = jobs.get(outcome.job.id).await.unwrap().unwrap();
    assert_eq!(job.row_count, Some(20));
    assert!(job.result_truncated);
    let last = jobs.results_page(&job, 10, 10).await.unwrap();
    assert_eq!(last.rows.len(), 10);
    assert_eq!(last.next_offset, None);
    let err = jobs.results_page(&job, 20, 10).await.expect_err("offset == row_count");
    assert!(matches!(err, nanosiem_core::SearchError::SqlValidationError(_)), "{err:?}");
    let err = jobs.results_page(&job, 5_000, 10).await.expect_err("deep page of a truncated job");
    assert!(matches!(err, nanosiem_core::SearchError::SqlValidationError(_)), "{err:?}");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn concurrent_distinct_submissions_cannot_exceed_the_owner_cap() {
    let h = harness().await;
    let mut config = fast_config();
    config.max_live_jobs_per_owner = 3;
    let jobs = h.jobs("worker-cap-race", config);
    drain(&h.pool).await;
    let owner = Uuid::now_v7();
    let mut handles = Vec::new();
    for i in 0..20 {
        let jobs = jobs.clone();
        handles.push(tokio::spawn(async move {
            jobs.submit(
                &request(&format!("error{i}")),
                owner,
                &ScopeSet::unrestricted(),
                JobOrigin::Submitted,
            )
            .await
        }));
    }
    let mut created = 0;
    let mut denied = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(o) => {
                assert!(!o.attached);
                created += 1;
            }
            Err(nanosiem_core::SearchError::AdmissionDenied(_)) => denied += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(created, 3, "exactly the cap is admitted under concurrency");
    assert_eq!(denied, 17);
    let (live,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM search_jobs WHERE owner_user_id = $1 AND state IN ('queued','running')",
    )
    .bind(owner)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(live, 3);
}

#[tokio::test]
#[ignore = "requires live PostgreSQL + ClickHouse; run with --ignored"]
async fn result_pages_prune_created_at_partitions() {
    let _h = harness().await;
    let job = format!("explain_{}", Uuid::now_v7().simple());
    // Two partitions for the same job: today and three days ago.
    ch_exec(&format!(
        "INSERT INTO nanosiem.search_job_results (job_id, attempt, seq, row, created_at) VALUES \
         ('{job}', 1, 0, '{{}}', now()), ('{job}', 1, 1, '{{}}', now() - INTERVAL 3 DAY)"
    ))
    .await;
    let now = Utc::now().timestamp();
    let sql = nanosiem_core::search::background::page_sql_for_tests("nanosiem.search_job_results")
        .replacen('?', &format!("{}", now - 600), 1)
        .replacen('?', &format!("{}", now + 600), 1)
        .replacen('?', &format!("'{job}'"), 1)
        .replacen('?', "1", 1)
        .replacen('?', "0", 1)
        .replacen('?', "10", 1);
    assert!(!sql.to_uppercase().contains("PREWHERE"), "single WHERE, no PREWHERE");
    let plan = ch_exec(&format!("EXPLAIN indexes = 1 {sql}")).await;
    assert!(
        plan.contains("toYYYYMMDD(created_at)") && plan.contains("Partition"),
        "partition key not used: {plan}"
    );
    let rows = ch_exec(&format!("{sql} FORMAT TSV")).await;
    assert_eq!(rows.lines().count(), 1, "the 3-day-old partition is outside the job window");
}
