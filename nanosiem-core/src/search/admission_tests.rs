// SPDX-License-Identifier: AGPL-3.0-or-later

//! Admission controller tests: limits, leases (NAN-3299), the auxiliary lane
//! (NAN-3299), the fair queue instead of 429 (NAN-4664) and the agent class
//! (NAN-4703).

use super::*;
use uuid::Uuid;

#[test]
fn test_priority_ordering() {
    assert!(QueryPriority::Detection.ordinal() < QueryPriority::Interactive.ordinal());
    assert!(QueryPriority::Interactive.ordinal() < QueryPriority::Analytics.ordinal());
}

#[test]
fn test_detection_bypasses_queue() {
    assert!(QueryPriority::Detection.bypasses_queue());
    assert!(QueryPriority::NearRealtime.bypasses_queue());
    assert!(!QueryPriority::Interactive.bypasses_queue());
    assert!(!QueryPriority::Analytics.bypasses_queue());
}

#[test]
fn test_ch_settings() {
    let det = QueryPriority::Detection.to_ch_settings();
    assert_eq!(det.max_execution_time, 30);
    assert_eq!(det.priority, 1);

    let interactive = QueryPriority::Interactive.to_ch_settings();
    assert_eq!(interactive.max_execution_time, 300);
    assert_eq!(interactive.priority, 3);

    let analytics = QueryPriority::Analytics.to_ch_settings();
    assert_eq!(analytics.max_execution_time, 3600);
    assert_eq!(analytics.priority, 5);
}

#[test]
fn deployment_memory_ceiling_only_clamps_memory() {
    let ceiling = 3 * 1024 * 1024 * 1024;
    let analytics = QueryPriority::Analytics.to_ch_settings_with_memory_ceiling(Some(ceiling));

    assert_eq!(analytics.max_memory_usage_bytes, Some(ceiling));
    assert_eq!(analytics.max_execution_time, 3600);
    assert_eq!(analytics.max_threads, 32);
    assert_eq!(analytics.priority, 5);
    assert_eq!(analytics.queue_max_wait_ms, 120_000);
}

#[test]
fn deployment_memory_ceiling_never_raises_priority_budget() {
    let generous_ceiling = 100 * 1024 * 1024 * 1024;
    let detection =
        QueryPriority::Detection.to_ch_settings_with_memory_ceiling(Some(generous_ceiling));
    let legacy = QueryPriority::Detection.to_ch_settings();

    assert_eq!(
        detection.max_memory_usage_bytes,
        legacy.max_memory_usage_bytes
    );
    assert_eq!(
        QueryPriority::Interactive
            .to_ch_settings_with_memory_ceiling(None)
            .max_memory_usage_bytes,
        None
    );
}

/// NAN-709: only Analytics yields before claiming an admit slot.
#[test]
fn admit_delay_only_applies_to_analytics() {
    assert_eq!(QueryPriority::Detection.admit_delay(), None);
    assert_eq!(QueryPriority::NearRealtime.admit_delay(), None);
    assert_eq!(QueryPriority::Interactive.admit_delay(), None);
    assert_eq!(
        QueryPriority::Analytics.admit_delay(),
        Some(std::time::Duration::from_millis(250))
    );
}

#[test]
fn test_default_config() {
    let config = AdmissionConfig::default();
    assert_eq!(config.global_adhoc_limit, 30);
    assert_eq!(config.per_user_limit, 10);
    assert_eq!(config.max_queue_depth, 100);
    // NAN-714: bumped to 300_000 (5 min) to match Interactive
    // max_execution_time. See AdmissionConfig::default.
    assert_eq!(config.queue_timeout_ms, 300_000);
}

async fn wait_for_depth(controller: &AdmissionController, depth: u32) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while controller.queue_depth().await != depth {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("queue never reached depth {depth}"));
}

#[tokio::test]
async fn test_detection_always_admitted() {
    let controller = AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 0, // no ad-hoc slots
        per_user_limit: 0,
        max_queue_depth: 0,
        queue_timeout_ms: 1,
    });

    let user = Uuid::now_v7();
    let permit = controller
        .acquire("job1", user, QueryPriority::Detection)
        .await;
    assert!(permit.is_ok());
}

#[tokio::test]
async fn test_admit_within_limits() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 5,
        per_user_limit: 3,
        max_queue_depth: 10,
        queue_timeout_ms: 5_000,
    }));
    controller.start_drain_loop();

    let user = Uuid::now_v7();
    let mut permits = Vec::new();

    for i in 0..3 {
        let permit = controller
            .acquire(&format!("job{}", i), user, QueryPriority::Interactive)
            .await;
        assert!(permit.is_ok(), "Should admit query {}", i);
        permits.push(permit.unwrap());
    }

    // NAN-3299: the 4th waits in the queue instead of failing.
    let queued_controller = Arc::clone(&controller);
    let fourth = tokio::spawn(async move {
        queued_controller
            .acquire("job3", user, QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;

    // A different user is still admitted.
    let user2 = Uuid::now_v7();
    let permit = controller
        .acquire("job4", user2, QueryPriority::Interactive)
        .await;
    assert!(permit.is_ok());
    permits.push(permit.unwrap());
    assert_eq!(controller.stats().await.active_adhoc, 4);
    assert!(!fourth.is_finished(), "per-user overflow waits for a slot");

    permits.remove(0);
    let fourth = tokio::time::timeout(std::time::Duration::from_secs(5), fourth)
        .await
        .expect("queued per-user overflow admits after a release")
        .expect("join")
        .expect("admitted");
    assert_eq!(controller.stats().await.active_adhoc, 4);
    drop(fourth);
}

#[tokio::test]
async fn test_permit_drop_frees_slot() {
    let controller = AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 1,
        per_user_limit: 5,
        max_queue_depth: 10,
        queue_timeout_ms: 1000,
    });
    let user = Uuid::now_v7();
    {
        let _permit = controller
            .acquire("job1", user, QueryPriority::Interactive)
            .await
            .unwrap();
        assert_eq!(controller.stats().await.active_adhoc, 1);
    }
    assert_eq!(controller.stats().await.active_adhoc, 0);
    let _permit2 = controller
        .acquire("job2", user, QueryPriority::Interactive)
        .await
        .unwrap();
    assert_eq!(controller.stats().await.active_adhoc, 1);
}

#[tokio::test]
async fn test_queue_full() {
    let controller = AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 1,
        per_user_limit: 10,
        max_queue_depth: 0, // no queue
        queue_timeout_ms: 100,
    });
    let _permit = controller
        .acquire("job1", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    let result = controller
        .acquire("job2", Uuid::now_v7(), QueryPriority::Interactive)
        .await;
    assert!(matches!(result, Err(AdmissionError::QueueFull { .. })));
}

#[tokio::test]
async fn test_cancel_queued() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 1,
        per_user_limit: 10,
        max_queue_depth: 10,
        queue_timeout_ms: 5000,
    }));
    let _permit = controller
        .acquire("job1", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    let controller2 = Arc::clone(&controller);
    let handle = tokio::spawn(async move {
        controller2
            .acquire("job2", Uuid::now_v7(), QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;
    controller.cancel_queued("job2").await;
    let result = handle.await.unwrap();
    assert!(matches!(result, Err(AdmissionError::Cancelled)));
}

#[tokio::test]
async fn test_update_config() {
    let controller = AdmissionController::new(AdmissionConfig::default());
    let new_config = AdmissionConfig {
        global_adhoc_limit: 50,
        per_user_limit: 10,
        max_queue_depth: 200,
        queue_timeout_ms: 60_000,
    };
    controller.update_config(new_config.clone()).await;
    let config = controller.config.lock().await;
    assert_eq!(config.global_adhoc_limit, 50);
    assert_eq!(config.per_user_limit, 10);
}

/// Every Redis admission and release is one atomic script over per-permit
/// leases: expired members are pruned before every count, not a key TTL
/// that every acquire refreshes.
#[test]
fn redis_acquire_and_release_scripts_keep_crash_and_race_fences() {
    assert!(ACQUIRE_LUA.contains("redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now)"));
    assert!(ACQUIRE_LUA.contains("redis.call('ZADD', key, expires, permit)"));
    assert!(!ACQUIRE_LUA.contains("INCR"));
    assert!(RELEASE_LUA.contains("redis.call('ZREM', KEYS[i], ARGV[1])"));
    assert!(!RELEASE_LUA.contains("DECR"));
    assert!(REDIS_ADMISSION_KEY_TTL_SECS as u64 > permit_lease(QueryPriority::Analytics).as_secs());
    // The agent key is the 4th and only exists for agent permits.
    let user = Uuid::from_u128(7);
    assert_eq!(redis_permit_keys(user, QueryClass::Human).len(), 3);
    assert_eq!(
        redis_permit_keys(user, QueryClass::Agent)[3],
        REDIS_AGENT_KEY
    );
}

#[test]
fn permit_leases_end_at_the_execution_ceiling_plus_slack() {
    assert_eq!(
        permit_lease(QueryPriority::Interactive),
        std::time::Duration::from_secs(300 + PERMIT_LEASE_SLACK_SECS)
    );
    assert_eq!(
        permit_lease(QueryPriority::Analytics),
        std::time::Duration::from_secs(3600 + PERMIT_LEASE_SLACK_SECS)
    );
}

#[test]
fn auxiliary_lane_keeps_slots_for_the_rows_search() {
    assert_eq!(auxiliary_user_limit(1), 1);
    assert_eq!(auxiliary_user_limit(2), 1);
    assert_eq!(auxiliary_user_limit(5), 4);
    assert_eq!(auxiliary_user_limit(10), 8);
    // NAN-4664: a principal may hold half the queue, never less than twice
    // its running permits.
    assert_eq!(principal_queue_limit(10, 25), 20);
    assert_eq!(principal_queue_limit(5, 100), 50);
    assert_eq!(principal_queue_limit(5, 4), 4);
    assert_eq!(principal_queue_limit(1, 0), 1);
}

fn short_lease_controller(config: AdmissionConfig, lease_ms: u64) -> Arc<AdmissionController> {
    let mut controller = AdmissionController::new(config);
    controller.lease_override = Some(std::time::Duration::from_millis(lease_ms));
    Arc::new(controller)
}

fn one_slot_per_user() -> AdmissionConfig {
    AdmissionConfig {
        global_adhoc_limit: 10,
        per_user_limit: 1,
        max_queue_depth: 10,
        queue_timeout_ms: 5_000,
    }
}

/// NAN-3299: a permit that is never released (its holder vanished) is
/// reclaimed once its lease ends; a waiter of the same user is admitted.
#[tokio::test]
async fn local_permit_never_released_is_reclaimed_after_its_lease() {
    let controller = short_lease_controller(one_slot_per_user(), 150);
    controller.start_drain_loop();
    let user = Uuid::now_v7();
    let mut leaked = controller
        .acquire("leaked", user, QueryPriority::Interactive)
        .await
        .unwrap();
    // The holder died: its renewer died with it (NAN-4928).
    leaked.renewer.take().unwrap().abort();
    std::mem::forget(leaked);
    assert_eq!(controller.stats().await.active_adhoc, 1);

    let started = Instant::now();
    let next = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        controller.acquire("next", user, QueryPriority::Interactive),
    )
    .await
    .expect("orphaned permit is reclaimed within lease + drain cadence")
    .expect("admitted after reclaim");
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
    assert_eq!(controller.stats().await.active_adhoc, 1);
    drop(next);
    assert_eq!(controller.stats().await.active_adhoc, 0);
}

/// A permit released after its lease was reclaimed must not release the
/// slot a newer permit now holds.
#[tokio::test]
async fn late_release_of_a_reclaimed_permit_does_not_double_free() {
    let controller = short_lease_controller(one_slot_per_user(), 50);
    let user = Uuid::now_v7();
    let mut stale = controller
        .acquire("stale", user, QueryPriority::Interactive)
        .await
        .unwrap();
    // A holder that stopped renewing (hung or partitioned), then releases late.
    stale.renewer.take().unwrap().abort();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let current = controller
        .acquire("current", user, QueryPriority::Interactive)
        .await
        .expect("expired lease is pruned on acquire");
    drop(stale);
    let stats = controller.stats().await;
    assert_eq!(stats.active_adhoc, 1);
    assert_eq!(stats.per_user_counts.len(), 1);
    assert_eq!(stats.per_user_counts[0].1, 1);
    drop(current);
    assert_eq!(controller.stats().await.active_adhoc, 0);
}

/// NAN-3299: one user's companions (histogram, field stats) cannot take the
/// slots reserved for the rows search of the same run.
#[tokio::test]
async fn auxiliary_requests_cannot_starve_the_rows_search() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 30,
        per_user_limit: 4,
        max_queue_depth: 10,
        queue_timeout_ms: 5_000,
    }));
    controller.start_drain_loop();
    let user = Uuid::from_u128(1);
    let mut auxiliary = Vec::new();
    for index in 0..3 {
        auxiliary.push(
            controller
                .acquire_in_lane(
                    &format!("aux-{index}"),
                    user,
                    QueryPriority::Interactive,
                    AdmissionLane::Auxiliary,
                )
                .await
                .expect("auxiliary within its cap"),
        );
    }
    let waiting_controller = Arc::clone(&controller);
    let fourth_auxiliary = tokio::spawn(async move {
        waiting_controller
            .acquire_in_lane(
                "aux-3",
                user,
                QueryPriority::Interactive,
                AdmissionLane::Auxiliary,
            )
            .await
    });
    wait_for_depth(&controller, 1).await;

    // The queue is not idle, so the rows search queues too, but the drain
    // admits it at once: the auxiliary waiter ahead is capped.
    let rows = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        controller.acquire("rows", user, QueryPriority::Interactive),
    )
    .await
    .expect("rows search is admitted")
    .expect("rows admitted");
    assert!(!fourth_auxiliary.is_finished());
    drop(rows);
    drop(auxiliary.pop());
    let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), fourth_auxiliary)
        .await
        .expect("auxiliary waiter admits after a release")
        .expect("join")
        .expect("admitted");
    drop((admitted, auxiliary));
}

/// Queued primary searches go before queued companions of equal priority.
#[tokio::test]
async fn queued_primary_is_served_before_queued_auxiliary() {
    let controller = Arc::new(AdmissionController::new(one_slot_per_user()));
    let user = Uuid::from_u128(1);
    let holder = controller
        .acquire("holder", user, QueryPriority::Interactive)
        .await
        .unwrap();
    let aux_controller = Arc::clone(&controller);
    let auxiliary = tokio::spawn(async move {
        aux_controller
            .acquire_in_lane(
                "aux",
                user,
                QueryPriority::Interactive,
                AdmissionLane::Auxiliary,
            )
            .await
    });
    wait_for_depth(&controller, 1).await;
    let rows_controller = Arc::clone(&controller);
    let rows = tokio::spawn(async move {
        rows_controller
            .acquire("rows", user, QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 2).await;
    assert_eq!(
        controller.queue_position("rows").await,
        Some(1),
        "the later rows search is first in line"
    );
    controller.start_drain_loop();
    drop(holder);
    let rows = tokio::time::timeout(std::time::Duration::from_secs(5), rows)
        .await
        .expect("rows admitted first")
        .expect("join")
        .expect("admitted");
    assert!(!auxiliary.is_finished());
    drop(rows);
    let auxiliary = tokio::time::timeout(std::time::Duration::from_secs(5), auxiliary)
        .await
        .expect("auxiliary admitted next")
        .expect("join")
        .expect("admitted");
    drop(auxiliary);
}

/// A user at their cap does not hold up another user's waiter behind it.
#[tokio::test]
async fn user_at_cap_does_not_block_other_users_waiters() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 2,
        per_user_limit: 1,
        max_queue_depth: 10,
        queue_timeout_ms: 5_000,
    }));
    controller.start_drain_loop();
    let busy = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let busy_permit = controller
        .acquire("busy-1", busy, QueryPriority::Interactive)
        .await
        .unwrap();
    let filler = controller
        .acquire("filler", Uuid::from_u128(3), QueryPriority::Interactive)
        .await
        .unwrap();
    let busy_controller = Arc::clone(&controller);
    let busy_waiter = tokio::spawn(async move {
        busy_controller
            .acquire("busy-2", busy, QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;
    let other_controller = Arc::clone(&controller);
    let other_waiter = tokio::spawn(async move {
        other_controller
            .acquire("other", other, QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 2).await;

    drop(filler);
    let other_permit = tokio::time::timeout(std::time::Duration::from_secs(5), other_waiter)
        .await
        .expect("other user admitted past the capped user's waiter")
        .expect("join")
        .expect("admitted");
    assert!(!busy_waiter.is_finished());
    drop((other_permit, busy_permit));
    let busy_second = tokio::time::timeout(std::time::Duration::from_secs(5), busy_waiter)
        .await
        .expect("capped user admitted after its own release")
        .expect("join")
        .expect("admitted");
    drop(busy_second);
}

// ------------------------------------------------------------------
// NAN-4664: bounded fair queue instead of rejection
// ------------------------------------------------------------------

fn fleet_config(global: u32, per_user: u32) -> AdmissionConfig {
    AdmissionConfig {
        global_adhoc_limit: global,
        per_user_limit: per_user,
        max_queue_depth: 100,
        queue_timeout_ms: 300_000,
    }
}

/// 16 closed-loop agents, each always with exactly one search in flight, 10
/// hunts each, over a cap of 5. Every hunt waits inside its budget instead
/// of failing, and the cap is never exceeded. Covered twice: 16 agents
/// sharing one login (the per-principal cap of 5 binds) and 16 distinct
/// principals over a global cap of 5.
#[tokio::test(start_paused = true)]
async fn fleet_of_16_agents_over_a_cap_of_5_completes_with_no_rejects() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    for (config, shared_login) in [(fleet_config(30, 5), true), (fleet_config(5, 10), false)] {
        let controller = Arc::new(AdmissionController::new(config));
        controller.start_drain_loop();
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let shared_user = Uuid::now_v7();
        let mut agents = Vec::new();
        for agent in 0..16u64 {
            let (controller, running, peak) = (controller.clone(), running.clone(), peak.clone());
            let user = if shared_login {
                shared_user
            } else {
                Uuid::now_v7()
            };
            agents.push(tokio::spawn(with_wait_budget(
                std::time::Duration::from_secs(60),
                async move {
                    let mut rejects = 0;
                    for hunt in 0..10u64 {
                        match controller
                            .acquire(
                                &format!("agent{agent}-hunt{hunt}"),
                                user,
                                QueryPriority::Interactive,
                            )
                            .await
                        {
                            Ok(permit) => {
                                let now = running.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                                peak.fetch_max(now, AtomicOrdering::SeqCst);
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    500 + 300 * ((agent + hunt) % 7),
                                ))
                                .await;
                                running.fetch_sub(1, AtomicOrdering::SeqCst);
                                drop(permit);
                            }
                            Err(_) => rejects += 1,
                        }
                    }
                    rejects
                },
            )));
        }
        let mut rejects = 0;
        for agent in agents {
            rejects += agent.await.expect("agent");
        }
        assert_eq!(rejects, 0, "every hunt waits inside its budget (shared login: {shared_login})");
        assert_eq!(peak.load(AtomicOrdering::SeqCst), 5, "the cap of 5 is kept, never raised");
        assert_eq!(controller.queue_depth().await, 0);
        assert_eq!(controller.stats().await.active_adhoc, 0);
    }
}

/// The budget is the only clock: it ends the wait with `QueueTimeout`
/// (429 + Retry-After at the handler), is capped by `queue_timeout_ms`, and
/// `0` fails fast. The expired waiter leaves the queue.
#[tokio::test(start_paused = true)]
async fn wait_budget_expiry_refuses_and_leaves_the_queue() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        queue_timeout_ms: 300,
        ..fleet_config(1, 1)
    }));
    controller.start_drain_loop();
    let holder = controller
        .acquire("holder", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    let short = with_wait_budget(
        std::time::Duration::from_millis(100),
        controller.acquire("short", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(
        matches!(short, Err(AdmissionError::QueueTimeout { timeout_ms: 100 })),
        "{:?}",
        short.err()
    );
    let waited = started.elapsed();
    assert!(
        waited >= std::time::Duration::from_millis(100)
            && waited < std::time::Duration::from_millis(150),
        "{waited:?}"
    );
    assert_eq!(controller.queue_depth().await, 0, "an expired waiter leaves the queue");

    let capped = with_wait_budget(
        std::time::Duration::from_secs(3600),
        controller.acquire("capped", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(
        matches!(capped, Err(AdmissionError::QueueTimeout { timeout_ms: 300 })),
        "{:?}",
        capped.err()
    );

    let started = tokio::time::Instant::now();
    let fast = with_wait_budget(
        std::time::Duration::ZERO,
        controller.acquire("fast", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(matches!(fast, Err(AdmissionError::QueueTimeout { timeout_ms: 0 })));
    assert!(started.elapsed() < std::time::Duration::from_millis(1), "never queued");

    let waiter_controller = controller.clone();
    let waiter = tokio::spawn(with_wait_budget(
        std::time::Duration::from_millis(250),
        async move {
            waiter_controller
                .acquire("waits", Uuid::now_v7(), QueryPriority::Interactive)
                .await
        },
    ));
    wait_for_depth(&controller, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(holder);
    waiter.await.unwrap().expect("admitted inside its budget");
}

/// No barging: an agent that releases and re-acquires at once queues behind
/// the waiter that was already there.
#[tokio::test]
async fn releasing_agent_cannot_retake_its_slot_ahead_of_a_waiter() {
    let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
    controller.start_drain_loop();
    let (agent, waiter_user) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let held = controller
        .acquire("agent-1", agent, QueryPriority::Interactive)
        .await
        .unwrap();
    let waiting = controller.clone();
    let waiter = tokio::spawn(async move {
        waiting
            .acquire("waiter", waiter_user, QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;
    drop(held);
    let barged = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        controller.acquire("agent-2", agent, QueryPriority::Interactive),
    )
    .await;
    assert!(barged.is_err(), "the releasing agent queues instead of re-taking the slot");
    let waiter = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("the waiter got the freed slot")
        .unwrap()
        .unwrap();
    assert_eq!(controller.queue_depth().await, 0, "the abandoned re-acquire left the queue");
    drop(waiter);
}

#[test]
fn header_budget_defaults_and_parses() {
    assert_eq!(request_wait_budget(None), DEFAULT_ADMISSION_WAIT);
    assert_eq!(request_wait_budget(Some("garbage")), DEFAULT_ADMISSION_WAIT);
    assert_eq!(
        request_wait_budget(Some(" 120000 ")),
        std::time::Duration::from_secs(120)
    );
    assert_eq!(request_wait_budget(Some("0")), std::time::Duration::ZERO);
    assert_eq!(effective_wait(None, 300_000), std::time::Duration::from_secs(300));
    assert_eq!(
        effective_wait(Some(std::time::Duration::from_secs(900)), 300_000),
        std::time::Duration::from_secs(300)
    );
    assert_eq!(
        effective_wait(Some(std::time::Duration::from_secs(5)), 300_000),
        std::time::Duration::from_secs(5)
    );
}

/// A background job escapes its request's HTTP budget (it waits up to the
/// configured cap); spawned request work keeps it via `inherit`.
#[tokio::test]
async fn async_jobs_escape_the_request_budget_and_side_tasks_inherit_it() {
    let five = std::time::Duration::from_secs(5);
    let job = with_wait_budget(five, without_wait_budget(async { current_wait_budget() })).await;
    assert_eq!(effective_wait(job, 300_000), std::time::Duration::from_secs(300));
    let side = with_wait_budget(five, async {
        tokio::spawn(crate::search::request_actor::inherit(async {
            current_wait_budget()
        }))
        .await
        .unwrap()
    })
    .await;
    assert_eq!(side, Some(five));
    assert_eq!(current_wait_budget(), None);
}

fn synthetic(seq: u64, subject: AdmissionSubject, priority: QueryPriority) -> QueuedSearch {
    QueuedSearch {
        seq,
        job_id: format!("job-{seq}"),
        subject,
        priority,
        lane: AdmissionLane::Primary,
        class: QueryClass::Human,
        principal_tag: 0,
        tx: oneshot::channel().0,
    }
}

fn queue_of(entries: &[(AdmissionSubject, QueryPriority)]) -> WaitQueue {
    let mut queue = WaitQueue::default();
    for &(subject, priority) in entries {
        queue.push(synthetic(0, subject, priority));
    }
    queue
}

fn served(queue: &mut WaitQueue) -> Vec<u64> {
    let order = service_order(&mut queue.waiters);
    order
        .into_iter()
        .map(|index| queue.waiters[index].seq)
        .collect()
}

fn serve_next(queue: &mut WaitQueue) -> u64 {
    let first = served(queue)[0];
    let search = queue.take(first).unwrap();
    queue.record_admitted(&search);
    first
}

/// Principals are served round-robin (a deep backlog from one agent cannot
/// starve another); priority still first.
#[test]
fn service_order_is_round_robin_across_principals() {
    let greedy = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let mut queue = queue_of(&[
        (greedy, QueryPriority::Interactive),
        (greedy, QueryPriority::Interactive),
        (greedy, QueryPriority::Interactive),
        (other, QueryPriority::Interactive),
        (other, QueryPriority::Interactive),
        (greedy, QueryPriority::Analytics),
    ]);
    assert_eq!(served(&mut queue), vec![1, 4, 2, 5, 3, 6]);

    // A principal arriving once service is under way joins the current
    // round, never behind greedy's whole backlog.
    assert_eq!(serve_next(&mut queue), 1);
    let late = queue.push(synthetic(0, Uuid::from_u128(3), QueryPriority::Interactive));
    assert_eq!(served(&mut queue), vec![4, 2, 5, late, 3, 6]);
    for expected in [4, 2, 5, late, 3, 6] {
        assert_eq!(serve_next(&mut queue), expected);
    }
    queue.prune_clocks();
    assert_eq!(queue.principal_clock, 0);
}

/// The fair order drives the real drain: a principal arriving behind
/// another's backlog is admitted second, not seventh.
#[tokio::test]
async fn drain_serves_a_late_principal_before_anothers_backlog() {
    let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
    let holder = controller
        .acquire("holder", Uuid::from_u128(9), QueryPriority::Interactive)
        .await
        .unwrap();
    let mut greedy = Vec::new();
    for index in 0..6u32 {
        let waiting = controller.clone();
        greedy.push(tokio::spawn(async move {
            waiting
                .acquire(
                    &format!("greedy-{index}"),
                    Uuid::from_u128(1),
                    QueryPriority::Interactive,
                )
                .await
        }));
        wait_for_depth(&controller, index + 1).await;
    }
    let late_controller = controller.clone();
    let late = tokio::spawn(async move {
        late_controller
            .acquire("late", Uuid::from_u128(2), QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 7).await;
    assert_eq!(controller.queue_position("late").await, Some(2));
    controller.start_drain_loop();
    drop(holder);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), greedy.remove(0))
        .await
        .expect("oldest admitted first")
        .unwrap()
        .unwrap();
    assert!(!late.is_finished());
    drop(first);
    let late = tokio::time::timeout(std::time::Duration::from_secs(5), late)
        .await
        .expect("late principal admitted second")
        .unwrap()
        .unwrap();
    assert_eq!(controller.queue_depth().await, 5, "the greedy backlog still waits");
    drop(late);
    for waiter in greedy {
        waiter.abort();
    }
}

/// A client that disconnects leaves the queue at once and its work is never
/// started: the slot goes to the next live waiter.
#[tokio::test]
async fn disconnected_waiter_leaves_the_queue_and_never_starts() {
    let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
    controller.start_drain_loop();
    let holder = controller
        .acquire("holder", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gone_controller = controller.clone();
    let gone_started = started.clone();
    let gone = tokio::spawn(async move {
        let permit = gone_controller
            .acquire("gone", Uuid::now_v7(), QueryPriority::Interactive)
            .await;
        gone_started.store(true, std::sync::atomic::Ordering::SeqCst);
        permit
    });
    wait_for_depth(&controller, 1).await;
    gone.abort();
    let _ = gone.await;
    assert_eq!(controller.queue_depth().await, 0, "the disconnected waiter left the queue");

    let live_controller = controller.clone();
    let live = tokio::spawn(async move {
        live_controller
            .acquire("live", Uuid::now_v7(), QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;
    drop(holder);
    let live = tokio::time::timeout(std::time::Duration::from_secs(5), live)
        .await
        .expect("live waiter admitted")
        .unwrap()
        .unwrap();
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "the dead waiter's work never started"
    );
    assert_eq!(controller.stats().await.active_adhoc, 1);
    drop(live);

    // A waiter whose receiver closed before the drain saw it is skipped by
    // the drain, never admitted.
    let holder = controller
        .acquire("holder-2", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    lock_queue(&controller.queue).push(synthetic(0, Uuid::now_v7(), QueryPriority::Interactive));
    drop(holder);
    controller.drain_queue().await;
    assert_eq!(controller.queue_depth().await, 0);
    assert_eq!(controller.stats().await.active_adhoc, 0, "no permit for a closed waiter");
}

/// A waiter being tried by the drain (which awaits config and Redis) stays
/// queued until admitted: its position holds, a cancel reaches it, and the
/// permit taken for a waiter cancelled meanwhile is released.
#[tokio::test]
async fn waiter_stays_queued_and_cancellable_while_the_drain_tries_it() {
    let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
    let holder = controller
        .acquire("holder", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    let waiting = controller.clone();
    let waiter = tokio::spawn(async move {
        waiting
            .acquire("waiter", Uuid::now_v7(), QueryPriority::Interactive)
            .await
    });
    wait_for_depth(&controller, 1).await;
    drop(holder);

    let config = controller.config.lock().await;
    let draining = controller.clone();
    let drain = tokio::spawn(async move { draining.drain_queue().await });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!drain.is_finished(), "the drain is mid-pass");
    assert_eq!(controller.queue_depth().await, 1, "a waiter being tried is still queued");
    assert_eq!(controller.queue_position("waiter").await, Some(1));
    controller.cancel_queued("waiter").await;
    assert!(matches!(waiter.await.unwrap(), Err(AdmissionError::Cancelled)));

    drop(config);
    drain.await.unwrap();
    assert_eq!(controller.queue_depth().await, 0);
    assert_eq!(
        controller.stats().await.active_adhoc,
        0,
        "no permit kept for the cancelled waiter"
    );
}

/// The queue is bounded whatever the arrival rate.
#[tokio::test]
async fn queue_memory_is_bounded_under_a_burst() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        max_queue_depth: 50,
        ..fleet_config(1, 1)
    }));
    let _holder = controller
        .acquire("holder", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    let mut waiters = Vec::new();
    for index in 0..1_000u32 {
        let controller = controller.clone();
        waiters.push(tokio::spawn(async move {
            controller
                .acquire(&format!("burst-{index}"), Uuid::now_v7(), QueryPriority::Interactive)
                .await
        }));
    }
    let mut refused = 0;
    let mut pending = Vec::new();
    for waiter in waiters {
        match tokio::time::timeout(std::time::Duration::from_millis(50), async {
            while !waiter.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        {
            Ok(()) => match waiter.await.unwrap() {
                Err(AdmissionError::QueueFull { depth: 50 }) => refused += 1,
                other => panic!("unexpected: {:?}", other.err()),
            },
            Err(_) => pending.push(waiter),
        }
    }
    assert_eq!(pending.len(), 50);
    assert_eq!(refused, 950);
    assert_eq!(controller.queue_depth().await, 50);
    assert!(
        lock_queue(&controller.queue).waiters.capacity() <= 128,
        "queue storage stays at its bound"
    );
    for waiter in pending {
        waiter.abort();
    }
}

// ------------------------------------------------------------------
// NAN-4703: agent class
// ------------------------------------------------------------------

#[test]
fn agent_class_cap_leaves_the_human_reserve() {
    for (limit, reserved, agents) in [
        (1, 0, 1),
        (2, 1, 1),
        (4, 1, 3),
        (5, 1, 4),
        (8, 2, 6),
        (10, 2, 8),
        (30, 7, 23),
    ] {
        assert_eq!(human_reserved_slots(limit), reserved, "{limit}");
        assert_eq!(agent_class_limit(limit), agents, "{limit}");
        assert!(limit < 2 || agent_class_limit(limit) < limit, "{limit}: humans keep a slot");
    }
    assert_eq!(parse_query_class_header(Some(" Agent ")), QueryClass::Agent);
    for other in [None, Some(""), Some("human"), Some("agents")] {
        assert_eq!(parse_query_class_header(other), QueryClass::Human, "{other:?}");
    }
    assert!(ACQUIRE_LUA.contains("redis.call('ZCARD', agent_key) >= agent_limit"));
    assert!(ACQUIRE_LUA.contains("return -4"));
    assert!(ACQUIRE_LUA.contains("lease(agent_key)"));
    for header in [None, Some("human"), Some("agent"), Some("")] {
        assert_eq!(resolve_query_class(true, header), QueryClass::Agent, "{header:?}");
    }
    assert_eq!(resolve_query_class(false, None), QueryClass::Human);
    assert_eq!(resolve_query_class(false, Some("agent")), QueryClass::Agent);
    for name in [
        "nano Desktop \u{2014} agent tools (mbp)",
        "nano Desktop \u{2014} recon (mbp)",
        "nano Desktop \u{2014} hunt runner (mbp)",
        "nano Desktop \u{2014} hunt sweep (mbp)",
    ] {
        assert!(is_agent_api_key_name(name), "{name}");
    }
    for name in ["ci ingest", "nano Desktop", "my nano Desktop \u{2014} key"] {
        assert!(!is_agent_api_key_name(name), "{name}");
    }
}

#[test]
fn service_order_serves_humans_before_agents() {
    let agent = Uuid::now_v7();
    let human = Uuid::now_v7();
    let mut queue = WaitQueue::default();
    for _ in 0..3 {
        let mut waiter = synthetic(0, agent, QueryPriority::Interactive);
        waiter.class = QueryClass::Agent;
        queue.push(waiter);
    }
    // An Analytics human still goes before Interactive agents.
    queue.push(synthetic(0, human, QueryPriority::Analytics));
    let order = service_order(&mut queue.waiters);
    assert_eq!(queue.waiters[order[0]].subject, human);
    assert!(order[1..]
        .iter()
        .all(|&index| queue.waiters[index].class == QueryClass::Agent));
}

/// Agents fill only their cap; a human arriving behind a queued agent is
/// admitted into the reserved slot; the queued agent runs when an agent
/// permit releases.
#[tokio::test]
async fn agents_never_take_the_human_share() {
    let controller = Arc::new(AdmissionController::new(fleet_config(4, 10)));
    controller.start_drain_loop();
    let agent = |controller: Arc<AdmissionController>, job: String| async move {
        with_query_class(QueryClass::Agent, async move {
            controller
                .acquire(&job, Uuid::now_v7(), QueryPriority::Interactive)
                .await
        })
        .await
    };
    let mut agents = Vec::new();
    for index in 0..agent_class_limit(4) {
        agents.push(
            agent(Arc::clone(&controller), format!("agent{index}"))
                .await
                .expect("agent under its cap"),
        );
    }
    let queued_agent = tokio::spawn(agent(Arc::clone(&controller), "agent-over-cap".into()));
    wait_for_depth(&controller, 1).await;
    assert!(!queued_agent.is_finished(), "the agent over its cap waits");

    let human = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        controller.acquire("human", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await
    .expect("the human is never queued behind capped agents")
    .expect("human admitted into the reserved share");
    assert_eq!(current_query_class(), QueryClass::Human);
    assert!(!queued_agent.is_finished());

    drop(agents.pop());
    let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), queued_agent)
        .await
        .expect("the queued agent runs once an agent permit releases")
        .expect("join")
        .expect("admitted");
    drop((admitted, human, agents));
}

/// Agent waiters never fill the queue (a human always finds a place in
/// line), and a fail-fast agent never takes a free slot past a waiting human.
#[tokio::test]
async fn agents_never_fill_the_queue_or_barge_past_humans() {
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        max_queue_depth: 4,
        ..fleet_config(1, 10)
    }));
    let held = controller
        .acquire("holder", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .expect("first slot");
    let mut waiting = Vec::new();
    for index in 0..agent_class_limit(4) {
        let spawned = Arc::clone(&controller);
        waiting.push(tokio::spawn(with_query_class(QueryClass::Agent, async move {
            spawned
                .acquire(&format!("agent{index}"), Uuid::now_v7(), QueryPriority::Interactive)
                .await
        })));
        wait_for_depth(&controller, index + 1).await;
    }
    let over = with_query_class(
        QueryClass::Agent,
        controller.acquire("agent-over", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(
        matches!(over, Err(AdmissionError::QueueFull { .. })),
        "agents stop at their share of the queue"
    );
    let human = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            controller
                .acquire("human", Uuid::now_v7(), QueryPriority::Interactive)
                .await
        })
    };
    wait_for_depth(&controller, agent_class_limit(4) + 1).await;

    drop(held);
    let barge = with_query_class(
        QueryClass::Agent,
        with_wait_budget(
            std::time::Duration::ZERO,
            controller.acquire("agent-fail-fast", Uuid::now_v7(), QueryPriority::Interactive),
        ),
    )
    .await;
    assert!(barge.is_err(), "a fail-fast agent never barges past a waiting human");
    controller.drain_queue().await;
    let human = tokio::time::timeout(std::time::Duration::from_secs(5), human)
        .await
        .expect("the human is served first")
        .expect("join")
        .expect("human admitted");
    drop(human);
    for waiter in waiting {
        waiter.abort();
    }
}

/// With Redis admission configured but not connected, an agent-class search
/// fails closed (the local ledger counts one replica only), while a human
/// search keeps the local fallback.
#[tokio::test]
async fn agents_fail_closed_without_configured_redis_humans_do_not() {
    let controller = AdmissionController::new(fleet_config(4, 10));
    controller.expect_redis();
    let agent = with_query_class(
        QueryClass::Agent,
        controller.acquire("agent", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(matches!(agent, Err(AdmissionError::Unavailable)), "agent fails closed");
    let human = controller
        .acquire("human", Uuid::now_v7(), QueryPriority::Interactive)
        .await;
    assert!(human.is_ok(), "a human keeps the local fallback");
}

/// An agent permit's ledger counts return to zero on every exit: a normal
/// drop, a cancelled holder task and a panicking one.
#[tokio::test]
async fn agent_ledger_counts_return_to_zero_on_every_exit() {
    let controller = Arc::new(AdmissionController::new(fleet_config(8, 10)));
    let acquire = move |controller: Arc<AdmissionController>| async move {
        with_query_class(
            QueryClass::Agent,
            controller.acquire("agent", Uuid::now_v7(), QueryPriority::Interactive),
        )
        .await
        .expect("agent admitted")
    };
    let dropped = acquire(Arc::clone(&controller)).await;
    let cancelled = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let _permit = acquire(controller).await;
            std::future::pending::<()>().await;
        })
    };
    let panicked = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let _permit = acquire(controller).await;
            panic!("search task panicked holding its permit");
        })
    };
    assert!(panicked.await.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while lock_ledger(&controller.ledger).agent_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the cancelled holder still holds its permit");
    cancelled.abort();
    let _ = cancelled.await;
    drop(dropped);
    let ledger = lock_ledger(&controller.ledger);
    assert_eq!((ledger.agent_count(), ledger.active()), (0, 0));
}

/// NAN-3299 / NAN-4703 against a real Redis-compatible server: a permit
/// whose release never arrives is pruned when its lease ends, agent permits
/// stop at the agent cap cluster-wide, and every release removes the
/// permit from every key.
#[tokio::test]
#[ignore = "requires a throwaway Redis at REDIS_URL; run with --ignored"]
async fn redis_leases_prune_orphans_and_cap_agents() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL");
    let client = redis::Client::open(url).unwrap();
    let mut conn = redis::aio::ConnectionManager::new(client).await.unwrap();
    for key in [REDIS_GLOBAL_KEY, REDIS_AGENT_KEY] {
        let _: () = redis::cmd("DEL").arg(key).query_async(&mut conn).await.unwrap();
    }

    let mut controller = AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 4,
        per_user_limit: 2,
        max_queue_depth: 0,
        queue_timeout_ms: 100,
    });
    controller.lease_override = Some(std::time::Duration::from_millis(600));
    controller.set_redis(conn.clone()).await;
    let user = Uuid::now_v7();
    let mut leaked = controller
        .acquire("leaked", user, QueryPriority::Interactive)
        .await
        .expect("first permit admits");
    // The holder's process died: neither the release nor the renewer runs.
    leaked.renewer.take().unwrap().abort();
    std::mem::forget(leaked);
    let held = controller
        .acquire("busy", user, QueryPriority::Interactive)
        .await
        .expect("one slot remains beside the orphan");
    let second = controller
        .acquire("busy-2", user, QueryPriority::Interactive)
        .await;
    assert!(matches!(second, Err(AdmissionError::QueueFull { .. })));
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let a = controller
        .acquire("after-1", user, QueryPriority::Interactive)
        .await
        .expect("orphan pruned");
    let b = controller
        .acquire("after-2", user, QueryPriority::Interactive)
        .await
        .expect("orphan pruned: both slots free again");
    drop((a, b));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Agents: agent_class_limit(4) = 3 cluster-wide.
    let mut agents = Vec::new();
    for _ in 0..3 {
        agents.push(
            with_query_class(
                QueryClass::Agent,
                controller.acquire("agent", Uuid::now_v7(), QueryPriority::Interactive),
            )
            .await
            .expect("agent under its cap"),
        );
    }
    let over = with_query_class(
        QueryClass::Agent,
        controller.acquire("agent-over", Uuid::now_v7(), QueryPriority::Interactive),
    )
    .await;
    assert!(over.is_err(), "the agent cap holds in Redis");
    let human = controller
        .acquire("human", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .expect("the human reserve holds");
    drop((agents, human));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for key in [REDIS_GLOBAL_KEY, REDIS_AGENT_KEY] {
        let members: i64 = redis::cmd("ZCARD").arg(key).query_async(&mut conn).await.unwrap();
        assert_eq!(members, 0, "{key} released");
    }
}

// ------------------------------------------------------------------
// NAN-4928 review: lease renewal and Redis-outage bounds
// ------------------------------------------------------------------

/// A permit that stays alive longer than one lease (a lateral search's many
/// hop queries) keeps its slot: the lease is renewed while it lives, so no
/// second search of the same user is admitted into it. Dropping it frees it.
#[tokio::test]
async fn live_permits_renew_their_lease_past_one_lease() {
    let controller = short_lease_controller(one_slot_per_user(), 120);
    controller.start_drain_loop();
    let user = Uuid::now_v7();
    let held = controller
        .acquire("long-lateral", user, QueryPriority::Interactive)
        .await
        .unwrap();
    // Five leases later the slot is still held.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let refused = with_wait_budget(
        std::time::Duration::ZERO,
        controller.acquire("second", user, QueryPriority::Interactive),
    )
    .await;
    assert!(refused.is_err(), "a renewed lease is never reclaimed while its permit lives");
    assert_eq!(controller.stats().await.active_adhoc, 1);
    drop(held);
    let next = controller
        .acquire("after", user, QueryPriority::Interactive)
        .await
        .expect("dropping the permit frees the slot");
    drop(next);
}

/// A leaked permit (holder gone, renewer gone with it) is still reclaimed.
#[tokio::test]
async fn a_leaked_permit_without_its_renewer_is_reclaimed() {
    let controller = short_lease_controller(one_slot_per_user(), 100);
    let user = Uuid::now_v7();
    let mut leaked = controller
        .acquire("leaked", user, QueryPriority::Interactive)
        .await
        .unwrap();
    // Simulate the holder's process dying: its renewer stops with it.
    leaked.renewer.take().unwrap().abort();
    std::mem::forget(leaked);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let next = controller
        .acquire("next", user, QueryPriority::Interactive)
        .await
        .expect("reclaimed after one lease");
    drop(next);
}

/// While configured Redis admission is down, each replica admits at most its
/// share of the global limit (3 replicas x 2 = the configured 6, never 18),
/// and past the grace ad-hoc searches fail closed until Redis answers.
#[tokio::test]
async fn redis_outage_keeps_the_global_limit_then_fails_closed() {
    let mut controller = AdmissionController::new(fleet_config(6, 10));
    controller.replica_count = 3;
    controller.redis_outage_grace = std::time::Duration::from_secs(30);
    controller.expect_redis(); // configured, never connected: an outage
    async fn fail_fast(c: &AdmissionController, job: &str) -> Result<AdmissionPermit, AdmissionError> {
        with_wait_budget(
            std::time::Duration::ZERO,
            c.acquire(job, Uuid::now_v7(), QueryPriority::Interactive),
        )
        .await
    }
    let a = fail_fast(&controller, "a").await.expect("within this replica's share");
    let b = fail_fast(&controller, "b").await.expect("within this replica's share");
    assert!(
        fail_fast(&controller, "c").await.is_err(),
        "a third local permit would exceed global / replicas"
    );
    drop((a, b));

    // Past the grace: fail closed.
    *controller.redis_failing_since.lock().unwrap() =
        Some(Instant::now() - std::time::Duration::from_secs(31));
    assert!(matches!(
        fail_fast(&controller, "d").await,
        Err(AdmissionError::Unavailable)
    ));
    // Detection / NRT still bypass admission entirely.
    assert!(controller
        .acquire("rule", Uuid::now_v7(), QueryPriority::Detection)
        .await
        .is_ok());
}

/// Without Redis configured (single instance) the local ledger keeps the
/// full global limit; the outage bound never applies.
#[tokio::test]
async fn single_instance_without_redis_keeps_the_full_limit() {
    let mut controller = AdmissionController::new(fleet_config(4, 10));
    controller.replica_count = 3;
    let mut held = Vec::new();
    for job in ["a", "b", "c", "d"] {
        held.push(
            with_wait_budget(
                std::time::Duration::ZERO,
                controller.acquire(job, Uuid::now_v7(), QueryPriority::Interactive),
            )
            .await
            .expect("full global limit"),
        );
    }
}

/// NAN-4928 review P1 against a real Redis-compatible server: a permit held
/// longer than its lease keeps its Redis lease (renewed), and its release
/// removes it.
#[tokio::test]
#[ignore = "requires a throwaway Redis at REDIS_URL; run with --ignored"]
async fn redis_lease_is_renewed_while_the_permit_lives() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL");
    let client = redis::Client::open(url).unwrap();
    let mut conn = redis::aio::ConnectionManager::new(client).await.unwrap();
    let _: () = redis::cmd("DEL").arg(REDIS_GLOBAL_KEY).query_async(&mut conn).await.unwrap();
    let mut controller = AdmissionController::new(fleet_config(4, 10));
    controller.lease_override = Some(std::time::Duration::from_millis(300));
    controller.set_redis(conn.clone()).await;
    let held = controller
        .acquire("long", Uuid::now_v7(), QueryPriority::Interactive)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let now_ms = unix_millis_now();
    let live: i64 = redis::cmd("ZCOUNT")
        .arg(REDIS_GLOBAL_KEY)
        .arg(now_ms)
        .arg("+inf")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(live, 1, "four leases later the Redis lease is still live");
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let left: i64 = redis::cmd("ZCARD").arg(REDIS_GLOBAL_KEY).query_async(&mut conn).await.unwrap();
    assert_eq!(left, 0);
}
