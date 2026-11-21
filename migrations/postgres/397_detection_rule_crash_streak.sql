-- NAN-5736: a detection run that kills the executing process (OOM, crash)
-- never reaches `release_claim`, so the NAN-5424 failure counters it folds in
-- at the next claim were never persisted: `consecutive_failures` stayed put,
-- `inflight_claims` kept climbing and the rule was retried every stale-claim
-- timeout forever, killing the jobs process each time.
--
-- A process crash kills EVERY rule executing in it, so a crash is only
-- attributed to a rule that was running alone:
--
-- `crash_suspect`: an earlier run of this rule died together with other
-- rules (attribution ambiguous). Its next run executes in isolation (no other
-- scheduled rule runs in that process meanwhile). Cleared when a run
-- completes.
--
-- `isolated_claim`: the current claim executes in isolation. Set right
-- before that run starts and cleared when it completes, so a claim found
-- unreleased with this flag set died ALONE: the crash is this rule's.
--
-- `crash_streak`: consecutive crashes attributed to this rule. Drives an
-- exponential back-off before it may run again, keeps the rule "failing now"
-- in detection health (also across a coverage gap), and is reset when a run
-- completes or the rule is edited.
ALTER TABLE public.detection_rules
    ADD COLUMN IF NOT EXISTS crash_streak SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS crash_suspect BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS isolated_claim BOOLEAN NOT NULL DEFAULT false;
