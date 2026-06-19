-- Re-apply the 119 rename of the system AI user to "pivt".
--
-- Migration 119 renamed the system AI user (id …099) from "NanoSIEM AI"
-- to "pivt". The 177 open-baseline seed later re-inserted that user with
-- name 'NanoSIEM AI' (ON CONFLICT DO NOTHING). On any database where the
-- user row was first created by 177 — after 119's UPDATE had already run
-- as a no-op against a non-existent row — the name stuck as "NanoSIEM AI"
-- and surfaced in the UI (e.g. the "start investigating" author in Cases).
--
-- Forward-fix only: 119/177 are applied migrations and must not be edited.
-- Guarded so it touches only the system AI user and is a no-op once correct.
UPDATE users
SET name = 'pivt'
WHERE id = '00000000-0000-0000-0000-000000000099'
  AND name = 'NanoSIEM AI';
