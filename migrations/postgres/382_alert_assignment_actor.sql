-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5314: record WHO assigned an alert and WHEN.
--
-- `alerts.assigned_to` only held the assignee's user typeid, so the alert
-- detail Triage card and Timeline had nothing to render for an assignment
-- ("No triage actions yet" after assigning). Acknowledge/close already store
-- their actor + timestamp; assignment now does the same.
--
-- Forward-only, additive, nullable: existing assigned rows keep NULL here and
-- render the assignee without an actor/time.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_by TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ;
