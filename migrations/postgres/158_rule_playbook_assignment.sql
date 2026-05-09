-- Rule → Playbook Assignment (NAN-452)
--
-- Lets a rule author pick, at authoring time, what playbook runs when the
-- rule fires and produces a case. Three modes:
--   * 'none'     — no playbook (default; preserves existing behaviour)
--   * 'specific' — attach a named library playbook at case-creation time
--   * 'adaptive' — leave the case empty; Shadow Investigator composes one on wrap
--
-- The alert → case grouping pipeline (cases/service/grouping.rs) reads these
-- columns after creating the case and calls PlaybookService::attach_to_case
-- when mode = 'specific'. Mode = 'adaptive' is a no-op at firing time; the
-- existing shadow-investigation hook already auto-composes on completion.

-- Note: ON DELETE RESTRICT (not SET NULL) — if we cleared playbook_id on delete
-- while the CHECK constraint requires it when mode = 'specific', the delete
-- would fail. Force admins to retarget or unassign referencing rules first.
ALTER TABLE detection_rules
    ADD COLUMN playbook_selector_mode TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN playbook_id UUID NULL REFERENCES playbooks(id) ON DELETE RESTRICT;

ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_playbook_selector_mode_check
        CHECK (playbook_selector_mode IN ('none', 'specific', 'adaptive'));

-- Integrity: playbook_id only meaningful when mode = 'specific'
ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_playbook_id_mode_check
        CHECK (
            (playbook_selector_mode = 'specific' AND playbook_id IS NOT NULL)
            OR (playbook_selector_mode IN ('none', 'adaptive') AND playbook_id IS NULL)
        );

-- Reverse lookup: find all rules that attach a given playbook (for the
-- playbook detail page's "used by" panel + for the archive-playbook guard).
CREATE INDEX idx_detection_rules_playbook_id
    ON detection_rules (playbook_id)
    WHERE playbook_id IS NOT NULL;

COMMENT ON COLUMN detection_rules.playbook_selector_mode IS 'Playbook attachment mode for alerts: none, specific (playbook_id set), or adaptive (Shadow Investigator composes)';
COMMENT ON COLUMN detection_rules.playbook_id IS 'Library playbook to attach when rule fires (only set when selector_mode = specific)';
