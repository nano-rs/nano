-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5956: what the last successful apply of a content channel did.
--
-- `apply_error` only records failures, so an apply that succeeded but chose
-- not to change anything (for example the model catalog installed while
-- Model Catalog Auto-Sync is off) looked the same as a full apply in
-- GET /api/content/channels. `apply_summary` keeps the applier's short
-- summary of the last successful apply. Additive, forward-only, idempotent.
ALTER TABLE content_channel_state ADD COLUMN IF NOT EXISTS apply_summary TEXT;

COMMENT ON COLUMN content_channel_state.apply_summary IS
    'Short summary of the last successful apply (NULL after a failed apply or before the first apply)';
