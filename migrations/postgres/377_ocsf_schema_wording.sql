-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5271: OCSF wording for schema-facing metadata.
--
-- Column comments that described these columns as UDM fields. Migrations
-- 001 / 000_open_init / 9000002 are applied and are not edited (forward-only);
-- COMMENT ON simply replaces the text. The `udm_validation` agent display-name
-- rename is in the enterprise overlay (9000093), because the overlay's 9000003
-- seed runs after this core series on a fresh install.
COMMENT ON COLUMN public.detection_rules.risk_entity_field IS
    'Field the risk entity is extracted from: an OCSF path (e.g. src_endpoint.ip, actor.user.name, device.hostname). If NULL, the entity is resolved from the matched event''s class-correct columns.';
COMMENT ON COLUMN public.detection_rules.requires_fields IS
    'Fields (OCSF paths) required for this rule';
COMMENT ON COLUMN public.repository_rules.requires_fields IS
    'Fields (OCSF paths) required for this rule to work';
