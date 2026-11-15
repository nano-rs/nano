-- Key the per-(rule, entity) alert-cooldown anchors on a fixed-size digest
-- of the entity instead of the entity text itself (NAN-5429).
--
-- Migration 248 made `(rule_id, entity)` the primary key. A btree index
-- entry is capped at ~2.7 KB, so an entity value longer than that which does
-- not compress well (a long hostname, URL or command line) could not be
-- inserted: the anchor write failed and the cooldown never applied to that
-- entity. The key is now `(rule_id, entity_hash)` where
-- `entity_hash = sha256(<entity as UTF-8>)` (32 bytes, computed by the
-- application). The full value stays in `entity`, which is no longer indexed.
--
-- Forward-only and cheap: the table holds one row per live (rule, entity)
-- pair and is pruned to 30 days on every write, so the backfill below is a
-- small single-statement UPDATE. Rows written by an older binary during a
-- rolling upgrade fail their (best-effort) anchor upsert until that replica
-- is replaced; reads by an older binary keep working (`entity` is unchanged).

ALTER TABLE detection_alert_entity_cooldowns
    ADD COLUMN IF NOT EXISTS entity_hash bytea;

UPDATE detection_alert_entity_cooldowns
SET entity_hash = sha256(convert_to(entity, 'UTF8'))
WHERE entity_hash IS NULL;

ALTER TABLE detection_alert_entity_cooldowns
    ALTER COLUMN entity_hash SET NOT NULL;

ALTER TABLE detection_alert_entity_cooldowns
    DROP CONSTRAINT IF EXISTS detection_alert_entity_cooldowns_pkey;

ALTER TABLE detection_alert_entity_cooldowns
    ADD CONSTRAINT detection_alert_entity_cooldowns_pkey PRIMARY KEY (rule_id, entity_hash);

ALTER TABLE detection_alert_entity_cooldowns
    ADD CONSTRAINT detection_alert_entity_cooldowns_hash_len
        CHECK (octet_length(entity_hash) = 32);

COMMENT ON COLUMN detection_alert_entity_cooldowns.entity_hash IS
    'NAN-5429: sha256 of the entity value (UTF-8). Primary-key component so entities of any length can be anchored; the full value is kept unindexed in entity.';
