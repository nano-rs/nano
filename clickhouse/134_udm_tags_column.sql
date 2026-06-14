-- NAN-1464: CIM realignment — add the `tags` event-class taxonomy column.
--
-- nano's UDM had repurposed `category` as a universal event-class taxonomy
-- (authentication / network / web_proxy / ...), which collides with Splunk CIM,
-- where `category` is the data-model-specific CONTENT category (Web.category =
-- social_media, etc.). This adds a dedicated `tags Array(String)` column for the
-- event-class taxonomy (a proxy event is `tags=['web','proxy']`), freeing
-- `category` for the CIM content category.
--
-- Parsers write `.udm.tags`; nPL `tags="web"` compiles to `has(tags,'web')`
-- (array membership). Plain (not MATERIALIZED) column, mirroring the physical
-- type of the existing Array(String) `*_tags` enrichment columns.

ALTER TABLE nanosiem.logs
    ADD COLUMN IF NOT EXISTS `tags` Array(String) DEFAULT [] CODEC(ZSTD(1)) AFTER `category`;
