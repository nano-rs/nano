CREATE SCHEMA nano_shared;
CREATE TABLE nano_shared.platform_enrichment_feeds(feed_id text primary key,registry_revision bigint default 1,redistribution_approved bool,status text,freshness_seconds int default 604800,terms_revision text default 'approved');
CREATE TABLE nano_shared.platform_feed_publications(feed_id text,enabled bool,adapter_built bool,active_revision bigint);
CREATE TABLE nano_shared.platform_enrichment_feed_versions(feed_id text,revision bigint,digest text,mapping_revision bigint,upstream_at timestamptz,valid_until timestamptz,license_revision text);
CREATE TABLE nano_shared.platform_enrichment_feed_runs(feed_id text,state text,published_revision bigint);
CREATE TABLE public.tenant_platform_enrichment_entitlements(tenant_id uuid,feed_id text,tier text,grant_revision bigint,revision bigint,state text,enabled bool,effective_at timestamptz,expires_at timestamptz,deny_epoch bigint);
CREATE TABLE nano_shared.platform_enrichment_grant_revisions(feed_id text,tier text,revision bigint,license_revision text,effective_at timestamptz,expires_at timestamptz,max_validity_seconds int);
CREATE TABLE nano_shared.platform_enrichment_deny_state(feed_id text,epoch bigint,feed_revision bigint,tier text,grant_revision bigint);
CREATE TABLE nano_shared.bronze_platform_objects(tenant_id uuid,object_sha256 text,claim jsonb);
CREATE FUNCTION nano_shared.bronze_platform_assert(uuid) RETURNS void LANGUAGE sql AS 'SELECT';
CREATE FUNCTION nano_shared.platform_feed_activate(bigint,timestamptz,jsonb,bytea) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE f record; rev bigint := 1;
BEGIN
 SELECT * INTO f FROM nano_shared.platform_enrichment_feeds WHERE feed_id=$3->>'feed_id';
 UPDATE nano_shared.platform_feed_publications SET active_revision=rev WHERE feed_id=f.feed_id;
 RETURN rev;
END $$;
INSERT INTO nano_shared.platform_enrichment_feeds(feed_id,redistribution_approved,status) VALUES
 ('ipinfo_lite',true,'inactive'),('threatfox',true,'inactive'),('tor_exit_nodes',true,'inactive'),('synthient',false,'inactive');
INSERT INTO nano_shared.platform_feed_publications SELECT feed_id,feed_id<>'synthient',true,CASE WHEN feed_id<>'synthient' THEN 1 END FROM nano_shared.platform_enrichment_feeds;
INSERT INTO nano_shared.platform_enrichment_feed_versions SELECT feed_id,1,repeat('a',64),1,now()-interval '1 hour',now()+interval '1 day','approved' FROM nano_shared.platform_enrichment_feeds WHERE feed_id<>'synthient';
INSERT INTO nano_shared.platform_enrichment_feed_runs SELECT feed_id,'published',1 FROM nano_shared.platform_enrichment_feed_versions;
INSERT INTO public.tenant_platform_enrichment_entitlements SELECT 'b464ceb9-28a6-4249-8e29-3489627ac5f6',feed_id,'included',1,1,'active',feed_id<>'synthient',now()-interval '1 day',NULL,0 FROM nano_shared.platform_enrichment_feeds;
INSERT INTO nano_shared.platform_enrichment_grant_revisions SELECT feed_id,'included',1,'approved',now()-interval '1 day',NULL,86400 FROM nano_shared.platform_enrichment_feeds;
