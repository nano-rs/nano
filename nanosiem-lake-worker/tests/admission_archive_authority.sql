-- Run only in an isolated test database after migration 9001240.
\set ON_ERROR_STOP on
CREATE ROLE archive_publisher LOGIN;
CREATE ROLE archive_reader LOGIN;
CREATE ROLE archive_other LOGIN;
GRANT USAGE ON SCHEMA nano_shared TO archive_publisher,archive_reader,archive_other;
GRANT EXECUTE ON FUNCTION nano_shared.admission_archive_transition(UUID,TEXT,TEXT,BYTEA,JSONB,UUID)
  TO archive_publisher,archive_reader,archive_other;
INSERT INTO nano_shared.admission_archive_principals VALUES
  ('archive_publisher','11111111-1111-4111-8111-111111111111',true,true,true,true),
  ('archive_reader','11111111-1111-4111-8111-111111111111',false,true,false,true),
  ('archive_other','22222222-2222-4222-8222-222222222222',true,true,true,true);

CREATE TEMP TABLE test_results(name TEXT PRIMARY KEY);
GRANT INSERT,SELECT ON test_results TO archive_publisher,archive_reader,archive_other;
CREATE FUNCTION pg_temp.ok(name TEXT, condition BOOLEAN) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM true THEN RAISE EXCEPTION 'FAIL: %',name; END IF;
    INSERT INTO pg_temp.test_results VALUES(name);
END $$;
CREATE FUNCTION pg_temp.refused(name TEXT, statement TEXT, expected TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE caught TEXT;
BEGIN
    BEGIN EXECUTE statement; EXCEPTION WHEN OTHERS THEN caught := SQLERRM; END;
    IF caught IS NULL OR position(expected IN caught)=0 THEN
        RAISE EXCEPTION 'FAIL: %, expected %, got %',name,expected,caught;
    END IF;
    INSERT INTO pg_temp.test_results VALUES(name);
END $$;

SELECT pg_temp.ok('four tables force RLS', (SELECT count(*)=4 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='nano_shared' AND c.relname IN ('admission_archives','admission_archive_principals','admission_archive_references','admission_archive_audit')
    AND c.relrowsecurity AND c.relforcerowsecurity));

-- This fixture tests the authority protocol; Rust tests cover descriptor schema.
SELECT convert_to('{"contract":1,"tenant_id":"11111111-1111-4111-8111-111111111111","dependencies":[{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":7}]}','UTF8') AS descriptor \gset
SELECT encode(sha256(:'descriptor'::bytea),'hex') AS digest \gset
SELECT '11111111-1111-4111-8111-111111111111/retained-generation/v1/admission/' || :'digest' || '/sha256/' || repeat('a',64) AS object_key \gset
SELECT jsonb_build_object('descriptor',convert_from(:'descriptor'::bytea,'UTF8')::jsonb,
  'objects',jsonb_build_object(:'object_key',jsonb_build_object('key',:'object_key','sha256',repeat('a',64),'bytes',7,'version','"etag-1"'))) AS publication \gset

SET SESSION AUTHORIZATION archive_publisher;
SELECT pg_temp.refused('unpublished cannot be retained',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111',:'digest','33333333-3333-4333-8333-333333333333'),'archive unavailable');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','reserve',:'descriptor'::bytea);
SELECT pg_temp.refused('partial publication cannot be retained',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111',:'digest','33333333-3333-4333-8333-333333333333'),'archive not admissible');
SELECT pg_temp.refused('reserved namespace cannot retire',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retire'')',
  '11111111-1111-4111-8111-111111111111',:'digest'),'archive remains retained');
SELECT pg_temp.refused('missing uploaded object refuses publication',format('SELECT nano_shared.admission_archive_transition(%L,%L,''publish'',NULL,%L::jsonb)',
  '11111111-1111-4111-8111-111111111111',:'digest',jsonb_set(:'publication'::jsonb,'{objects}','{}')),'incomplete publication');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','publish',NULL,:'publication'::jsonb);
SELECT pg_temp.ok('publication replay is idempotent',nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','publish',NULL,:'publication'::jsonb)='{}');
SELECT pg_temp.refused('publication hold covers admission window',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retire'')',
  '11111111-1111-4111-8111-111111111111',:'digest'),'archive remains retained');
SELECT pg_temp.refused('publication hold cannot drop without successor',format('SELECT nano_shared.admission_archive_transition(%L,%L,''release_publication'')',
  '11111111-1111-4111-8111-111111111111',:'digest'),'publication has no retained successor');

RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION archive_other;
SELECT pg_temp.refused('wrong tenant cannot retain',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111',:'digest','33333333-3333-4333-8333-333333333333'),'archive capability denied');
SELECT pg_temp.refused('caller GUC cannot override principal',format('SELECT set_config(''app.tenant_id'',%L,false); SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111','11111111-1111-4111-8111-111111111111',:'digest','33333333-3333-4333-8333-333333333333'),'archive capability denied');
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION archive_reader;
SELECT pg_temp.refused('reader has no table DML','DELETE FROM nano_shared.admission_archives','permission denied');
SELECT pg_temp.refused('reader cannot retire',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retire'')',
  '11111111-1111-4111-8111-111111111111',:'digest'),'archive capability denied');
SELECT pg_temp.ok('retained receipt is exact',nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','retain',NULL,NULL,'33333333-3333-4333-8333-333333333333')=:'publication'::jsonb);
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION archive_publisher;
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','release_publication');
SELECT pg_temp.refused('held accepted reference prevents retirement',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retire'')',
  '11111111-1111-4111-8111-111111111111',:'digest'),'archive remains retained');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','release',NULL,NULL,'33333333-3333-4333-8333-333333333333');
SELECT pg_temp.refused('released reference cannot be reused',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111',:'digest','33333333-3333-4333-8333-333333333333'),'reference conflict');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'digest','retire');
SELECT pg_temp.refused('retired descriptor cannot be retained',format('SELECT nano_shared.admission_archive_transition(%L,%L,''retain'',NULL,NULL,%L)',
  '11111111-1111-4111-8111-111111111111',:'digest','44444444-4444-4444-8444-444444444444'),'archive unavailable');
SELECT pg_temp.refused('late publisher cannot resurrect',format('SELECT nano_shared.admission_archive_transition(%L,%L,''reserve'',%L::bytea)',
  '11111111-1111-4111-8111-111111111111',:'digest',:'descriptor'),'archive unavailable');
RESET SESSION AUTHORIZATION;
SELECT pg_temp.ok('transitions are audited',(SELECT count(*)=7 FROM nano_shared.admission_archive_audit));
SELECT count(*) AS passed FROM test_results;
SELECT * FROM test_results ORDER BY name;

-- A second publication for the shell harness's two-connection race tests.
SELECT convert_to((convert_from(:'descriptor'::bytea,'UTF8')::jsonb || '{"race":true}'::jsonb)::text,'UTF8') AS race_descriptor \gset
SELECT encode(sha256(:'race_descriptor'::bytea),'hex') AS race_digest \gset
SELECT '11111111-1111-4111-8111-111111111111/retained-generation/v1/admission/' || :'race_digest' || '/sha256/' || repeat('a',64) AS race_key \gset
SELECT jsonb_build_object('descriptor',convert_from(:'race_descriptor'::bytea,'UTF8')::jsonb,
  'objects',jsonb_build_object(:'race_key',jsonb_build_object('key',:'race_key','sha256',repeat('a',64),'bytes',7,'version','"etag-1"'))) AS race_publication \gset
SET SESSION AUTHORIZATION archive_publisher;
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'race_digest','reserve',:'race_descriptor'::bytea);
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'race_digest','publish',NULL,:'race_publication'::jsonb);
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'race_digest','retain',NULL,NULL,'55555555-5555-4555-8555-555555555555');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'race_digest','release_publication');
SELECT nano_shared.admission_archive_transition('11111111-1111-4111-8111-111111111111',:'race_digest','release',NULL,NULL,'55555555-5555-4555-8555-555555555555');
