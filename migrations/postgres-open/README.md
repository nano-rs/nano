# Open-tier fresh-init Postgres snapshot

This directory contains the **open-only** fresh-init snapshot
(`000_open_init.sql`), applied by the runtime when it detects a truly
fresh database. It captures the open-tier schema as of legacy migration
version 175.

See `../SPLIT_RATIONALE.md` for the three-state migration topology that
this directory plugs into, and `nanosiem-core/src/db/migrations.rs` for
the runtime detection logic.

## When this file is applied

Three deployment states (`migrations/SPLIT_RATIONALE.md`):

| State                | `_sqlx_migrations` | What runs                                     |
|----------------------|--------------------|-----------------------------------------------|
| Legacy tenant        | populated 1..N     | `migrations/postgres/` only                   |
| Fresh open install   | absent             | snapshot → backfill 1..175 → migrator no-op   |
| Fresh enterprise     | absent             | same as fresh open + enterprise overlay       |

Detection is auto by default. The env var
`NANOSIEM_MIGRATION_MODE=legacy` forces the today-equivalent path
(useful as a belt-and-suspenders pin on known-existing deployments).

## Going forward — new open-tier migrations

NEW open-tier migrations (versions 176+) land in `migrations/postgres/`
exactly as today. They run on **all three states**:
- Legacy: applied directly
- Fresh: after the snapshot pre-applied 1..175 as no-ops, the migrator
  picks up version 176+ and runs them
- Fresh enterprise: same as fresh

There is no fork. The snapshot is regenerated periodically (see below)
to fold in newer history once it has soaked.

## Regenerating the snapshot

When the snapshot needs to advance beyond version 175 (typically every
quarter or so to keep fresh-install times short), regenerate as follows:

```bash
# 1. Spin up a one-off Postgres
docker run -d --rm --name nan749-snap-pg \
  -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test -e POSTGRES_DB=test \
  -p 55749:5432 postgres:18
sleep 4

# 2. Apply all current migrations
docker cp migrations/postgres nan749-snap-pg:/migrations
docker exec nan749-snap-pg bash -c '
  set -e; cd /migrations
  for f in $(ls *.sql | sort); do
    PGPASSWORD=test psql -U test -d test -v ON_ERROR_STOP=1 -q -f "$f"
  done'

# 3. Dump the schema
docker exec nan749-snap-pg pg_dump -U test -d test \
  --schema-only --no-owner --no-acl > /tmp/nan749_full_schema.sql

# 3b. NAN-851: dump seed data for whitelisted seed tables. Without this
#     step every regen drops the INSERTs from migrations 1..175 and the
#     fresh-deploy snapshot ships missing rows (providers, agents, GDPR
#     salt, queues, permissions, etc.) — the exact drift NAN-850 patched
#     after the fact. The whitelist mirrors `SEED_TABLES` in the splitter;
#     update both together when seeding a new table.
docker exec nan749-snap-pg pg_dump -U test -d test \
  --data-only --column-inserts --no-owner --no-acl \
  --table=permissions --table=role_permissions \
  --table=roles --table=groups --table=group_roles \
  --table=namespaces \
  --table=marketplace_catalog --table=enrichment_marketplace_repos --table=enrichment_sources \
  --table=provider_credentials \
  --table=source_configurations --table=routing_rules \
  --table=system_settings --table=prevalence_settings \
  --table=signal_processor_watermarks --table=license_status \
  --table=users \
  --table=queues --table=queue_routing_rules \
  --table=melod_settings --table=agent_model_config --table=case_grouping_rules \
  --table=playbook_repositories \
  > /tmp/nan749_seed_data.sql

# 4. Run the splitter — produces /tmp/nan749_open_init.sql
#    and /tmp/nan749_enterprise_init.sql. Reads both /tmp/nan749_full_schema.sql
#    (schema) and /tmp/nan749_seed_data.sql (data) and routes each block to
#    the appropriate output by table classification. Seed INSERTs are
#    rewritten with `ON CONFLICT DO NOTHING` for idempotency.
python3 tools/nan749_split_open_overlay.py

# 5. Schema parity gate (must show only cosmetic diffs)
docker exec nan749-snap-pg psql -U test -d test -c \
  'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
docker cp /tmp/nan749_open_init.sql nan749-snap-pg:/open.sql
docker cp /tmp/nan749_enterprise_init.sql nan749-snap-pg:/ent.sql
docker exec nan749-snap-pg psql -U test -d test -v ON_ERROR_STOP=1 -f /open.sql
docker exec nan749-snap-pg psql -U test -d test -v ON_ERROR_STOP=1 -f /ent.sql
docker exec nan749-snap-pg pg_dump -U test -d test --schema-only \
  --no-owner --no-acl > /tmp/nan749_combined.sql
diff /tmp/nan749_full_schema.sql /tmp/nan749_combined.sql

# 6. Replace the committed files
cp /tmp/nan749_open_init.sql migrations/postgres-open/000_open_init.sql
cp /tmp/nan749_enterprise_init.sql \
  migrations/postgres-enterprise/9000002_enterprise_full.sql

# 7. Update the version cutoff in the snapshot's header comment and
#    expand SHARED_TABLE_ENTERPRISE_COLUMNS in tools/nan749_split_open_overlay.py
#    if any new ALTER TABLE column-adds on shared tables landed between
#    snapshots.

docker stop nan749-snap-pg
```

The schema parity diff should show only:
- Different `\restrict` random tokens (cosmetic — psql meta-cmd)
- CHECK constraint formatting differences (`ANY (ARRAY[...]::text[])` vs
  `ANY (ARRAY[(...)::text, (...)::text])`)
- Column ordering: ALTER-added columns appear at the end of the table
  rather than where they were originally inserted
- `incident_id` / `playbook_id` ordering on `alerts` / `detection_rules`

These are functionally equivalent — the application doesn't depend on
column ordering or check-formatting whitespace.

If the diff shows a real schema difference (missing table, missing
index, wrong column type), iterate the splitter's classification:
- `ENTERPRISE_TABLES` — the enterprise-only table list
- `SHARED_TABLE_ENTERPRISE_COLUMNS` — enterprise columns on otherwise-
  shared tables that get stripped from open

## Idempotence rules

Every statement in this file MUST be idempotent because the snapshot
applies on top of:

1. A fresh open install (clean DB → CREATE everything)
2. A fresh enterprise install (clean DB → CREATE everything, then the
   overlay layers enterprise tables/columns on top)
3. Defensively, even if Layer 1 detection ever misfires on a populated
   DB, the snapshot must be a no-op

Use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`,
`CREATE OR REPLACE FUNCTION`, `CREATE OR REPLACE VIEW`,
`CREATE SEQUENCE IF NOT EXISTS`, and guarded `DO $$ … $$` blocks for
constraints, triggers, and types.
