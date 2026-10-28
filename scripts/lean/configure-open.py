#!/usr/bin/env python3
"""Add lane C services to lane A's initializer output; never mint identity or keys."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import quote


def write(path, value, mode=0o400, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(tmp, mode)
        if owner is not None:
            os.chown(tmp, *owner)
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def configure(root, environ):
    tenant = (root / 'tenant_id').read_text().strip()
    parsed = uuid.UUID(tenant)
    if str(parsed) != tenant or parsed.version != 4:
        raise ValueError('initializer did not produce a canonical UUIDv4')
    secret = root / 'cell/secret' / tenant
    cell_path = root / 'cell/cell.json'
    cell = json.loads(cell_path.read_text())
    if cell.get('mode') != 'dedicated' or any(cell.get(k) is not None for k in ('control_url', 'cell_identity_file', 'part_signing')):
        raise ValueError('open configuration requires a dedicated local cell')
    # `trusted-local init` owns the flag; never set it here.
    if cell.get('trusted_local') is not True:
        raise ValueError('open configuration requires a cell rendered by trusted-local init')
    cell['require_landlock'] = False
    # NAN-3767: stamp the identity directory (directory-sync feeds, provider
    # sync, pushed identity) onto events at ingest: department, title,
    # manager and groups on the event's user.
    cell['identity_directory_enrich'] = True
    cell['tcp_connect_ports'] = sorted(set(cell.get('tcp_connect_ports', []) + [5432, 9000]))
    write(cell_path, json.dumps(cell), 0o644)
    ingest = json.loads((secret / 'ingest.token').read_text())
    query = json.loads((secret / 'query.token').read_text())
    if ingest['tenant_id'] != tenant or query['tenant_id'] != tenant or 'bronze_list' not in ingest:
        raise ValueError('bootstrap scope does not match the listing tenant')
    dsn_dir = environ.get('NANO_LEAN_PG_DSN_DIR')
    if dsn_dir:
        # NAN-4711 sovereign single-host: each cell role gets its own least-privilege
        # login over verify-full TLS (scripts/sovereign/single-host.sh renders them).
        ingest_database = Path(dsn_dir, 'ingest.dsn').read_text().strip()
        database = Path(dsn_dir, 'detect.dsn').read_text().strip()
        for dsn in (ingest_database, database):
            if not dsn.startswith('postgresql://') or 'sslmode=verify-full' not in dsn:
                raise ValueError('NANO_LEAN_PG_DSN_DIR DSNs must be postgresql:// with sslmode=verify-full')
    else:
        database = 'postgres://{}:{}@postgres:5432/{}'.format(quote(environ.get('POSTGRES_USER', 'nanosiem'), safe=''),
            quote(environ['POSTGRES_PASSWORD'], safe=''), quote(environ.get('POSTGRES_DB', 'nanosiem'), safe=''))
        ingest_database = database
    ingest['local_gc'] = {'database_url': ingest_database}
    location = dict(ingest['bronze'])
    location.update(bucket='nano-shared-r2-' + tenant, prefix=tenant + '/durable-query-result/v1/')
    query['trusted_local_job_results'] = location
    enrichment = dict(ingest['bronze'])
    enrichment.update(prefix='lake/enrichment/v1/tenant_id=' + tenant + '/')
    ingest['enrichment'] = enrichment
    # IOC's existing S3 store supports private RustFS without widening hosted part reads.
    query['enrichment_r2'] = {k: enrichment[k] for k in ('endpoint', 'region', 'access_key_id', 'secret_access_key')}
    query['enrichment_r2']['session_token'] = None
    # Lane B's static detect bootstrap uses the persisted ingest signer.
    # It drains findings; rule reads share query[T]'s host-sized native engine.
    detect_query = dict(query)
    for field in ('trusted_local_job_results', 'job_results_r2', 'enrichment_r2', 'r2', 'part_write_r2', 'part_log_r2', 'expires_at'):
        detect_query.pop(field, None)
    detect = {'format':'nano.lake-detect-trusted-local.v1', 'query':detect_query,
        'database_url':database, 'signer_key_id':ingest['lab_signer_key_id'],
        'signer_seed_hex':ingest['lab_signer_seed_hex'], 'writer_epoch':ingest['writer_epoch']}
    write(secret / 'detect.token', json.dumps(detect))
    write(secret / 'ingest.token', json.dumps(ingest))
    write(secret / 'query.token', json.dumps(query))
    app = root / 'app'
    for name, key in [('otel-ingest.token', 'NANO_OTEL_LAKE_INGEST_TOKEN'), ('otel-query.token', 'NANO_OTEL_LAKE_QUERY_TOKEN'), ('enrichment.token', 'NANO_LAKE_ENRICHMENT_TOKEN'), ('audit.token', 'NANO_LOCAL_AUDIT_TOKEN')]:
        token = environ[key]
        if len(token) < 32 or any(c.isspace() for c in token):
            raise ValueError('invalid local service token')
        write(app / name, token, owner=(999, 999))
    write(app / 'enrichment.json', json.dumps(enrichment), owner=(999, 999))
    # This file carries paths and the public tenant UUID only.
    env = (app / 'lake-cell.env').read_text()
    write(app / 'lake-cell.env', env, 0o644, owner=(999, 999))
    return tenant


if __name__ == '__main__':
    try:
        root = Path(sys.argv[1])
        configure(root, os.environ)
        if '--probe' in sys.argv[2:]:
            probe = subprocess.run(['nanosiem-lake-cell', 'probe', '--config', '/etc/nano-cell/cell.json'], check=True, capture_output=True, text=True)
            # Probe emits the opportunistic Landlock warning on stderr, without credentials.
            sys.stderr.write(probe.stderr)
            report = json.loads(probe.stdout)
            if report.get('identity', {}).get('fatal') or report.get('selected', {}).get('mode') is None:
                raise ValueError('cell isolation probe refused this host; inspect the probe report')
        print('Trusted-local UUID bootstrap configured; hosted control is disabled.')
    except Exception:
        # Bootstrap contains credentials: keep arbitrary exception strings out of logs.
        print('Open lean bootstrap failed; check initializer files, token settings and isolation probe.', file=sys.stderr)
        sys.exit(1)
