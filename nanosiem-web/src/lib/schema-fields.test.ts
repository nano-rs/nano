// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  SEMANTIC_FIELDS,
  buildFieldFilter,
  buildMultiFieldFilter,
  conceptColumns,
  contentBranchFor,
  profileColumns,
  readSchemaField,
  readSchemaFieldEntry,
  schemaField,
  schemaFieldCandidates,
  schemaFieldMap,
  semanticFieldsFor,
  toSchemaProfile,
  type SemanticField,
} from './schema-fields';
import { OCSF_FIELD_FALLBACKS, fieldVal } from './ocsf-field-fallbacks';
import { UDM_COLUMNS } from './udm-fields';

describe('schema-fields: profile resolution', () => {
  it('maps the backend discriminator and never guesses one', () => {
    expect(toSchemaProfile('udm')).toBe('udm');
    expect(toSchemaProfile('ocsf')).toBe('ocsf');
    expect(toSchemaProfile(undefined)).toBeNull();
    expect(toSchemaProfile('spans')).toBeNull();
  });
});

describe('schema-fields: UDM profile', () => {
  it('returns UDM column names', () => {
    expect(schemaField('udm', 'srcIp')).toBe('src_ip');
    expect(schemaField('udm', 'destIp')).toBe('dest_ip');
    expect(schemaField('udm', 'user')).toBe('user');
    expect(schemaField('udm', 'processName')).toBe('process_name');
    expect(schemaField('udm', 'commandLine')).toBe('command_line');
    expect(schemaField('udm', 'logSource')).toBe('source_type');
  });

  it('builds single-column UDM filters', () => {
    expect(buildFieldFilter('udm', 'srcIp', '10.0.0.1')).toBe('src_ip="10.0.0.1"');
    expect(buildFieldFilter('udm', 'user', 'bob')).toBe('user="bob"');
  });

  it('every UDM column is a real nanosiem.logs column (or a documented alias)', () => {
    const notInCsv: string[] = [];
    for (const key of Object.keys(SEMANTIC_FIELDS) as SemanticField[]) {
      for (const col of SEMANTIC_FIELDS[key].udm) if (!UDM_COLUMNS.has(col)) notInCsv.push(col);
    }
    expect(notInCsv).toEqual([]);
  });
});

describe('schema-fields: OCSF profile', () => {
  it('returns OCSF paths', () => {
    expect(schemaField('ocsf', 'srcIp')).toBe('src_endpoint.ip');
    expect(schemaField('ocsf', 'destIp')).toBe('dst_endpoint.ip');
    expect(schemaField('ocsf', 'host')).toBe('device.hostname');
    expect(schemaField('ocsf', 'processName')).toBe('process.name');
    expect(schemaField('ocsf', 'commandLine')).toBe('process.cmd_line');
    expect(schemaField('ocsf', 'fileHash')).toBe('file.hashes.value');
    expect(schemaField('ocsf', 'url')).toBe('http_request.url.url_string');
    expect(schemaField('ocsf', 'logSource')).toBe('metadata.log_source');
  });

  it('class-dependent concepts carry every column, most specific first', () => {
    expect(schemaFieldCandidates('ocsf', 'user')).toEqual(['actor.user.name', 'user.name']);
    expect(schemaFieldCandidates('ocsf', 'host')).toEqual(['device.hostname', 'src_endpoint.hostname']);
  });

  it('builds single-column and OR-group filters', () => {
    expect(buildFieldFilter('ocsf', 'srcIp', '10.0.0.1')).toBe('src_endpoint.ip="10.0.0.1"');
    expect(buildFieldFilter('ocsf', 'user', 'bob')).toBe('(actor.user.name="bob" OR user.name="bob")');
  });

  it('preserves quotes by switching delimiter, and doubles backslashes', () => {
    expect(buildFieldFilter('ocsf', 'commandLine', 'a "b" \\c')).toBe(`process.cmd_line='a "b" \\\\c'`);
  });

  it('every OCSF path except the routing key is a promoted registry column', () => {
    const promotedPath = fileURLToPath(
      new URL('../../../nanosiem-core/docs/ocsf/events/promoted.json', import.meta.url),
    );
    const promoted = new Set(
      (JSON.parse(readFileSync(promotedPath, 'utf8')) as { ocsf_path: string }[]).map((e) => e.ocsf_path),
    );
    const missing: string[] = [];
    for (const key of Object.keys(SEMANTIC_FIELDS) as SemanticField[]) {
      for (const col of SEMANTIC_FIELDS[key].ocsf) {
        if (col !== 'metadata.log_source' && !promoted.has(col)) missing.push(`${key}:${col}`);
      }
    }
    expect(missing).toEqual([]);
  });
});

describe('schema-fields: pivots are exact (no wildcard broadening)', () => {
  it('a value with * or ? uses the literal IN form', () => {
    expect(buildFieldFilter('udm', 'user', '*')).toBe('user IN ("*")');
    expect(buildFieldFilter('ocsf', 'srcHost', 'ws-??-01')).toBe('src_endpoint.hostname IN ("ws-??-01")');
    expect(buildFieldFilter('ocsf', 'url', 'https://e.com/a?id=1')).toBe(
      '(http_request.url.url_string IN ("https://e.com/a?id=1") OR url.url_string IN ("https://e.com/a?id=1"))',
    );
  });

  it('plain values keep the = form', () => {
    expect(buildFieldFilter('ocsf', 'srcIp', '10.0.0.1')).toBe('src_endpoint.ip="10.0.0.1"');
  });

  it('backslashes are doubled in both forms', () => {
    expect(buildFieldFilter('udm', 'filePath', '\\\\srv\\share')).toBe('file_path="\\\\\\\\srv\\\\share"');
    expect(buildFieldFilter('udm', 'filePath', 'C:\\a?.txt')).toBe('file_path IN ("C:\\\\a?.txt")');
  });

  it('multi-concept filters are exact too', () => {
    expect(buildMultiFieldFilter('udm', ['srcIp', 'destIp'], '*')).toBe('(src_ip IN ("*") OR dest_ip IN ("*"))');
  });
});

describe('schema-fields: reading rows', () => {
  it('reads the active profile first, then the other', () => {
    expect(readSchemaField({ 'src_endpoint.ip': '1.1.1.1' }, 'srcIp', 'ocsf')).toBe('1.1.1.1');
    expect(readSchemaField({ src_ip: '2.2.2.2' }, 'srcIp', 'ocsf')).toBe('2.2.2.2');
    expect(readSchemaField({ src_ip: '2.2.2.2', 'src_endpoint.ip': '1.1.1.1' }, 'srcIp', 'udm')).toBe('2.2.2.2');
  });

  it('falls through empty and "-" placeholders to the next class column', () => {
    const row = { 'actor.user.name': '-', 'user.name': 'alice' };
    expect(readSchemaFieldEntry(row, 'user', 'ocsf')).toEqual({ key: 'user.name', value: 'alice' });
    expect(readSchemaField({}, 'user', 'ocsf')).toBeUndefined();
  });

  it('reverse lookup spans both profiles', () => {
    expect(semanticFieldsFor('src_ip')).toContain('srcIp');
    expect(semanticFieldsFor('SRC_ENDPOINT.IP')).toContain('srcIp');
    expect(semanticFieldsFor('actor.user.name')).toEqual(['user', 'srcUser']);
    expect(semanticFieldsFor('nope')).toEqual([]);
  });
});

describe('schema-fields: helpers', () => {
  it('translates UDM table columns under OCSF and passes unknowns through', () => {
    expect(profileColumns('ocsf', ['timestamp', 'src_ip', 'process_name', 'src_host'])).toEqual([
      'timestamp',
      'src_endpoint.ip',
      'process.name',
      'src_endpoint.hostname',
    ]);
    expect(profileColumns('udm', ['timestamp', 'src_ip'])).toEqual(['timestamp', 'src_ip']);
  });

  it('multi-concept filters dedupe columns and group ORs', () => {
    expect(conceptColumns('ocsf', ['host', 'srcHost'])).toEqual(['device.hostname', 'src_endpoint.hostname']);
    expect(buildMultiFieldFilter('udm', ['srcIp', 'destIp'], '1.2.3.4')).toBe('(src_ip="1.2.3.4" OR dest_ip="1.2.3.4")');
    expect(buildMultiFieldFilter('ocsf', ['srcIp'], '1.2.3.4')).toBe('src_endpoint.ip="1.2.3.4"');
    expect(buildMultiFieldFilter('udm', ['srcHost'], 'h', ['hostname'])).toBe('(src_host="h" OR hostname="h")');
  });

  it('content channel follows the profile', () => {
    expect(contentBranchFor('ocsf')).toBe('main');
    expect(contentBranchFor('udm')).toBe('legacy/clickhouse');
  });

  it('bound map mirrors the free functions', () => {
    const m = schemaFieldMap('ocsf');
    expect(m.isOcsf).toBe(true);
    expect(m.field('destIp')).toBe('dst_endpoint.ip');
    expect(m.filter('srcIp', 'x')).toBe('src_endpoint.ip="x"');
    expect(schemaFieldMap('udm').filter('srcIp', 'x')).toBe('src_ip="x"');
  });

  it('legacy OCSF_FIELD_FALLBACKS derive from the map', () => {
    expect(OCSF_FIELD_FALLBACKS.src_ip).toEqual(['src_endpoint.ip']);
    expect(OCSF_FIELD_FALLBACKS.src_host).toEqual(['src_endpoint.hostname', 'device.hostname']);
    expect(OCSF_FIELD_FALLBACKS.file_hash).toEqual(['file.hashes.value']);
    expect(fieldVal({ 'process.name': 'cmd.exe' }, 'process_name')).toBe('cmd.exe');
  });
});
