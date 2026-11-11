// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The profile-aware field map (NAN-4903): one place that says which column a
 * security concept lives in under each storage schema.
 *
 * A deployment runs one schema profile, fixed at install time and reported by
 * `GET /api/schema/fields` (`schema: "udm" | "ocsf"`). The same login event is
 * `user` / `src_ip` under UDM and `actor.user.name` / `src_endpoint.ip` under
 * OCSF. UI code names the CONCEPT (`srcIp`, `processName`, …) and asks this
 * module for the column, so no surface hardcodes one profile's names.
 *
 * Source of truth for the OCSF paths is the promoted-column registry
 * `nanosiem-core/docs/ocsf/events/promoted.json` (the same artifact the backend
 * `OcsfProfile` loads); each concept's OCSF list is drawn from the entries whose
 * `udm_fields` name the UDM column. The UDM side is the `nanosiem.logs` column.
 *
 * Several OCSF concepts are class-dependent, so a concept can carry more than
 * one OCSF column, ordered most-specific first:
 * - the acting user is `actor.user.name` on endpoint and API events (Sysmon,
 *   CloudTrail) and `user.name` on authentication events;
 * - the host an endpoint event ran on is `device.hostname` (Sysmon leaves
 *   `src_endpoint.hostname` empty), while network/auth events use
 *   `src_endpoint.hostname`;
 * - a proxy URL lives under `http_request.url.*`, other classes use `url.*`.
 *
 * Reads try every column; filters OR across them (`buildFieldFilter`), so a
 * pivot never misses a class that keeps the value in the other column.
 *
 * `metadata.log_source` is the OCSF spelling of the routing key. It is not a
 * promoted column (it resolves to the operational `source_type` column), so the
 * backend field universe does not list it; `logSource` maps to it here.
 */

import { nplExactEquals } from './npl-quote';

export type SchemaProfileId = 'udm' | 'ocsf';

/**
 * Placeholder profile for the moments before `/api/schema/fields` has answered
 * (or while it is failing). It is NEVER a guess at the tenant's schema:
 * `useSchemaFieldMap()` reports `unresolved` and every query-producing action
 * is disabled or guarded until the real profile arrives (NAN-4903). The
 * placeholder only shapes labels and row reads (which try both profiles'
 * columns anyway). UDM spelling is used because it is the one spelling both
 * profiles accept: the OCSF query resolver maps UDM names onto their OCSF
 * columns (NAN-1248), so an ungated straggler still produces a valid query.
 */
export const UNRESOLVED_SCHEMA_PROFILE: SchemaProfileId = 'udm';

/** Normalize the backend discriminator; null when absent or unrecognized. */
export function toSchemaProfile(schema: string | null | undefined): SchemaProfileId | null {
  if (schema === 'udm') return 'udm';
  if (schema === 'ocsf') return 'ocsf';
  return null;
}

interface SemanticFieldDef {
  /** UDM column(s), primary first. */
  readonly udm: readonly string[];
  /** OCSF column path(s), primary first (class-dependent alternates after). */
  readonly ocsf: readonly string[];
}

/**
 * Concept → columns. Keep keys camelCase and named for the concept, not for
 * either profile's column.
 */
export const SEMANTIC_FIELDS = {
  // --- Network endpoints ---
  srcIp: { udm: ['src_ip'], ocsf: ['src_endpoint.ip'] },
  destIp: { udm: ['dest_ip'], ocsf: ['dst_endpoint.ip'] },
  deviceIp: { udm: ['dvc_ip'], ocsf: ['device.ip'] },
  srcHost: { udm: ['src_host'], ocsf: ['src_endpoint.hostname'] },
  destHost: { udm: ['dest_host'], ocsf: ['dst_endpoint.hostname'] },
  /** The host an event happened on (endpoint device, else the source host). */
  host: { udm: ['src_host'], ocsf: ['device.hostname', 'src_endpoint.hostname'] },
  srcPort: { udm: ['src_port'], ocsf: ['src_endpoint.port'] },
  destPort: { udm: ['dest_port'], ocsf: ['dst_endpoint.port'] },
  srcMac: { udm: ['src_mac'], ocsf: ['src_endpoint.mac'] },
  destMac: { udm: ['dest_mac'], ocsf: ['dst_endpoint.mac'] },
  protocol: { udm: ['protocol'], ocsf: ['connection_info.protocol_num'] },
  bytesIn: { udm: ['bytes_in'], ocsf: ['traffic.bytes_in'] },
  bytesOut: { udm: ['bytes_out'], ocsf: ['traffic.bytes_out'] },
  srcCountry: { udm: ['enriched_src_country'], ocsf: ['src_endpoint.location.country'] },
  destCountry: { udm: ['enriched_dest_country'], ocsf: ['dst_endpoint.location.country'] },
  srcAsn: { udm: ['enriched_src_asn'], ocsf: ['src_endpoint.autonomous_system.number'] },
  destAsn: { udm: ['enriched_dest_asn'], ocsf: ['dst_endpoint.autonomous_system.number'] },

  // --- Identity ---
  /** The acting user: actor on endpoint/API events, subject on auth events. */
  user: { udm: ['user'], ocsf: ['actor.user.name', 'user.name'] },
  srcUser: { udm: ['src_user'], ocsf: ['actor.user.name'] },
  destUser: { udm: ['dest_user'], ocsf: ['user.name'] },
  userId: { udm: ['user_id'], ocsf: ['user.uid', 'actor.user.uid'] },
  email: { udm: ['email'], ocsf: ['email.from', 'email.to'] },

  // --- Process ---
  processName: { udm: ['process_name'], ocsf: ['process.name'] },
  commandLine: { udm: ['command_line'], ocsf: ['process.cmd_line'] },
  processPath: { udm: ['process_path'], ocsf: ['process.file.path'] },
  processId: { udm: ['process_id'], ocsf: ['process.pid'] },
  processGuid: { udm: ['process_guid'], ocsf: ['process.uid'] },
  processHash: { udm: ['process_hash'], ocsf: ['process.file.hashes.value'] },
  parentProcessName: { udm: ['parent_process_name'], ocsf: ['actor.process.name', 'process.parent_process.name'] },
  parentCommandLine: { udm: ['parent_command_line'], ocsf: ['actor.process.cmd_line', 'process.parent_process.cmd_line'] },
  parentProcessId: { udm: ['parent_process_id'], ocsf: ['actor.process.pid'] },
  parentProcessGuid: { udm: ['parent_process_guid'], ocsf: ['actor.process.uid'] },
  parentProcessPath: { udm: ['parent_process_path'], ocsf: ['actor.process.file.path'] },

  // --- File / registry ---
  fileName: { udm: ['file_name'], ocsf: ['file.name'] },
  filePath: { udm: ['file_path'], ocsf: ['file.path'] },
  fileHash: { udm: ['file_hash'], ocsf: ['file.hashes.value'] },
  registryPath: { udm: ['registry_path'], ocsf: ['reg_key.path'] },
  registryValueName: { udm: ['registry_value_name'], ocsf: ['reg_value.name'] },
  registryValueData: { udm: ['registry_value_data'], ocsf: ['reg_value.data'] },

  // --- Web / DNS ---
  url: { udm: ['url'], ocsf: ['http_request.url.url_string', 'url.url_string'] },
  domain: { udm: ['url_domain'], ocsf: ['http_request.url.hostname', 'url.hostname'] },
  httpMethod: { udm: ['http_method'], ocsf: ['http_request.http_method'] },
  userAgent: { udm: ['http_user_agent'], ocsf: ['http_request.user_agent'] },
  httpStatus: { udm: ['http_status_code'], ocsf: ['http_response.code'] },
  dnsQuery: { udm: ['query'], ocsf: ['query.hostname'] },
  dnsAnswer: { udm: ['answer'], ocsf: ['answers.rdata'] },

  // --- Auth / session ---
  authResult: { udm: ['auth_result'], ocsf: ['status'] },
  authType: { udm: ['auth_type'], ocsf: ['auth_protocol'] },
  sessionId: { udm: ['session_id'], ocsf: ['session.uid'] },

  // --- Cloud ---
  cloudProvider: { udm: ['cloud_provider'], ocsf: ['cloud.provider'] },
  cloudRegion: { udm: ['cloud_region'], ocsf: ['cloud.region'] },
  cloudAccountId: { udm: ['cloud_account_id'], ocsf: ['cloud.account.uid'] },
  cloudService: { udm: ['cloud_service'], ocsf: ['api.service.name'] },

  // --- Event taxonomy / provenance ---
  /** The routing key. OCSF spells it `metadata.log_source` (→ `source_type`). */
  logSource: { udm: ['source_type'], ocsf: ['metadata.log_source'] },
  eventType: { udm: ['event_type'], ocsf: ['class_name', 'activity_name'] },
  vendorProduct: { udm: ['vendor_product'], ocsf: ['metadata.product.name'] },
  vendor: { udm: ['vendor'], ocsf: ['metadata.product.vendor_name'] },
  severity: { udm: ['severity'], ocsf: ['severity'] },
  status: { udm: ['status'], ocsf: ['status'] },
  message: { udm: ['message'], ocsf: ['message'] },
} as const satisfies Record<string, SemanticFieldDef>;

export type SemanticField = keyof typeof SEMANTIC_FIELDS;

/** Every column a concept may live in under `profile`, primary first. */
export function schemaFieldCandidates(profile: SchemaProfileId, key: SemanticField): readonly string[] {
  return SEMANTIC_FIELDS[key][profile];
}

/** The primary column for a concept under `profile` (display + single-column use). */
export function schemaField(profile: SchemaProfileId, key: SemanticField): string {
  return SEMANTIC_FIELDS[key][profile][0];
}

/**
 * Exact nPL filter matching `value` in a concept's column(s) (`nplExactEquals`:
 * wildcard metacharacters stay literal, quotes are preserved): `src_ip="1.2.3.4"`
 * under UDM, `src_endpoint.ip="1.2.3.4"` under OCSF, and an OR group when the
 * concept is class-dependent (`(actor.user.name="bob" OR user.name="bob")`).
 */
export function buildFieldFilter(profile: SchemaProfileId, key: SemanticField, value: string): string {
  const cols = schemaFieldCandidates(profile, key);
  if (cols.length === 1) return nplExactEquals(cols[0], value);
  return `(${cols.map((c) => nplExactEquals(c, value)).join(' OR ')})`;
}

/**
 * Every column of several concepts under `profile`, deduped, in order. `extra`
 * appends raw column names that are not a concept (a source-specific alias).
 */
export function conceptColumns(
  profile: SchemaProfileId,
  keys: readonly SemanticField[],
  extra: readonly string[] = [],
): string[] {
  const out: string[] = [];
  for (const key of keys) for (const col of schemaFieldCandidates(profile, key)) if (!out.includes(col)) out.push(col);
  for (const col of extra) if (!out.includes(col)) out.push(col);
  return out;
}

/**
 * One nPL filter matching `value` in ANY column of several concepts (an IP that
 * may be source or destination, a host on either side). Single column → bare
 * `col="v"`; more → a parenthesized OR group, safe to AND with other terms.
 */
export function buildMultiFieldFilter(
  profile: SchemaProfileId,
  keys: readonly SemanticField[],
  value: string,
  extra: readonly string[] = [],
): string {
  const cols = conceptColumns(profile, keys, extra);
  if (cols.length === 1) return nplExactEquals(cols[0], value);
  return `(${cols.map((c) => nplExactEquals(c, value)).join(' OR ')})`;
}

function isEmptyValue(v: unknown): boolean {
  return (
    v === null ||
    v === undefined ||
    v === '' ||
    // Sysmon / syslog emit "-" for an absent value.
    (typeof v === 'string' && v.trim() === '-')
  );
}

/**
 * The first non-empty column holding `key` in a flat result row, with the key
 * it was found under. The active profile's columns are tried first, then the
 * other profile's, so a row from a mixed source (a lookup, a UDM-era finding on
 * an OCSF tenant) still resolves.
 */
export function readSchemaFieldEntry(
  row: Record<string, unknown> | null | undefined,
  key: SemanticField,
  profile: SchemaProfileId = UNRESOLVED_SCHEMA_PROFILE,
): { key: string; value: unknown } | null {
  if (!row) return null;
  const other: SchemaProfileId = profile === 'udm' ? 'ocsf' : 'udm';
  for (const col of [...SEMANTIC_FIELDS[key][profile], ...SEMANTIC_FIELDS[key][other]]) {
    const v = row[col];
    if (!isEmptyValue(v)) return { key: col, value: v };
  }
  return null;
}

/** Value of `key` in a flat result row (see `readSchemaFieldEntry`), or undefined. */
export function readSchemaField(
  row: Record<string, unknown> | null | undefined,
  key: SemanticField,
  profile: SchemaProfileId = UNRESOLVED_SCHEMA_PROFILE,
): unknown {
  return readSchemaFieldEntry(row, key, profile)?.value;
}

/** String form of `readSchemaField` ('' when absent). */
export function readSchemaFieldString(
  row: Record<string, unknown> | null | undefined,
  key: SemanticField,
  profile: SchemaProfileId = UNRESOLVED_SCHEMA_PROFILE,
): string {
  const v = readSchemaField(row, key, profile);
  return v === undefined || v === null ? '' : String(v);
}

let reverseIndex: Map<string, SemanticField[]> | null = null;

/**
 * Concepts a column name denotes under either profile (`src_ip` and
 * `src_endpoint.ip` both → `srcIp`). Case-insensitive. A column shared by
 * several concepts (`actor.user.name` is `user` and `srcUser`) returns all,
 * in declaration order.
 */
export function semanticFieldsFor(column: string): readonly SemanticField[] {
  if (!reverseIndex) {
    reverseIndex = new Map();
    for (const key of Object.keys(SEMANTIC_FIELDS) as SemanticField[]) {
      for (const profile of ['udm', 'ocsf'] as const) {
        for (const col of SEMANTIC_FIELDS[key][profile]) {
          const list = reverseIndex.get(col.toLowerCase()) ?? [];
          if (!list.includes(key)) list.push(key);
          reverseIndex.set(col.toLowerCase(), list);
        }
      }
    }
  }
  return reverseIndex.get(column.toLowerCase()) ?? [];
}

/** True when `column` is one of `key`'s columns under either profile. */
export function isSchemaField(column: string, key: SemanticField): boolean {
  return semanticFieldsFor(column).includes(key);
}

/**
 * Translate a comma-separated `| table` column list written in UDM names into
 * the active profile's columns (primary column per concept). Names that are
 * not a known concept pass through unchanged; duplicates collapse.
 */
export function profileColumns(profile: SchemaProfileId, udmColumns: readonly string[]): string[] {
  const out: string[] = [];
  for (const raw of udmColumns) {
    const col = raw.trim();
    if (!col) continue;
    let mapped = col;
    if (profile !== 'udm') {
      const key = (Object.keys(SEMANTIC_FIELDS) as SemanticField[]).find(
        (k) => (SEMANTIC_FIELDS[k].udm as readonly string[])[0] === col,
      );
      if (key) mapped = schemaField(profile, key);
    }
    if (!out.includes(mapped)) out.push(mapped);
  }
  return out;
}

/**
 * The content channel (git branch) of the official parsers/rules repositories
 * for a profile: OCSF installs follow `main` (OCSF 1.9); UDM installs stay on
 * the frozen `legacy/clickhouse` branch, whose trees still carry UDM content.
 */
export function contentBranchFor(profile: SchemaProfileId): string {
  return profile === 'udm' ? 'legacy/clickhouse' : 'main';
}

/** Bound helpers for one profile — what `useSchemaFieldMap()` returns. */
export interface SchemaFieldMap {
  profile: SchemaProfileId;
  isOcsf: boolean;
  field: (key: SemanticField) => string;
  candidates: (key: SemanticField) => readonly string[];
  filter: (key: SemanticField, value: string) => string;
  filterAny: (keys: readonly SemanticField[], value: string, extra?: readonly string[]) => string;
  columnsOf: (keys: readonly SemanticField[], extra?: readonly string[]) => string[];
  read: (row: Record<string, unknown> | null | undefined, key: SemanticField) => unknown;
  readString: (row: Record<string, unknown> | null | undefined, key: SemanticField) => string;
  readEntry: (
    row: Record<string, unknown> | null | undefined,
    key: SemanticField,
  ) => { key: string; value: unknown } | null;
  columns: (udmColumns: readonly string[]) => string[];
}

export function schemaFieldMap(profile: SchemaProfileId): SchemaFieldMap {
  return {
    profile,
    isOcsf: profile === 'ocsf',
    field: (key) => schemaField(profile, key),
    candidates: (key) => schemaFieldCandidates(profile, key),
    filter: (key, value) => buildFieldFilter(profile, key, value),
    filterAny: (keys, value, extra) => buildMultiFieldFilter(profile, keys, value, extra),
    columnsOf: (keys, extra) => conceptColumns(profile, keys, extra),
    read: (row, key) => readSchemaField(row, key, profile),
    readString: (row, key) => readSchemaFieldString(row, key, profile),
    readEntry: (row, key) => readSchemaFieldEntry(row, key, profile),
    columns: (udmColumns) => profileColumns(profile, udmColumns),
  };
}

// ---------------------------------------------------------------------------
// Event-class concept drilldowns (NAN-5271 E)
// ---------------------------------------------------------------------------

/** An asset-view drilldown that selects a KIND of event rather than a value. */
export type AssetEventConcept =
  | 'authLane'
  | 'authAll'
  | 'authSuccess'
  | 'authFailure'
  | 'interactiveLogon'
  | 'networkLogon'
  | 'fileEvents'
  | 'fileLane';

/**
 * OCSF `| where` bodies for each concept. These MUST stay the nPL spelling of
 * the predicates in `nanosiem-core/src/schema/ocsf_predicates.rs` (the asset
 * dossier counts and timeline lanes the drilldown opens are computed from
 * those); `ocsf_concept_predicate_tests.rs` compiles these exact strings.
 * UDM answers with string values, OCSF with enum ints — `category` is the
 * content (URL) category and `activity` holds HTTP methods / Logon, so neither
 * can say "auth event" or "file event" under OCSF.
 */
export const OCSF_ASSET_CONCEPT_WHERE: Record<AssetEventConcept, string> = {
  authLane: 'category_uid=3',
  authAll: 'class_uid=3002',
  authSuccess: 'class_uid=3002 AND activity_id!=2 AND status_id=1',
  authFailure: 'class_uid=3002 AND activity_id!=2 AND status_id=2',
  interactiveLogon: 'class_uid=3002 AND activity_id=1 AND logon_type_id IN (2, 10, 11, 12)',
  networkLogon: 'class_uid=3002 AND activity_id=1 AND logon_type_id IN (3, 8)',
  fileEvents: 'class_uid=1001',
  fileLane: 'class_uid IN (1001, 201001, 201002)',
};

/** The legacy UDM drilldowns, unchanged. */
const UDM_ASSET_CONCEPT_DRILL: Record<AssetEventConcept, Record<string, unknown>> = {
  authLane: { _tableCommand: '| where category="authentication" OR category="authorization"' },
  authAll: { category: 'authentication' },
  authSuccess: { category: 'authentication', auth_result: 'success' },
  authFailure: { category: 'authentication', auth_result: 'failure' },
  interactiveLogon: {
    _tableCommand: '| where category="authentication" AND lower(auth_type) LIKE "%interactive%"',
  },
  networkLogon: {
    _tableCommand:
      '| where category="authentication" AND (lower(auth_type) LIKE "%network%" OR lower(auth_type) LIKE "%lateral%")',
  },
  fileEvents: { _tableCommand: '| where file_action!=""' },
  fileLane: { _tableCommand: '| where file_action!=""' },
};

/** Drilldown filters (field=value pairs and/or `_tableCommand`) for a concept. */
export function assetConceptDrill(profile: SchemaProfileId, concept: AssetEventConcept): Record<string, unknown> {
  return profile === 'ocsf'
    ? { _tableCommand: `| where ${OCSF_ASSET_CONCEPT_WHERE[concept]}` }
    : { ...UDM_ASSET_CONCEPT_DRILL[concept] };
}
