#!/usr/bin/env node
/**
 * Generate all UDM field artifacts from the CSV source of truth.
 *
 * Outputs:
 *   1. nanosiem-web/src/lib/udm-fields.ts   (frontend Set)
 *   2. docs/udm_fields_parsed.json           (full metadata JSON)
 *   3. nanosiem-enterprise/src/melod/sigma_converter/data/udm-fields.json  (sigma converter, enterprise crate; skipped if absent)
 *   4. <docs-site>/public/udm-fields.json    (docs site, if present)
 *
 * Usage:  node scripts/generate-udm-fields.mjs
 * Called automatically by:  npm run generate:udm
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');
const CSV_PATH = resolve(ROOT, 'nanosiem-core/docs/udmfields.csv');

// Output paths
const TS_OUTPUT = resolve(__dirname, '../src/lib/udm-fields.ts');
const JSON_OUTPUTS = [
  resolve(ROOT, 'docs/udm_fields_parsed.json'),
  resolve(ROOT, 'nanosiem-enterprise/src/melod/sigma_converter/data/udm-fields.json'),
];
// Optional: docs-site in sibling directory
const DOCS_SITE_JSON = resolve(ROOT, '../nano-main/docs-site/public/udm-fields.json');
if (existsSync(resolve(ROOT, '../nano-main/docs-site/public'))) {
  JSON_OUTPUTS.push(DOCS_SITE_JSON);
}

// Additional fields not in the CSV but used in the frontend
const EXTRA_TS_FIELDS = [
  '_time', '_inserted_at',
  'first_seen', 'last_seen', 'count', 'raw_risk_score',
  'domain_prevalence', 'domain_first_seen', 'domain_last_seen',
];

// ---------------------------------------------------------------------------
// Type inference (mirrors nanosiem-core/src/udm/csv_parser.rs)
// ---------------------------------------------------------------------------
function inferType(fieldName) {
  const n = fieldName.toLowerCase();
  if (n.endsWith('_tags')) return 'Array';
  if (n.includes('_ip') || n === 'ip' || n.endsWith('_ips')) return 'IpAddress';
  if (n.includes('_time') || n.includes('timestamp') || n.endsWith('_date') || n === 'time') return 'Timestamp';
  if (n.startsWith('is_') || n.startsWith('has_') || n.startsWith('should_') || n.startsWith('requires_')
      || n.endsWith('_enabled') || n.endsWith('_supported') || n === 'ioc_matched') return 'Boolean';
  if (n.endsWith('_count') || n.endsWith('_id') || n.endsWith('_port') || n.endsWith('_code')
      || n.endsWith('_pid') || n === 'count' || n.endsWith('_confidence')
      || n.startsWith('prevalence_')) return 'Integer';
  if (n.includes('bytes') || n.endsWith('_size') || n.includes('memory')) return 'Long';
  if (n.endsWith('_percent') || n.endsWith('_ratio') || n.endsWith('_score') || n.includes('_load')) return 'Float';
  return 'String';
}

// ---------------------------------------------------------------------------
// Category inference (mirrors nanosiem-core/src/udm/csv_parser.rs)
// ---------------------------------------------------------------------------
function inferCategory(dataModels) {
  for (const model of dataModels) {
    const m = model.toLowerCase();
    if (m.includes('authentication')) return 'Authentication';
    if (m.includes('network traffic') || m.includes('network sessions')) return 'Network';
    if (m.includes('endpoint')) return 'Endpoint';
    if (m.includes('email')) return 'Email';
    if (m.includes('web')) return 'Web';
    if (m.includes('database')) return 'Database';
    if (m.includes('malware')) return 'Malware';
    if (m.includes('intrusion')) return 'Intrusion';
    if (m.includes('vulnerabilities')) return 'Vulnerability';
    if (m.includes('certificates')) return 'Certificate';
    if (m.includes('dns') || m.includes('network resolution')) return 'Dns';
    if (m.includes('performance')) return 'Performance';
    if (m.includes('inventory')) return 'Inventory';
    if (m.includes('change')) return 'Change';
    if (m.includes('data access')) return 'DataAccess';
    if (m.includes('data loss prevention')) return 'DataLossPrevention';
    if (m.includes('alerts')) return 'Alerts';
    if (m.includes('updates')) return 'Updates';
    if (m.includes('event signatures')) return 'EventSignatures';
    if (m.includes('interprocess messaging')) return 'InterprocessMessaging';
    if (m.includes('system')) return 'System';
    if (m.includes('enrichment') && !m.includes('custom')) return 'Enrichment';
    if (m.includes('threat intelligence')) return 'ThreatIntelligence';
    if (m.includes('custom enrichment')) return 'CustomEnrichment';
    if (m.includes('prevalence')) return 'Prevalence';
    if (m.includes('risk')) return 'Risk';
    if (m.includes('detection')) return 'Detection';
  }
  return 'Entity';
}

function toPascalCase(s) {
  return s.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
}

// ---------------------------------------------------------------------------
// Parse CSV
// ---------------------------------------------------------------------------
if (!existsSync(CSV_PATH)) {
  // In Docker/CI builds, only nanosiem-web is available — the CSV lives
  // outside this package.  The generated udm-fields.ts is committed, so
  // we can safely skip regeneration.
  console.log(`  SKIP  CSV not found at ${CSV_PATH} (using committed udm-fields.ts)`);
  process.exit(0);
}
const csv = readFileSync(CSV_PATH, 'utf-8');
const seen = new Set();
const fields = [];

for (const line of csv.split('\n').slice(1)) {
  if (!line.trim()) continue;
  const firstComma = line.indexOf(',');
  const fieldName = (firstComma === -1 ? line : line.slice(0, firstComma)).trim();
  if (!fieldName || seen.has(fieldName)) continue;
  seen.add(fieldName);

  const dataModelsRaw = firstComma === -1 ? '' : line.slice(firstComma + 1).trim();
  const dataModels = dataModelsRaw ? dataModelsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

  fields.push({
    field_name: fieldName,
    snake_case_name: fieldName.toLowerCase().replace(/-/g, '_'),
    pascal_case_name: toPascalCase(fieldName),
    data_models: dataModels,
    inferred_type: inferType(fieldName),
    category: inferCategory(dataModels),
  });
}

const sortedNames = fields.map(f => f.field_name).sort();

// ---------------------------------------------------------------------------
// 1. Generate TypeScript
// ---------------------------------------------------------------------------
function formatFieldLines(fieldList, indent = '  ') {
  const lines = [];
  let current = indent;
  for (const field of fieldList) {
    const entry = `'${field}', `;
    if (current.length + entry.length > 95 && current.trim().length > 0) {
      lines.push(current.trimEnd().replace(/, $/, ','));
      current = indent + entry;
    } else {
      current += entry;
    }
  }
  if (current.trim().length > 0) {
    lines.push(current.trimEnd().replace(/, $/, ','));
  }
  return lines.join('\n');
}

const tsOutput = `// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * UDM (Unified Data Model) field definitions
 *
 * AUTO-GENERATED — do not edit manually.
 * Source: nanosiem-core/docs/udmfields.csv (${fields.length} fields)
 * Regenerate: npm run generate:udm
 */

export const UDM_COLUMNS = new Set([
  // === UDM Fields (from udmfields.csv) ===
${formatFieldLines(sortedNames)}

  // === Additional system/computed fields ===
${formatFieldLines(EXTRA_TS_FIELDS)}
]);

/**
 * Check if a field name is a UDM column (stored as explicit column in ClickHouse)
 */
export function isUdmColumn(fieldName: string): boolean {
  return UDM_COLUMNS.has(fieldName);
}

/** Canonical UDM field names, sorted alphabetically. */
export const UDM_FIELD_LIST: readonly string[] = Object.freeze(
  Array.from(UDM_COLUMNS).sort((a, b) => a.localeCompare(b)),
);

/**
 * Return UDM field names whose start matches \`prefix\` (case-insensitive).
 * Empty \`prefix\` returns the full sorted list. Result is capped at \`limit\`.
 */
export function filterUdmFields(prefix: string, limit = 12): string[] {
  const needle = prefix.toLowerCase();
  if (!needle) return UDM_FIELD_LIST.slice(0, limit);
  const out: string[] = [];
  for (const name of UDM_FIELD_LIST) {
    if (name.toLowerCase().startsWith(needle)) {
      out.push(name);
      if (out.length >= limit) break;
    }
  }
  return out;
}

/**
 * Prefix-filter the union of UDM field names and the active schema's field names
 * (NAN-1241). Under UDM (\`extraFields\` empty/undefined) this is byte-identical to
 * \`filterUdmFields\`; under OCSF the promoted columns (\`src_endpoint.ip\`, …) are
 * offered too. The union is sorted, de-duplicated, and matched both on the full
 * name and on the dotted leaf so a partial leaf still suggests dotted columns.
 */
export function filterFieldsWithSchema(
  prefix: string,
  extraFields: readonly string[] | undefined,
  limit = 12,
): string[] {
  if (!extraFields || extraFields.length === 0) {
    return filterUdmFields(prefix, limit);
  }
  const seen = new Set(UDM_FIELD_LIST);
  const merged = [...UDM_FIELD_LIST];
  for (const f of extraFields) {
    if (!seen.has(f)) {
      seen.add(f);
      merged.push(f);
    }
  }
  merged.sort((a, b) => a.localeCompare(b));

  const needle = prefix.toLowerCase();
  if (!needle) return merged.slice(0, limit);
  const out: string[] = [];
  for (const name of merged) {
    const lower = name.toLowerCase();
    const dot = lower.lastIndexOf('.');
    const leaf = dot >= 0 ? lower.slice(dot + 1) : '';
    if (lower.startsWith(needle) || (leaf && leaf.startsWith(needle))) {
      out.push(name);
      if (out.length >= limit) break;
    }
  }
  return out;
}
`;

writeFileSync(TS_OUTPUT, tsOutput);
console.log(`  TS  ${TS_OUTPUT} (${fields.length} + ${EXTRA_TS_FIELDS.length} extra)`);

// ---------------------------------------------------------------------------
// 2. Generate JSON (matches Rust generate_udm_json output format)
// ---------------------------------------------------------------------------
const fieldsByCategory = {};
const fieldsByType = {};
for (const f of fields) {
  (fieldsByCategory[f.category] ??= []).push(f.field_name);
  (fieldsByType[f.inferred_type] ??= []).push(f.field_name);
}

const jsonOutput = {
  total_fields: fields.length,
  fields,
  fields_by_category: fieldsByCategory,
  fields_by_type: fieldsByType,
};

const jsonStr = JSON.stringify(jsonOutput, null, 2) + '\n';

for (const dest of JSON_OUTPUTS) {
  // Skip when the parent dir is absent — the open-core repo split (NAN-744)
  // means nanosiem-enterprise/ may not be present in every checkout.
  if (!existsSync(dirname(dest))) {
    console.log(`  SKIP  ${dest} (parent dir missing)`);
    continue;
  }
  writeFileSync(dest, jsonStr);
  console.log(`  JSON ${dest}`);
}

console.log(`\nDone — ${fields.length} fields from CSV.`);
