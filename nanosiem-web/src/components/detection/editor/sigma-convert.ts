// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sigma → nano rule conversion (pure; rendered by `SigmaConverter`).
 *
 * Field targets are profile-aware (NAN-4903): every Sigma field maps to a UDM
 * column AND an explicit OCSF column (`SIGMA_OCSF_TARGETS`). A field whose UDM
 * target has no OCSF equivalent makes an OCSF conversion UNSUCCESSFUL — a UDM
 * name passed through would resolve to an absent column and the detection
 * would silently never fire.
 *
 * Serialization is split by grammar: YAML frontmatter uses `yamlEscape` (where
 * backslash IS an escape); every nPL predicate and keyword uses `nplLiteral`
 * (the canonical quote-preserving nPL literal — nPL has no backslash escape);
 * `|re` patterns go through the same literal as an `=~ "…"` operand.
 */

import YAML from 'yaml';
import { nplLiteral } from '@/lib/npl-quote';
import { schemaField, type SchemaProfileId } from '@/lib/schema-fields';

export interface SigmaRule {
  title?: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  date?: string;
  modified?: string;
  references?: string[];
  tags?: string[];
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
  };
  detection?: Record<string, unknown>;
  falsepositives?: string[];
  level?: string;
  fields?: string[];
}

export interface ConversionResult {
  success: boolean;
  output: string;
  warnings: string[];
  errors: string[];
}

// Sigma field → UDM column. Each UDM target also has an explicit OCSF column in
// `SIGMA_OCSF_TARGETS` (a test pins that the two tables stay total).
export const SIGMA_FIELD_MAPPINGS: Record<string, string> = {
  // Process fields
  'Image': 'process_path',
  'NewProcessName': 'process_path',
  'ParentProcessName': 'parent_process_path',
  'OriginalFileName': 'process_name',
  'CommandLine': 'command_line',
  'ParentImage': 'parent_process_path',
  'ParentCommandLine': 'parent_command_line',
  'User': 'user',
  'ProcessId': 'process_id',
  'ParentProcessId': 'parent_process_id',
  'IntegrityLevel': 'integrity_level',
  'Hashes': 'process_hash',
  'md5': 'file_hash_md5',
  'sha1': 'file_hash_sha1',
  'sha256': 'file_hash_sha256',
  'imphash': 'file_hash_imphash',

  // Network fields
  'DestinationIp': 'dest_ip',
  'DestinationPort': 'dest_port',
  'DestinationHostname': 'dest_host',
  'SourceIp': 'src_ip',
  'SourcePort': 'src_port',
  'SourceHostname': 'src_host',
  'Protocol': 'protocol',

  // File fields
  'TargetFilename': 'file_path',
  'FileName': 'file_name',
  'FilePath': 'file_path',

  // Registry fields
  'TargetObject': 'registry_path',
  'Details': 'registry_value_data',
  'EventType': 'registry_action',

  // Authentication
  'LogonType': 'logon_type',
  'TargetUserName': 'dest_user',
  'TargetDomainName': 'dest_domain',
  'SubjectUserName': 'src_user',
  'SubjectDomainName': 'src_domain',
  'IpAddress': 'src_ip',
  'WorkstationName': 'src_host',
  'Status': 'status',

  // DNS
  'QueryName': 'dns_query',
  'QueryResults': 'dns_answers',
  'query': 'dns_query',

  // Web/Proxy
  'cs-uri-query': 'url',
  'c-uri': 'url',
  'cs-method': 'http_method',
  'cs-host': 'dest_host',
  'cs-User-Agent': 'http_user_agent',

  // Generic
  'EventID': 'event_id',
  'Channel': 'log_source',
  'Provider_Name': 'provider',
  'Computer': 'host',
  'ComputerName': 'host',
};

/**
 * UDM target → OCSF 1.9 column for every `SIGMA_FIELD_MAPPINGS` value. `null`
 * means OCSF has no faithful equivalent; using such a field fails an OCSF
 * conversion instead of emitting a column that does not exist.
 */
export const SIGMA_OCSF_TARGETS: Record<string, string | null> = {
  process_path: 'process.file.path',
  process_name: 'process.name',
  command_line: 'process.cmd_line',
  parent_process_path: 'actor.process.file.path',
  parent_command_line: 'actor.process.cmd_line',
  user: 'actor.user.name',
  process_id: 'process.pid',
  parent_process_id: 'actor.process.pid',
  integrity_level: 'process.integrity',
  // Fingerprints: the promoted column holds every algorithm's value (they
  // differ in length, so a value match is algorithm-exact). Sysmon-style
  // `ALGO=value` is reduced to the value (see `ocsfHashValue`).
  process_hash: 'process.file.hashes.value',
  file_hash_md5: 'file.hashes.value',
  file_hash_sha1: 'file.hashes.value',
  file_hash_sha256: 'file.hashes.value',
  // OCSF fingerprints carry no imphash algorithm.
  file_hash_imphash: null,
  dest_ip: 'dst_endpoint.ip',
  dest_port: 'dst_endpoint.port',
  dest_host: 'dst_endpoint.hostname',
  src_ip: 'src_endpoint.ip',
  src_port: 'src_endpoint.port',
  src_host: 'src_endpoint.hostname',
  protocol: 'connection_info.protocol_name',
  file_path: 'file.path',
  file_name: 'file.name',
  registry_path: 'reg_key.path',
  registry_value_data: 'reg_value.data',
  // Sigma EventType values (SetValue, CreateKey, …) have no 1:1 OCSF activity.
  registry_action: null,
  // Windows logon type numbers equal OCSF logon_type_id values (2, 3, 10, …).
  logon_type: 'logon_type_id',
  dest_user: 'user.name',
  dest_domain: 'user.domain',
  src_user: 'actor.user.name',
  src_domain: 'actor.user.domain',
  // Windows NTSTATUS codes (0xC000006D) land in the source status code, not the
  // normalized Success/Failure `status`.
  status: 'status_code',
  dns_query: 'query.hostname',
  dns_answers: 'answers.rdata',
  url: 'http_request.url.url_string',
  http_method: 'http_request.http_method',
  http_user_agent: 'http_request.user_agent',
  event_id: 'metadata.event_code',
  // Sigma `Channel` ("Security", "Microsoft-Windows-Sysmon/Operational") is the
  // Windows log name. It is NOT the nano routing key (`metadata.log_source`).
  log_source: 'metadata.log_name',
  provider: 'metadata.log_provider',
  host: 'device.hostname',
};

const HASH_TARGETS = new Set(['process_hash', 'file_hash_md5', 'file_hash_sha1', 'file_hash_sha256']);

/** Sysmon `Hashes` values look like `SHA256=ABC…`; OCSF stores only the value. */
function ocsfHashValue(value: string): string {
  const m = /^(?:md5|sha1|sha256|imphash)=(.+)$/i.exec(value);
  return m ? m[1] : value;
}

// Logsource to source_type mappings
const LOGSOURCE_MAPPINGS: Record<string, string> = {
  // Windows
  'windows_security': 'windows_security',
  'windows_system': 'windows_system',
  'windows_application': 'windows_application',
  'windows_sysmon': 'sysmon',
  'windows_powershell': 'powershell',
  'windows_powershell_classic': 'powershell',
  'windows_defender': 'defender',
  'windows_firewall': 'windows_firewall',
  'windows_dns': 'windows_dns',

  // Linux
  'linux_auth': 'linux_auth',
  'linux_syslog': 'syslog',
  'linux_audit': 'auditd',

  // Network
  'firewall': 'firewall',
  'proxy': 'proxy',
  'dns': 'dns',
  'webserver': 'webserver',

  // Cloud
  'aws_cloudtrail': 'cloudtrail',
  'azure_activitylogs': 'azure_activity',
  'gcp_audit': 'gcp_audit',
  'okta': 'okta',
  'm365': 'o365',

  // Endpoint
  'process_creation': 'process',
  'file_event': 'file',
  'network_connection': 'network',
  'registry_event': 'registry',
  'dns_query': 'dns',
  'image_load': 'image_load',
  'pipe_created': 'pipe',
};

function toSnakeCase(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
}

/** Per-conversion bookkeeping threaded through the selection converters. */
interface ConvertContext {
  profile: SchemaProfileId;
  warnings: string[];
  unmappedFields: Set<string>;
  /** Sigma fields whose UDM target has no OCSF column (fails an OCSF conversion). */
  unsupportedFields: Set<string>;
  /** Values nPL cannot represent exactly (both quote kinds). */
  lossyValues: Set<string>;
}

/** The active profile's column for a Sigma field, plus its UDM target. */
function mapField(field: string, ctx: ConvertContext): { column: string; udm: string | null } {
  const udm = SIGMA_FIELD_MAPPINGS[field];
  if (udm) {
    if (ctx.profile === 'udm') return { column: udm, udm };
    const ocsf = SIGMA_OCSF_TARGETS[udm];
    if (ocsf) return { column: ocsf, udm };
    ctx.unsupportedFields.add(`${field} (${udm})`);
    return { column: udm, udm };
  }
  // Field not in our mapping - track it and convert to snake_case
  const converted = field.toLowerCase().replace(/[^a-z0-9_]/gi, '_');
  ctx.unmappedFields.add(`${field} → ${converted}`);
  return { column: converted, udm: null };
}

/** nPL literal for a predicate value; records a lossy (both-quote) value. */
function lit(value: string, ctx: ConvertContext): string {
  const { literal, lossy } = nplLiteral(value);
  if (lossy) ctx.lossyValues.add(value);
  return literal;
}

/**
 * Escape a value for a YAML double-quoted scalar (frontmatter ONLY — never an
 * nPL literal; nPL has no backslash escape, see `@/lib/npl-quote`).
 *
 * Unlike nPL (see `@/lib/npl-quote`), YAML double-quoted scalars DO treat
 * backslash as an escape character, so `\\` and `\"` are both correct here.
 * Order matters: backslashes first, or the backslash introduced by `\"` gets
 * doubled into a literal backslash followed by a bare quote.
 */
function yamlEscape(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function parseModifiers(fieldName: string): { baseName: string; modifiers: string[] } {
  const parts = fieldName.split('|');
  return {
    baseName: parts[0],
    modifiers: parts.slice(1),
  };
}

function convertValueWithModifiers(
  field: string,
  value: string | number | boolean,
  modifiers: string[],
  ctx: ConvertContext,
): string {
  const { column: mappedField, udm } = mapField(field, ctx);
  let strValue = String(value);
  if (ctx.profile === 'ocsf' && udm && HASH_TARGETS.has(udm)) strValue = ocsfHashValue(strValue);

  // Handle wildcards in value
  const hasStartWildcard = strValue.startsWith('*');
  const hasEndWildcard = strValue.endsWith('*') && !strValue.endsWith('\\*');

  // Remove wildcards for processing
  if (hasStartWildcard) strValue = strValue.slice(1);
  if (hasEndWildcard) strValue = strValue.slice(0, -1);

  // Check modifiers
  const hasContains = modifiers.includes('contains') || (hasStartWildcard && hasEndWildcard);
  const hasStartswith = modifiers.includes('startswith') || (!hasStartWildcard && hasEndWildcard);
  const hasEndswith = modifiers.includes('endswith') || (hasStartWildcard && !hasEndWildcard);
  const hasRe = modifiers.includes('re');
  const hasCidr = modifiers.includes('cidr');
  const hasCased = modifiers.includes('cased');
  const hasBase64 = modifiers.includes('base64') || modifiers.includes('base64offset');

  if (hasBase64) {
    ctx.warnings.push(`base64 modifier on "${field}" - may need manual adjustment`);
  }

  if (hasRe) {
    // `field =~ "pattern"`: the pattern rides in an nPL string literal (no
    // slash escaping needed; backslashes doubled so `\\` survives the parse).
    // Sigma `|re` without `|cased` was historically case-insensitive here.
    return `${mappedField} =~ ${lit(hasCased ? strValue : `(?i)${strValue}`, ctx)}`;
  }

  if (hasCidr) {
    // cidrmatch(cidr, ip) — network first.
    return `cidrmatch(${lit(strValue, ctx)}, ${mappedField})`;
  }

  if (hasContains) {
    return `${mappedField} CONTAINS ${lit(strValue, ctx)}`;
  }

  if (hasStartswith) {
    return `${mappedField} STARTSWITH ${lit(strValue, ctx)}`;
  }

  if (hasEndswith) {
    return `${mappedField} ENDSWITH ${lit(strValue, ctx)}`;
  }

  // Handle remaining wildcards in value
  if (strValue.includes('*') || strValue.includes('?')) {
    // Convert to LIKE pattern
    const likePattern = strValue.replace(/\*/g, '%').replace(/\?/g, '_');
    return `${mappedField} LIKE ${lit(likePattern, ctx)}`;
  }

  // Simple equality
  if (typeof value === 'number') {
    return `${mappedField}=${value}`;
  }

  return `${mappedField}=${lit(strValue, ctx)}`;
}

function convertSelection(
  name: string,
  selection: unknown,
  ctx: ConvertContext,
): { condition: string; isKeyword: boolean } {
  const warnings = ctx.warnings;
  if (typeof selection === 'string') {
    // Keyword search
    return { condition: lit(selection, ctx), isKeyword: true };
  }

  if (Array.isArray(selection)) {
    // Array of keywords
    const keywords = selection.map(k => lit(String(k), ctx));
    return { condition: `(${keywords.join(' OR ')})`, isKeyword: true };
  }

  if (typeof selection !== 'object' || selection === null) {
    warnings.push(`Unknown selection format for "${name}"`);
    return { condition: '*', isKeyword: false };
  }

  // Object with field conditions
  const conditions: string[] = [];

  for (const [rawField, rawValue] of Object.entries(selection)) {
    const { baseName, modifiers } = parseModifiers(rawField);
    const hasAll = modifiers.includes('all');

    if (Array.isArray(rawValue)) {
      // Multiple values
      const valueConditions = rawValue.map(v =>
        convertValueWithModifiers(baseName, v, modifiers, ctx)
      );

      if (hasAll) {
        // AND all values together
        conditions.push(`(${valueConditions.join(' AND ')})`);
      } else {
        // OR values together
        if (valueConditions.length === 1) {
          conditions.push(valueConditions[0]);
        } else {
          conditions.push(`(${valueConditions.join(' OR ')})`);
        }
      }
    } else if (rawValue !== null && rawValue !== undefined) {
      conditions.push(convertValueWithModifiers(baseName, rawValue as string | number | boolean, modifiers, ctx));
    }
  }

  if (conditions.length === 0) {
    return { condition: '*', isKeyword: false };
  }

  if (conditions.length === 1) {
    return { condition: conditions[0], isKeyword: false };
  }

  // AND all field conditions together (standard Sigma behavior)
  return { condition: `(${conditions.join(' AND ')})`, isKeyword: false };
}

function parseCondition(
  condition: string,
  selections: Map<string, { condition: string; isKeyword: boolean }>,
  warnings: string[]
): string {
  let result = condition;

  const selectionNames = Array.from(selections.keys()).sort((a, b) => b.length - a.length);

  // IMPORTANT: Handle special patterns FIRST, before replacing individual selection names

  // Handle "1 of them" pattern
  result = result.replace(/\b1 of them\b/gi, () => {
    const conditions = Array.from(selections.values()).map(s => s.condition);
    return `(${conditions.join(' OR ')})`;
  });

  // Handle "all of them" pattern
  result = result.replace(/\ball of them\b/gi, () => {
    const conditions = Array.from(selections.values()).map(s => s.condition);
    return `(${conditions.join(' AND ')})`;
  });

  // Handle "1 of selection*" pattern (matches any selection starting with prefix)
  result = result.replace(/\b1 of (\w+)\*\b/gi, (_, prefix) => {
    const matchingSelections = selectionNames.filter(n => n.startsWith(prefix));
    if (matchingSelections.length === 0) {
      warnings.push(`No selections match pattern "${prefix}*"`);
      return 'false';
    }
    const conditions = matchingSelections.map(n => selections.get(n)?.condition || '*');
    return `(${conditions.join(' OR ')})`;
  });

  // Handle "all of selection*" pattern
  result = result.replace(/\ball of (\w+)\*\b/gi, (_, prefix) => {
    const matchingSelections = selectionNames.filter(n => n.startsWith(prefix));
    if (matchingSelections.length === 0) {
      warnings.push(`No selections match pattern "${prefix}*"`);
      return 'true';
    }
    const conditions = matchingSelections.map(n => selections.get(n)?.condition || '*');
    return `(${conditions.join(' AND ')})`;
  });

  // NOW replace remaining individual selection names with their conditions
  for (const name of selectionNames) {
    const sel = selections.get(name);
    if (sel) {
      const regex = new RegExp(`\\b${name}\\b`, 'g');
      result = result.replace(regex, sel.condition);
    }
  }

  // Convert logical operators
  result = result.replace(/\band\b/gi, 'AND');
  result = result.replace(/\bor\b/gi, 'OR');
  result = result.replace(/\bnot\b/gi, 'NOT');

  return result;
}

export function convertSigmaRule(sigmaYaml: string, profile: SchemaProfileId, currentUser?: string): ConversionResult {
  const warnings: string[] = [];
  const errors: string[] = [];

  let rule: SigmaRule;

  try {
    rule = YAML.parse(sigmaYaml) as SigmaRule;
  } catch (e) {
    return {
      success: false,
      output: '',
      warnings: [],
      errors: [`Failed to parse YAML: ${(e as Error).message}`],
    };
  }

  if (!rule.detection) {
    return {
      success: false,
      output: '',
      warnings: [],
      errors: ['No detection section found in Sigma rule'],
    };
  }

  // Build the frontmatter
  const frontmatter: Record<string, unknown> = {};

  // Title (convert to snake_case)
  frontmatter.title = rule.title ? toSnakeCase(rule.title) : 'sigma_converted_rule';

  // Description (quoted)
  if (rule.description) {
    frontmatter.description = `"${yamlEscape(rule.description)}"`;
  }

  // Author - use current user, store original for comment
  const originalAuthor = rule.author;
  if (currentUser) {
    frontmatter.author = currentUser;
  }

  // Severity (map Sigma level)
  const levelMap: Record<string, string> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'low',
  };
  frontmatter.severity = levelMap[rule.level || 'medium'] || 'medium';

  // Mode defaults
  frontmatter.mode = 'staging';
  frontmatter.detection_mode = 'scheduled';
  frontmatter.schedule = '*/30 * * * * *';
  frontmatter.lookback = '15m';

  // Extract MITRE tags
  const mitreTactics: string[] = [];
  const mitreTechniques: string[] = [];
  const otherTags: string[] = [];

  if (rule.tags) {
    for (const tag of rule.tags) {
      if (tag.startsWith('attack.t')) {
        // Technique (e.g., attack.t1059.001 -> T1059.001)
        mitreTechniques.push(tag.replace('attack.', '').toUpperCase());
      } else if (tag.match(/^attack\.[\w-]+$/) && !tag.match(/^attack\.t\d/i)) {
        // Tactic name (e.g., attack.execution, attack.defense-evasion)
        // Map common tactic names to IDs
        const tacticMap: Record<string, string> = {
          'reconnaissance': 'TA0043',
          'resource_development': 'TA0042',
          'initial_access': 'TA0001',
          'execution': 'TA0002',
          'persistence': 'TA0003',
          'privilege_escalation': 'TA0004',
          'defense_evasion': 'TA0005',
          'credential_access': 'TA0006',
          'discovery': 'TA0007',
          'lateral_movement': 'TA0008',
          'collection': 'TA0009',
          'command_and_control': 'TA0011',
          'exfiltration': 'TA0010',
          'impact': 'TA0040',
        };
        const tacticName = tag.replace('attack.', '').replace(/-/g, '_');
        if (tacticMap[tacticName]) {
          mitreTactics.push(tacticMap[tacticName]);
        }
      } else if (!tag.startsWith('attack.') && !tag.startsWith('cve.') && !tag.startsWith('tlp.')) {
        otherTags.push(tag);
      }
    }
  }

  if (mitreTactics.length > 0) {
    frontmatter.mitre_tactics = `"${mitreTactics.join(', ')}"`;
  }
  if (mitreTechniques.length > 0) {
    frontmatter.mitre_techniques = `"${mitreTechniques.join(', ')}"`;
  }
  if (otherTags.length > 0) {
    frontmatter.tags = otherTags.join(', ');
  }

  // Build the query
  const queryParts: string[] = [];
  const logSourceField = schemaField(profile, 'logSource');

  // Determine source_type from logsource
  if (rule.logsource) {
    const { category, product, service } = rule.logsource;
    let sourceType = '';

    // Try to find a mapping
    if (category) {
      sourceType = LOGSOURCE_MAPPINGS[category] || '';
    }
    if (!sourceType && product && service) {
      sourceType = LOGSOURCE_MAPPINGS[`${product}_${service}`] || '';
    }
    if (!sourceType && product) {
      sourceType = LOGSOURCE_MAPPINGS[product] || '';
    }

    if (sourceType) {
      queryParts.push(`${logSourceField}=${nplLiteral(sourceType).literal}`);
    } else {
      // Generate a source_type from logsource components
      const parts = [product, service, category].filter(Boolean);
      if (parts.length > 0) {
        const generatedType = parts.join('_').toLowerCase().replace(/[^a-z0-9_]/g, '_');
        queryParts.push(`${logSourceField}=${nplLiteral(generatedType).literal}`);
        warnings.push(`Generated source_type "${generatedType}" from logsource - verify this matches your data`);
      }
    }
  }

  // Process detection section
  const detection = rule.detection;
  const condition = detection.condition as string | undefined;

  if (!condition) {
    errors.push('No condition found in detection section');
    return { success: false, output: '', warnings, errors };
  }

  // Build selection map - track unmapped fields
  const selections = new Map<string, { condition: string; isKeyword: boolean }>();
  const ctx: ConvertContext = {
    profile,
    warnings,
    unmappedFields: new Set<string>(),
    unsupportedFields: new Set<string>(),
    lossyValues: new Set<string>(),
  };

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition' || key === 'timeframe') continue;

    const converted = convertSelection(key, value, ctx);
    selections.set(key, converted);
  }

  // Warn about unmapped fields that need manual review
  if (ctx.unmappedFields.size > 0) {
    const schemaName = profile === 'ocsf' ? 'OCSF schema' : 'UDM';
    warnings.push(`Unmapped fields (verify these match your ${schemaName}): ${Array.from(ctx.unmappedFields).join(', ')}`);
  }
  // NAN-4903: a mapped field with no OCSF column must not pass through as a UDM
  // name (it would read an absent column and the rule would never fire).
  if (ctx.unsupportedFields.size > 0) {
    errors.push(
      `No OCSF equivalent for: ${Array.from(ctx.unsupportedFields).join(', ')}. ` +
        'Rewrite these conditions by hand before using this rule.',
    );
  }
  if (ctx.lossyValues.size > 0) {
    errors.push(
      `nPL cannot express these values exactly (they contain both ' and "): ${Array.from(ctx.lossyValues).join(', ')}`,
    );
  }

  // Parse and convert the condition
  const queryCondition = parseCondition(condition, selections, warnings);

  // Combine source filter with detection logic
  // Only wrap in parens if not already wrapped and has multiple parts
  // Always group a compound condition: `(a) OR b` starts with `(` but is not
  // one group, and `src (a) OR b` would let `b` escape the source scope.
  const needsParens = queryParts.length > 0 &&
    (queryCondition.includes(' OR ') || queryCondition.includes(' AND '));

  if (queryParts.length > 0) {
    queryParts.push(needsParens ? `(${queryCondition})` : queryCondition);
  } else {
    queryParts.push(queryCondition);
  }

  // Check for timeframe
  if (detection.timeframe) {
    warnings.push(`Timeframe "${detection.timeframe}" specified - may need to add aggregation with time window`);
  }

  // Build the final query - combine source filter and detection condition with space
  const query = queryParts.join(' ');

  // Add a basic stats command for aggregation-style rules
  if (rule.description?.toLowerCase().includes('count') ||
      rule.description?.toLowerCase().includes('multiple') ||
      rule.description?.toLowerCase().includes('brute')) {
    warnings.push('Consider adding aggregation (| stats count() by ...) based on detection intent');
  }

  // Build the output
  const frontmatterYaml = Object.entries(frontmatter)
    .map(([key, value]) => `${key}: ${typeof value === 'string' && value.includes('\n') ? `|\n  ${value.replace(/\n/g, '\n  ')}` : value}`)
    .join('\n');

  // Add original Sigma author as comment if available
  const authorComment = originalAuthor ? `// Sigma rule by: ${originalAuthor}\n` : '';

  const output = `---
${frontmatterYaml}
---

${authorComment}${query}`;

  return {
    success: errors.length === 0,
    output,
    warnings,
    errors,
  };
}

