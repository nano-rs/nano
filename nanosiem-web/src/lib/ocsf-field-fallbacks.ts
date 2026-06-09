/**
 * OCSF native-column fallbacks for UDM-semantic concepts (NAN-1322/NAN-1324).
 *
 * Under OCSF the search/asset rows are keyed by NATIVE OCSF columns
 * (`process.name`, `user.name`, `dst_endpoint.hostname`, …) instead of UDM
 * names, so UDM-keyed accessors (`row.process_name`) read `undefined`. Resolve a
 * UDM concept through `fieldVal`: the UDM key is checked FIRST (so under UDM the
 * value is byte-identical), then the native OCSF column(s). Mirrors the backend
 * `class_split_udm_field` / `display_field_name` mappings. Concepts OCSF has no
 * clean column for are simply absent → the bare UDM key is used (graceful).
 */
export const OCSF_FIELD_FALLBACKS: Record<string, string[]> = {
  process_name: ['process.name', 'actor.process.name'],
  command_line: ['process.cmd_line', 'actor.process.cmd_line'],
  parent_command_line: ['actor.process.cmd_line'],
  user: ['user.name', 'actor.user.name'],
  file_name: ['file.name'],
  file_path: ['file.path'],
  file_hash: ['file.hashes.sha256'],
  process_hash: ['process.file.hashes.sha256', 'actor.process.file.hashes.sha256'],
  dest_host: ['dst_endpoint.hostname'],
  dest_ip: ['dst_endpoint.ip'],
  dest_port: ['dst_endpoint.port'],
  src_ip: ['src_endpoint.ip'],
  src_host: ['src_endpoint.hostname', 'device.hostname'],
  src_mac: ['src_endpoint.mac'],
  url: ['url.url_string', 'http_request.url.url_string'],
  query: ['query.hostname'],
  answer: ['answers.rdata'],
  auth_type: ['auth_protocol'],
  bytes_out: ['traffic.bytes_out'],
  bytes_in: ['traffic.bytes_in'],
};

/** A value is "empty" if it's null/undefined/'' or the `"-"` placeholder that
 *  many sources (Sysmon, syslog) emit for an absent field. */
function isEmptyVal(v: unknown): boolean {
  return (
    v === null ||
    v === undefined ||
    v === '' ||
    (typeof v === 'string' && v.trim() === '-')
  );
}

/**
 * Resolve a UDM concept to the ACTUAL key it lives under + its value, checking
 * the UDM key first (byte-identical under UDM) then the native OCSF column(s).
 * Returns `null` when no non-empty value exists. The `key` is the matched
 * column, so callers can display the schema-native name (`process.name` under
 * OCSF, `process_name` under UDM) — keeping the collapsed summary consistent with
 * the native-keyed detail (NAN-1326). `"-"` placeholders are treated as empty, so
 * a Sysmon `dst_endpoint.hostname = "-"` falls through to the next candidate.
 */
export function fieldEntry(
  fields: Record<string, unknown>,
  concept: string,
): { key: string; value: unknown } | null {
  const direct = fields[concept];
  if (!isEmptyVal(direct)) return { key: concept, value: direct };
  for (const alt of OCSF_FIELD_FALLBACKS[concept] ?? []) {
    const v = fields[alt];
    if (!isEmptyVal(v)) return { key: alt, value: v };
  }
  return null;
}

/**
 * Resolve a UDM concept from a (possibly OCSF-native-keyed) flat field record.
 * UDM key first → byte-identical under UDM; then the native OCSF column(s).
 * Returns the original (possibly undefined/empty) UDM value when no native hit.
 */
export function fieldVal(fields: Record<string, unknown>, concept: string): unknown {
  return fieldEntry(fields, concept)?.value ?? fields[concept];
}
