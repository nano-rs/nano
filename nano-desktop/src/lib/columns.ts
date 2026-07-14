/**
 * The stream tells us the column order for `| table` queries; otherwise we lead
 * with the fields an analyst triages on and let the rest follow alphabetically.
 *
 * Covers both schema profiles: a UDM deployment returns `user` / `src_ip`, an
 * OCSF one returns `actor.user.name` / `src_endpoint.ip` for the same event.
 */
const PREFERRED = [
  'timestamp',
  '_time',
  'time',
  'source_type',
  'sourcetype',
  // OCSF
  'activity',
  'class_name',
  'severity',
  'device.hostname',
  'actor.user.name',
  'actor.process.name',
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'status',
  // UDM
  'event_name',
  'event_type',
  'action',
  'rule_name',
  'user',
  'src_ip',
  'dest_ip',
  'src_host',
  'dest_host',
  'outcome',
  'auth_result',
  'process_name',
  'command_line',
  'message',
];

/**
 * `*_unified` are cross-profile accelerator columns and `_inserted_at` is
 * ingest bookkeeping — neither is part of the schema at the surface, so neither
 * belongs in a results table.
 */
function isInternal(column: string): boolean {
  return column.endsWith('_unified') || column === '_inserted_at';
}

export function deriveColumns(rows: Record<string, unknown>[], columnOrder?: string[]): string[] {
  // An explicit `| table a, b` ordering is the user's instruction — honour it verbatim.
  if (columnOrder?.length) return columnOrder;

  const keys = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!isInternal(key)) keys.add(key);
    }
  }

  const leading = PREFERRED.filter((key) => keys.has(key));
  const rest = [...keys].filter((key) => !leading.includes(key)).sort();
  return [...leading, ...rest];
}

const TIME_COLUMNS = new Set(['timestamp', '_time', 'time']);
const IP_COLUMNS = new Set([
  'src_ip',
  'dest_ip',
  'ip',
  'client_ip',
  'src_endpoint.ip',
  'dst_endpoint.ip',
]);
const EVENT_COLUMNS = new Set([
  'event_name',
  'event_type',
  'action',
  'rule_name',
  'activity',
  'class_name',
]);
const OUTCOME_COLUMNS = new Set(['outcome', 'auth_result', 'status', 'result']);

const FAILURE = /fail|deny|denied|block|error|invalid/i;
const SUCCESS = /success|allow|accept|^ok$/i;

export function isTimeColumn(column: string): boolean {
  return TIME_COLUMNS.has(column);
}

/** Colour carries meaning here: IPs read as entities, outcomes as risk. */
export function cellClass(column: string, value: unknown): string {
  if (TIME_COLUMNS.has(column)) return 'text-t3';
  if (EVENT_COLUMNS.has(column)) return 'text-accent';
  if (IP_COLUMNS.has(column)) return 'text-warn';
  if (OUTCOME_COLUMNS.has(column)) {
    const text = String(value ?? '');
    if (FAILURE.test(text)) return 'text-danger';
    if (SUCCESS.test(text)) return 'text-t2';
  }
  return 'text-t2';
}

export function formatCell(value: unknown): string {
  if (value == null || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
