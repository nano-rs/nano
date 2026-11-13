// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared autocomplete logic for query editors (Search, RuleEditor)
import { authenticatedFetch } from '@/lib/authenticated-fetch';
import { api } from '@/lib/api';
import { PIPE_COMMANDS, EVAL_FUNCTIONS, COMMAND_PARAMS } from '@/lib/query-tokens';
import {
  curatedFieldsFor,
  rankFieldSuggestions,
  type FieldSection,
  type FieldUsage,
  type RankableField,
} from '@/lib/field-suggestion-ranking';
import { schemaField } from '@/lib/schema-fields';

const OCSF_LOG_SOURCE_FIELD = schemaField('ocsf', 'logSource');

export type { FieldSection, FieldUsage } from '@/lib/field-suggestion-ranking';

export interface AutocompleteOption {
  value: string;
  description?: string;
  category?: string;
  /** Field suggestions only: which group the field belongs to (NAN-3812). */
  section?: FieldSection;
}

interface AutocompleteResult {
  options: AutocompleteOption[];
  /**
   * - 'function': callable functions (eval / aggregation); the rule editor appends `()`.
   * - 'parameter': command parameter names (span, window, ...); plain insertion.
   * - 'argument_value': values for `param=` (span=1h, type=inner, ...); plain insertion.
   */
  context:
    | 'command'
    | 'field'
    | 'source_type'
    | 'function'
    | 'parameter'
    | 'argument_value'
    | 'table_wildcard'
    | null;
}

export interface UdmFieldInfo {
  name: string;
  column_name: string;
  data_type: string;
  category: string;
  description: string;
}

/**
 * Where the dynamic half of autocomplete (source types + the field universe)
 * comes from. The static half — pipe commands, eval functions, command params —
 * needs no I/O.
 *
 * The web app uses the default below. The desktop app cannot: its webview is
 * cross-origin to the SIEM, so it issues HTTP from Rust and injects a provider
 * that goes over IPC instead. Same suggestions, different transport.
 */
export interface AutocompleteDataSource {
  /** `/api/source-types` — [value, count] pairs. */
  getSourceTypes(timeRange?: { start: string; end: string }): Promise<[string, number][]>;
  /** `/api/schema/fields` — the active profile's promoted columns. */
  getSchemaFields(): Promise<{
    schema: string;
    fields: { name: string; type: string; category: string }[];
  } | null>;
  /** `/api/udm/fields` — UDM only, but carries the human-readable descriptions. */
  getLegacyUdmFields(): Promise<UdmFieldInfo[]>;
  /** `/api/me/field-usage` — the caller's recent + workspace-popular fields. Optional. */
  getFieldUsage?(): Promise<FieldUsage | null>;
  /** Bare spill keys seen in recent data (the OCSF `unmapped` column). Optional. */
  getSpillFieldNames?(): Promise<string[]>;
}

const defaultDataSource: AutocompleteDataSource = {
  getSourceTypes: (timeRange) => api.getSourceTypes(timeRange),
  getSchemaFields: () => api.getSchemaFields(),
  getLegacyUdmFields: () => {
    return authenticatedFetch('/api/udm/fields', `${import.meta.env.VITE_API_URL ?? ''}/api/udm/fields`)
      .then((res) => res.json())
      .then((data) => (data.fields || []) as UdmFieldInfo[])
      .catch(() => [] as UdmFieldInfo[]);
  },
  getFieldUsage: () => {
    return authenticatedFetch('/api/me/field-usage', `${import.meta.env.VITE_API_URL ?? ''}/api/me/field-usage`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => (data ? normalizeFieldUsage(data) : null))
      .catch(() => null);
  },
  getSpillFieldNames: () => api.getExtFieldNames().catch(() => [] as string[]),
};

/**
 * NAN-5326: category labels arrive lowercase from `/api/schema/fields`
 * (`network`) and capitalised from the curated/UDM lists (`Network`), so the
 * dropdown showed both spellings. Display one form.
 */
function displayCategory(category: string | undefined): string | undefined {
  if (!category) return category;
  return category.charAt(0).toUpperCase() + category.slice(1);
}

/** Namespaced `unmapped.<key>` entries for the OCSF spill (bare keys from the API). */
async function fetchUnmappedFields(): Promise<UdmFieldInfo[]> {
  if (!dataSource.getSpillFieldNames) return [];
  let names: string[] = [];
  try {
    names = await dataSource.getSpillFieldNames();
  } catch {
    return [];
  }
  const seen = new Set<string>();
  const out: UdmFieldInfo[] = [];
  for (const raw of names) {
    if (typeof raw !== 'string' || !raw) continue;
    const name = raw.startsWith('unmapped.') ? raw : `unmapped.${raw}`;
    if (seen.has(name)) continue;
    seen.add(name);
    out.push({ name, column_name: name, data_type: 'String', category: 'Unmapped', description: '' });
  }
  return out;
}

function normalizeFieldUsage(data: unknown): FieldUsage | null {
  if (!data || typeof data !== 'object') return null;
  const pick = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
  const d = data as Record<string, unknown>;
  return { recent: pick(d.recent), popular: pick(d.popular) };
}

let dataSource: AutocompleteDataSource = defaultDataSource;

/** Swap the transport (see AutocompleteDataSource). Clears any cached results. */
export function setAutocompleteDataSource(source: AutocompleteDataSource) {
  dataSource = source;
  sourceTypesCache = null;
  sourceTypesCacheKey = null;
  sourceTypesFetchPromise = null;
  udmFieldsCache = null;
  udmFieldsFetchPromise = null;
  invalidateFieldUsageCache();
}

/** Drop cached field usage so the next suggestion re-reads it (call after a
 *  search lands in history, or history is cleared). */
export function invalidateFieldUsageCache(): void {
  fieldUsageCache = null;
  fieldUsageFetchPromise = null;
}

const pipeCommands = PIPE_COMMANDS as readonly string[];

// Common fields that should always be available for autocomplete (not always in UDM API)
const commonQueryFields: AutocompleteOption[] = [
  { value: 'sourcetype', description: 'Data source type', category: 'Source' },
  { value: 'source_type', description: 'Data source type (alias)', category: 'Source' },
  { value: 'source', description: 'Data source', category: 'Source' },
  { value: 'src_ip', description: 'Source IP address', category: 'Network' },
  { value: 'dest_ip', description: 'Destination IP address', category: 'Network' },
  { value: 'user', description: 'Username', category: 'Identity' },
  { value: 'hostname', description: 'Host name', category: 'Host' },
  { value: 'process_name', description: 'Process name', category: 'Process' },
  { value: 'command_line', description: 'Full command line (path + exe + args)', category: 'Process' },
  { value: 'file_path', description: 'File path', category: 'File' },
  { value: 'event_type', description: 'Event type', category: 'Event' },
];

// Field usage (recent + workspace-popular), refreshed at most once a minute.
const FIELD_USAGE_TTL_MS = 60_000;
let fieldUsageCache: { at: number; usage: FieldUsage | null } | null = null;
let fieldUsageFetchPromise: Promise<FieldUsage | null> | null = null;

async function fetchFieldUsage(): Promise<FieldUsage | null> {
  if (!dataSource.getFieldUsage) return null;
  if (fieldUsageCache && Date.now() - fieldUsageCache.at < FIELD_USAGE_TTL_MS) {
    return fieldUsageCache.usage;
  }
  if (fieldUsageFetchPromise) return fieldUsageFetchPromise;
  const promise = dataSource
    .getFieldUsage()
    .catch(() => null)
    .then((usage) => {
      // A failed read is cached too (as null) so a broken endpoint is not
      // hammered on every keystroke; suggestions fall back to the defaults.
      // An invalidation while in flight wins: do not resurrect a stale answer.
      if (fieldUsageFetchPromise === promise) {
        fieldUsageCache = { at: Date.now(), usage };
      }
      return usage;
    })
    .finally(() => {
      if (fieldUsageFetchPromise === promise) fieldUsageFetchPromise = null;
    });
  fieldUsageFetchPromise = promise;
  return promise;
}

// Cache for source types keyed by time range
let sourceTypesCache: string[] | null = null;
let sourceTypesCacheKey: string | null = null;
let sourceTypesFetchPromise: Promise<string[]> | null = null;

// Cache for UDM fields to avoid repeated API calls
let udmFieldsCache: UdmFieldInfo[] | null = null;
let udmFieldsFetchPromise: Promise<UdmFieldInfo[]> | null = null;

// Current time range for source type queries (set by caller)
let _currentTimeRange: { start: string; end: string } | undefined;

/** Set the time range used for source type autocomplete (call from search page) */
export function setAutocompleteTimeRange(timeRange?: { start: string; end: string }) {
  _currentTimeRange = timeRange;
}

async function fetchSourceTypes(): Promise<string[]> {
  const cacheKey = _currentTimeRange ? `${_currentTimeRange.start}_${_currentTimeRange.end}` : 'default';
  if (sourceTypesCache && sourceTypesCacheKey === cacheKey) return sourceTypesCache;

  sourceTypesCache = null;
  sourceTypesFetchPromise = null;
  sourceTypesCacheKey = cacheKey;

  sourceTypesFetchPromise = dataSource.getSourceTypes(_currentTimeRange)
    .then(values => {
      sourceTypesCache = values.map(([value]) => value);
      return sourceTypesCache;
    })
    .catch(() => {
      sourceTypesFetchPromise = null;
      return [];
    });

  return sourceTypesFetchPromise;
}

/** Raw UDM field fetch (`/api/udm/fields`). UDM-only, but carries human-readable
 *  `description`s that `/api/schema/fields` does not. Used directly under the UDM
 *  profile (to keep suggestions byte-identical) and as the fallback when the
 *  profile-aware schema endpoint is unavailable. */
async function fetchLegacyUdmFields(): Promise<UdmFieldInfo[]> {
  return dataSource.getLegacyUdmFields();
}

/**
 * Field universe for nPL autocomplete, sourced from the profile-aware
 * `/api/schema/fields` endpoint the rest of the app uses (NAN-1241). Previously
 * this hit UDM-only `/api/udm/fields`, so under OCSF the promoted columns
 * (`src_endpoint.ip`, `class_uid`, …) were never suggested.
 *
 * - Schema `udm`: defer to `/api/udm/fields` so suggestions (incl. descriptions)
 *   stay byte-identical to the pre-OCSF behavior.
 * - Schema `ocsf` (or any non-UDM): map the schema response into the
 *   autocomplete shape (`name`/`column_name` = the schema column name; `type` →
 *   `data_type`; no description in the schema response).
 * - Schema endpoint unavailable / empty: fall back to `/api/udm/fields`.
 */
async function fetchUdmFields(): Promise<UdmFieldInfo[]> {
  if (udmFieldsCache) return udmFieldsCache;
  if (udmFieldsFetchPromise) return udmFieldsFetchPromise;

  udmFieldsFetchPromise = dataSource
    .getSchemaFields()
    .then(async (resp) => {
      // UDM: keep the existing description-bearing source for byte-identical
      // suggestions. Also covers an empty schema field set.
      if (!resp || resp.schema === 'udm' || !resp.fields?.length) {
        return fetchLegacyUdmFields();
      }
      const fields: UdmFieldInfo[] = resp.fields.map((f) => ({
        name: f.name,
        column_name: f.name,
        data_type: f.type,
        category: f.category,
        description: '',
      }));
      // NAN-4903: `metadata.log_source` is the OCSF routing key, but it resolves
      // to the operational `source_type` column rather than a promoted one, so
      // the backend universe omits it. Without it the OCSF universe was never
      // recognized (the ranking keys on it): the UDM common list (`src_ip`,
      // `process_name`, …) buried the real columns and `metadata.` completed to
      // nothing source-scoped.
      if (!fields.some((f) => f.name === OCSF_LOG_SOURCE_FIELD)) {
        fields.unshift({
          name: OCSF_LOG_SOURCE_FIELD,
          column_name: OCSF_LOG_SOURCE_FIELD,
          data_type: 'String',
          category: 'Metadata',
          description: 'Log source (routing key)',
        });
      }
      // NAN-5326: `unmapped.` completed to nothing although the fields panel
      // lists the spill keys. The spill inventory is a data scan, so it never
      // blocks suggestions: it is merged into the cached universe when it lands.
      void fetchUnmappedFields().then((extra) => {
        const known = new Set(fields.map((f) => f.name));
        for (const f of extra) {
          if (!known.has(f.name)) fields.push(f);
        }
      });
      return fields;
    })
    .catch(() => fetchLegacyUdmFields())
    .then((fields) => {
      udmFieldsCache = fields;
      return fields;
    })
    .catch(() => {
      udmFieldsFetchPromise = null;
      return [] as UdmFieldInfo[];
    });

  return udmFieldsFetchPromise;
}

/**
 * Field suggestions for `partial`, grouped Recent → Popular → Common → rest
 * (NAN-3812). The universe is the schema fields plus fields seen in the current
 * results plus the common list; usage comes from `/api/me/field-usage`.
 */
async function rankedFieldOptions(
  partial: string,
  availableFields: string[],
  udmFields: UdmFieldInfo[],
): Promise<AutocompleteOption[]> {
  const universe = new Map<string, RankableField>();
  for (const f of udmFields) {
    universe.set(f.name, { value: f.name, description: f.description || undefined, category: displayCategory(f.category) });
  }
  for (const name of availableFields) {
    if (!universe.has(name)) universe.set(name, { value: name });
  }
  const schemaKnown = universe.size > 0;
  // The UDM common list (aliases like `sourcetype` the schema does not carry)
  // joins the universe unless the schema is OCSF, where it would bury the real
  // columns.
  if (!universe.has(OCSF_LOG_SOURCE_FIELD)) {
    for (const f of commonQueryFields) if (!universe.has(f.value)) universe.set(f.value, f);
  }
  let usage: FieldUsage | null = null;
  try {
    usage = await fetchFieldUsage();
  } catch {
    usage = null;
  }
  const curated = curatedFieldsFor(schemaKnown ? universe : new Map(), commonQueryFields);
  return rankFieldSuggestions({ partial, universe, universeComplete: schemaKnown, usage, curated });
}

/** Cursor sits where a new search term (field filter) may start, with nothing typed. */
function isEmptyFilterPosition(textBeforeCursor: string): boolean {
  if (/\|[^|]*$/.test(textBeforeCursor)) return false; // inside a pipe command
  if ((textBeforeCursor.match(/"/g) ?? []).length % 2 === 1) return false; // inside a string
  return /(?:^|\s|\()$/.test(textBeforeCursor);
}

/**
 * Get autocomplete suggestions based on query text and cursor position
 * @param query - The full query text
 * @param cursorPos - Current cursor position in the query
 * @param availableFields - Optional array of fields from current context (e.g., search results)
 * @returns AutocompleteResult with options and context type
 */
export async function getQueryAutocompleteSuggestions(
  query: string,
  cursorPos: number,
  availableFields: string[] = [],
  opts: { explicit?: boolean } = {},
): Promise<AutocompleteResult> {
  const textBeforeCursor = query.substring(0, cursorPos);
  
  // Check for pipe command context
  const pipeCommandMatch = textBeforeCursor.match(/\|\s*(\w*)$/);
  if (pipeCommandMatch) {
    const partial = pipeCommandMatch[1].toLowerCase();
    const matches = pipeCommands.filter(cmd => cmd.toLowerCase().startsWith(partial));

    if (matches.length > 0) {
      return {
        options: matches.map(m => ({ value: m })),
        context: 'command',
      };
    }
  }

  // Check for stats/timechart/eventstats/streamstats/chart aggregation function context
  const statsAggMatch = textBeforeCursor.match(/\|\s*(?:stats|timechart|eventstats|streamstats|chart)\s+(?:.*,\s*)?(\w*)$/i);
  if (statsAggMatch && !/\bby\s+[\w.,\s]*$/i.test(textBeforeCursor)) {
    const partial = statsAggMatch[1].toLowerCase();
    const aggFunctions = [
      'count', 'dc', 'avg', 'sum', 'min', 'max', 'values', 'list',
      'earliest', 'latest', 'first', 'last', 'median', 'mode',
      'percentile', 'perc95', 'perc99', 'stdev', 'var', 'range', 'sparkline',
    ];
    const matches = aggFunctions.filter(f => f.startsWith(partial));
    if (matches.length > 0) {
      return {
        options: matches.map(m => ({ value: m, description: 'Aggregation function' })),
        context: 'function',
      };
    }
  }

  // Check for parameter value context — suggest values for known params
  const paramValueMatch = textBeforeCursor.match(/\b([\w.]+)=(\w*)$/);
  if (paramValueMatch) {
    const paramName = paramValueMatch[1].toLowerCase();
    const partial = paramValueMatch[2].toLowerCase();
    const paramValues: Record<string, { value: string; description?: string }[]> = {
      'method': [
        { value: 'zscore', description: 'Standard deviation method' },
        { value: 'mad', description: 'Median absolute deviation' },
      ],
      'type': [
        { value: 'inner', description: 'Inner join' },
        { value: 'left', description: 'Left outer join' },
        { value: 'outer', description: 'Full outer join' },
      ],
      'format': [
        { value: 'json', description: 'JSON format' },
        { value: 'csv', description: 'CSV format' },
      ],
      'enrich': [
        { value: 'true', description: 'Add prevalence metadata' },
        { value: 'false' },
      ],
      'mode': [
        { value: 'sed', description: 'Sed substitution mode (rex)' },
      ],
      'span': [
        { value: '1m' }, { value: '5m' }, { value: '10m' }, { value: '15m' }, { value: '30m' },
        { value: '1h' }, { value: '4h' }, { value: '12h' }, { value: '1d' }, { value: '7d' }, { value: '30d' },
      ],
      'window': [
        { value: '24h' }, { value: '7d' }, { value: '30d' },
        { value: '1d' }, { value: '14d' }, { value: '90d' },
      ],
      'maxspan': [
        { value: '1m' }, { value: '5m' }, { value: '10m' }, { value: '15m' }, { value: '30m' },
        { value: '1h' }, { value: '4h' }, { value: '12h' }, { value: '24h' },
      ],
      'hop': [
        { value: '1m' }, { value: '5m' }, { value: '10m' }, { value: '15m' }, { value: '30m' },
        { value: '1h' },
      ],
    };
    const knownValues = paramValues[paramName];
    if (knownValues) {
      const matches = knownValues.filter(v => v.value.startsWith(partial));
      if (matches.length > 0) {
        return { options: matches, context: 'argument_value' };
      }
    }
  }

  // Check for command parameter name context for param-heavy commands
  const paramCmdMatch = textBeforeCursor.match(/\|\s*(?:anomaly|prevalence|risk|transaction|sequence|funnel|tree|ai|sample|lookup|inputlookup|bin|fillnull|rex|resolve_identity|timechart|streamstats|eventstats)\s+.*?(\w+)$/i);
  if (paramCmdMatch && !paramValueMatch) {
    const partial = paramCmdMatch[1].toLowerCase();
    const params = COMMAND_PARAMS as readonly string[];
    const matches = params.filter(p => p.startsWith(partial) && p !== partial);
    if (matches.length > 0 && matches.length <= 15) {
      return {
        options: matches.map(m => ({ value: m, description: 'Parameter' })),
        context: 'parameter',
      };
    }
  }

  // Check for source_type= context
  const sourceTypeMatch = textBeforeCursor.match(/(?:source_type|sourcetype|metadata\.log_source)\s*=\s*"?([^"\s]*)$/i);
  if (sourceTypeMatch) {
    const partial = sourceTypeMatch[1].toLowerCase();
    try {
      const sourceTypes = await fetchSourceTypes();
      const matches = sourceTypes.filter(st =>
        st.toLowerCase().startsWith(partial) || partial === ''
      );

      if (matches.length > 0) {
        return {
          options: matches.map(m => ({ value: m })),
          context: 'source_type',
        };
      }
    } catch {
      // Silently fail - autocomplete is optional
    }
  }

  // Fetch UDM fields from API
  let udmFields: UdmFieldInfo[] = [];
  try {
    udmFields = await fetchUdmFields();
  } catch {
    // Silently fail - will fall back to hardcoded fields
  }

  // Field context patterns — commands where the next token is a field name
  const fieldContextPatterns = [
    /\|\s*table\s+[\w.,\s]*$/i,
    /\|\s*fields\s+[\w.,\s]*$/i,
    /\|\s*(?:stats|eventstats|streamstats|chart)\s+.*\bby\s+[\w.,\s]*$/i,
    /\bby\s+[\w.,\s]*$/i,
    /\|\s*sort\s+[-+]?[\w.]*$/i,
    /\|\s*timechart\s+.*\bby\s+[\w.]*$/i,
    /\|\s*where\s+[\w.]*$/i,
    /\|\s*eval\s+\w+\s*=\s*[\w.]*$/i,
    /\|\s*dedup\s+[\w.,\s]*$/i,
    /\|\s*top\s+[\w.,\s]*$/i,
    /\|\s*rare\s+[\w.,\s]*$/i,
    /\|\s*rename\s+[\w.]*$/i,
    /\|\s*mvexpand\s+[\w.]*$/i,
    /\|\s*transaction\s+[\w.,\s]*$/i,
    /\|\s*join\s+(?:type=\w+\s+)?[\w.,\s]*$/i,
    /\|\s*return\s+[\w.,\s]*$/i,
    /\|\s*(?:anomaly|resolve_identity)\s+.*\bfield=[\w.]*$/i,
    /\|\s*prevalence\s+[\w.]*$/i,
    /\|\s*fillnull\s+(?:value="[^"]*"\s+)?[\w.,\s]*$/i,
    /\bfield=[\w.]*$/i,
    /\|\s*rex\s+field=[\w.]*$/i,
  ];
  
  // Check for table command specifically to suggest wildcard
  const tableCommandMatch = textBeforeCursor.match(/\|\s*table\s+$/i);
  if (tableCommandMatch) {
    return {
      options: [
        { value: '*', description: 'Select all fields' },
      ],
      context: 'table_wildcard',
    };
  }
  
  const isInFieldContext = fieldContextPatterns.some(pattern => pattern.test(textBeforeCursor));

  // Empty field prompt (Ctrl+Space at the start of the query, or after a
  // complete filter term): offer the grouped field list. Only on explicit
  // request so it never pops on space.
  if (opts.explicit && !isInFieldContext && isEmptyFilterPosition(textBeforeCursor)) {
    const fieldOptions = await rankedFieldOptions('', availableFields, udmFields);
    if (fieldOptions.length > 0) {
      return { options: fieldOptions, context: 'field' };
    }
  }
  
  // Check for filter condition context - typing a field name for a new condition
  // Matches: start of query (after ---), start of line, after AND/OR, after quotes, after parentheses
  const filterConditionMatch = textBeforeCursor.match(/(?:^|---\s*|\n\s*|AND\s+|OR\s+|"\s+|'\s+|\)\s+)([\w.]+)$/i);
  const isTypingFieldName = filterConditionMatch && filterConditionMatch[1].length >= 1;
  
  if (isTypingFieldName && !isInFieldContext) {
    const partial = filterConditionMatch[1].toLowerCase();

    const fieldOptions = await rankedFieldOptions(partial, availableFields, udmFields);
    if (fieldOptions.length > 0) {
      return { options: fieldOptions, context: 'field' };
    }
  }
  
  if (isInFieldContext) {
    const lastWord = textBeforeCursor.match(/[\w.]*$/)?.[0] || '';
    const partial = lastWord.toLowerCase();

    // Require at least 2 chars to avoid flooding with all UDM fields
    if (partial.length < 2) {
      return { options: [], context: null };
    }

    const fieldOptions = await rankedFieldOptions(partial, availableFields, udmFields);
    if (fieldOptions.length > 0) {
      return { options: fieldOptions, context: 'field' };
    }
  }
  
  // Check for eval function context
  const evalFunctionMatch = textBeforeCursor.match(/\|\s*eval\s+\w+\s*=\s*(\w*)$/i);
  if (evalFunctionMatch) {
    const partial = evalFunctionMatch[1].toLowerCase();
    const evalFuncs = EVAL_FUNCTIONS as readonly string[];
    const matches = evalFuncs.filter(func => func.toLowerCase().startsWith(partial));

    if (matches.length > 0) {
      return {
        options: matches.map(m => ({ value: m })),
        context: 'function',
      };
    }
  }
  
  return {
    options: [],
    context: null,
  };
}

