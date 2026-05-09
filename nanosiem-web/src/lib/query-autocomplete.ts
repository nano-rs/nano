// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared autocomplete logic for query editors (Search, RuleEditor)
import { api } from '@/lib/api';
import { getAccessToken } from '@/lib/auth-token';
import { PIPE_COMMANDS, EVAL_FUNCTIONS, COMMAND_PARAMS } from '@/lib/query-tokens';

export interface AutocompleteOption {
  value: string;
  description?: string;
  category?: string;
}

interface AutocompleteResult {
  options: AutocompleteOption[];
  context: 'command' | 'field' | 'source_type' | 'function' | 'table_wildcard' | null;
}

interface UdmFieldInfo {
  name: string;
  column_name: string;
  data_type: string;
  category: string;
  description: string;
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

  sourceTypesFetchPromise = api.getSourceTypes(_currentTimeRange)
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

async function fetchUdmFields(): Promise<UdmFieldInfo[]> {
  if (udmFieldsCache) return udmFieldsCache;
  if (udmFieldsFetchPromise) return udmFieldsFetchPromise;
  
  const token = getAccessToken();
  udmFieldsFetchPromise = fetch(`${import.meta.env.VITE_API_URL ?? ''}/api/udm/fields`, {
    headers: {
      'Authorization': token ? `Bearer ${token}` : '',
    },
  })
    .then(res => res.json())
    .then(data => {
      const fields: UdmFieldInfo[] = data.fields || [];
      udmFieldsCache = fields;
      return fields;
    })
    .catch(() => {
      udmFieldsFetchPromise = null;
      return [] as UdmFieldInfo[];
    });
  
  return udmFieldsFetchPromise;
}

function groupByCategory(options: AutocompleteOption[]): Map<string, AutocompleteOption[]> {
  const grouped = new Map<string, AutocompleteOption[]>();
  
  for (const option of options) {
    const category = option.category || 'Other';
    if (!grouped.has(category)) {
      grouped.set(category, []);
    }
    grouped.get(category)!.push(option);
  }
  
  return grouped;
}

function flattenGroupedOptions(grouped: Map<string, AutocompleteOption[]>): AutocompleteOption[] {
  const result: AutocompleteOption[] = [];
  
  // Sort categories alphabetically, but put "Other" last
  const sortedCategories = Array.from(grouped.keys()).sort((a, b) => {
    if (a === 'Other') return 1;
    if (b === 'Other') return -1;
    return a.localeCompare(b);
  });
  
  for (const category of sortedCategories) {
    const options = grouped.get(category)!;
    result.push(...options);
  }
  
  return result;
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
  availableFields: string[] = []
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
  if (statsAggMatch && !/\bby\s+[\w,\s]*$/i.test(textBeforeCursor)) {
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
  const paramValueMatch = textBeforeCursor.match(/\b(\w+)=(\w*)$/);
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
        return { options: matches, context: 'function' };
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
        context: 'function',
      };
    }
  }

  // Check for source_type= context
  const sourceTypeMatch = textBeforeCursor.match(/(?:source_type|sourcetype)\s*=\s*"?([^"\s]*)$/i);
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
    /\|\s*table\s+[\w,\s]*$/i,
    /\|\s*fields\s+[\w,\s]*$/i,
    /\|\s*(?:stats|eventstats|streamstats|chart)\s+.*\bby\s+[\w,\s]*$/i,
    /\bby\s+[\w,\s]*$/i,
    /\|\s*sort\s+[-+]?[\w.]*$/i,
    /\|\s*timechart\s+.*\bby\s+[\w.]*$/i,
    /\|\s*where\s+[\w.]*$/i,
    /\|\s*eval\s+\w+\s*=\s*[\w.]*$/i,
    /\|\s*dedup\s+[\w,\s]*$/i,
    /\|\s*top\s+[\w,\s]*$/i,
    /\|\s*rare\s+[\w,\s]*$/i,
    /\|\s*rename\s+[\w.]*$/i,
    /\|\s*mvexpand\s+[\w.]*$/i,
    /\|\s*transaction\s+[\w,\s]*$/i,
    /\|\s*join\s+(?:type=\w+\s+)?[\w,\s]*$/i,
    /\|\s*return\s+[\w,\s]*$/i,
    /\|\s*(?:anomaly|resolve_identity)\s+.*\bfield=[\w.]*$/i,
    /\|\s*prevalence\s+[\w.]*$/i,
    /\|\s*fillnull\s+(?:value="[^"]*"\s+)?[\w,\s]*$/i,
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
  
  // Check for filter condition context - typing a field name for a new condition
  // Matches: start of query (after ---), start of line, after AND/OR, after quotes, after parentheses
  const filterConditionMatch = textBeforeCursor.match(/(?:^|---\s*|\n\s*|AND\s+|OR\s+|"\s+|'\s+|\)\s+)(\w+)$/i);
  const isTypingFieldName = filterConditionMatch && filterConditionMatch[1].length >= 1;
  
  if (isTypingFieldName && !isInFieldContext) {
    const partial = filterConditionMatch[1].toLowerCase();

    let fieldOptions: AutocompleteOption[] = [];
    const existingValues = new Set<string>();

    // Start with common query fields
    const matchingCommonFields = commonQueryFields.filter(f =>
      f.value.toLowerCase().startsWith(partial)
    );
    for (const field of matchingCommonFields) {
      if (!existingValues.has(field.value)) {
        fieldOptions.push(field);
        existingValues.add(field.value);
      }
    }

    // Add context-specific fields
    if (availableFields.length > 0) {
      const contextFields = availableFields
        .filter(field => field.toLowerCase().startsWith(partial) && !existingValues.has(field))
        .map(field => {
          const udmField = udmFields.find(f => f.name === field || f.column_name === field);
          return {
            value: field,
            description: udmField?.description,
            category: udmField?.category,
          };
        });

      for (const field of contextFields) {
        fieldOptions.push(field);
        existingValues.add(field.value);
      }
    }

    // Add UDM fields from API
    const allUdmFields = udmFields
      .filter(f => f.name.toLowerCase().startsWith(partial) && !existingValues.has(f.name))
      .map(f => ({
        value: f.name,
        description: f.description,
        category: f.category,
      }));

    fieldOptions = [...fieldOptions, ...allUdmFields];

    if (fieldOptions.length > 0) {
      const grouped = groupByCategory(fieldOptions);
      const flatOptions = flattenGroupedOptions(grouped);

      return {
        options: flatOptions,
        context: 'field',
      };
    }
  }
  
  if (isInFieldContext) {
    const lastWord = textBeforeCursor.match(/[\w.]*$/)?.[0] || '';
    const partial = lastWord.toLowerCase();

    // Require at least 2 chars to avoid flooding with all UDM fields
    if (partial.length < 2) {
      return { options: [], context: null };
    }

    let fieldOptions: AutocompleteOption[] = [];
    const existingValues = new Set<string>();

    // Start with common query fields
    const matchingCommonFields = commonQueryFields.filter(f =>
      f.value.toLowerCase().startsWith(partial)
    );
    for (const field of matchingCommonFields) {
      if (!existingValues.has(field.value)) {
        fieldOptions.push(field);
        existingValues.add(field.value);
      }
    }

    // Add context-specific fields
    if (availableFields.length > 0) {
      const contextFields = availableFields
        .filter(field => field.toLowerCase().startsWith(partial) && !existingValues.has(field))
        .map(field => {
          const udmField = udmFields.find(f => f.name === field || f.column_name === field);
          return {
            value: field,
            description: udmField?.description,
            category: udmField?.category,
          };
        });

      for (const field of contextFields) {
        fieldOptions.push(field);
        existingValues.add(field.value);
      }
    }

    // Add UDM fields from API
    const allUdmFields = udmFields
      .filter(f => f.name.toLowerCase().startsWith(partial) && !existingValues.has(f.name))
      .map(f => ({
        value: f.name,
        description: f.description,
        category: f.category,
      }));

    fieldOptions = [...fieldOptions, ...allUdmFields];

    if (fieldOptions.length > 0) {
      const grouped = groupByCategory(fieldOptions);
      const flatOptions = flattenGroupedOptions(grouped);

      return {
        options: flatOptions,
        context: 'field',
      };
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

