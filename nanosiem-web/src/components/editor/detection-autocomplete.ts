// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 autocomplete integration for detection rules
 * Wraps existing yaml-autocomplete.ts and query-autocomplete.ts utilities
 */
import {
  autocompletion,
  CompletionContext,
  CompletionResult,
  Completion,
  snippetCompletion,
} from '@codemirror/autocomplete';
import { Extension } from '@codemirror/state';
import { isInYamlSection } from './detection-language';
import {
  getMitreTactics,
  getMitreTechniques,
  type AutocompleteOption as YamlOption,
} from '@/lib/yaml-autocomplete';
import {
  getQueryAutocompleteSuggestions,
  type AutocompleteOption as QueryOption,
} from '@/lib/query-autocomplete';

// YAML field value options (static fields)
export const YAML_FIELD_OPTIONS: Record<string, YamlOption[]> = {
  severity: [
    { value: 'critical', label: 'Critical', description: 'Immediate action required' },
    { value: 'high', label: 'High', description: 'Urgent attention needed' },
    { value: 'medium', label: 'Medium', description: 'Standard priority' },
    { value: 'low', label: 'Low', description: 'Informational' },
  ],
  mode: [
    { value: 'staging', label: 'Staging', description: 'Development/testing - not executed' },
    { value: 'live', label: 'Live', description: 'Runs but does not create alerts' },
    { value: 'alerting', label: 'Alerting', description: 'Runs and creates alerts on matches' },
    { value: 'paused', label: 'Paused', description: 'Temporarily stopped - was alerting/live' },
  ],
  detection_mode: [
    { value: 'realtime', label: 'Real-time', description: 'Fast detection (10-30s latency)' },
    { value: 'scheduled', label: 'Scheduled', description: 'Cron-based execution' },
  ],
  // NAN-1561/NAN-1805: dataset the rule queries. Non-logs values are scheduled-only.
  dataset: [
    { value: 'logs', label: 'Logs', description: 'UDM/OCSF events (default)' },
    { value: 'spans', label: 'Traces', description: 'OTLP spans (scheduled-only)' },
    { value: 'metrics', label: 'Metrics', description: 'OTLP metrics (scheduled-only)' },
    { value: 'risk', label: 'Risk', description: 'Accumulated entity risk (scheduled-only; rules cannot add risk)' },
  ],
  alert_mode: [
    { value: 'grouped', label: 'Grouped', description: 'All matches → 1 alert (default)' },
    { value: 'per_event', label: 'Per Event', description: 'Each match → its own alert (vendor pass-through)' },
  ],
  risk_score: [
    { value: 'auto', label: 'Auto', description: 'Calculated from severity' },
    { value: '90', label: '90', description: 'Critical risk' },
    { value: '70', label: '70', description: 'High risk' },
    { value: '50', label: '50', description: 'Medium risk' },
    { value: '30', label: '30', description: 'Low risk' },
  ],
  risk_entity: [
    { value: 'auto-detect', label: 'Auto-detect', description: 'src_ip → user → hostname' },
    { value: 'src_ip', label: 'src_ip', description: 'Source IP address' },
    { value: 'user', label: 'user', description: 'Username' },
    { value: 'hostname', label: 'hostname', description: 'Host name' },
    { value: 'dest_ip', label: 'dest_ip', description: 'Destination IP' },
    { value: 'process_name', label: 'process_name', description: 'Process name' },
  ],
  schedule: [
    { value: '*/30 * * * * *', label: 'Every 30 seconds', description: '6-field cron (with seconds)' },
    { value: '*/1 * * * *', label: 'Every 1 minute', description: 'Default schedule' },
    { value: '*/2 * * * *', label: 'Every 2 minutes', description: 'Light-frequency polling' },
    { value: '*/5 * * * *', label: 'Every 5 minutes', description: 'Standard detection interval' },
    { value: '*/10 * * * *', label: 'Every 10 minutes', description: 'Moderate-frequency polling' },
    { value: '*/15 * * * *', label: 'Every 15 minutes', description: 'Quarter-hour interval' },
    { value: '*/30 * * * *', label: 'Every 30 minutes', description: 'Half-hour interval' },
    { value: '0 * * * *', label: 'Every hour', description: 'Hourly execution' },
  ],
  lookback: [
    { value: '15m', label: '15 minutes', description: 'Default lookback' },
    { value: '1h', label: '1 hour', description: 'Short-term analysis' },
    { value: '6h', label: '6 hours', description: 'Medium-term analysis' },
    { value: '24h', label: '24 hours', description: 'Daily analysis (for prevalence)' },
    { value: '7d', label: '7 days', description: 'Weekly analysis' },
  ],
};

/**
 * Get options for a YAML field (handles dynamic MITRE data)
 */
function getYamlFieldOptions(field: string): YamlOption[] | null {
  if (field === 'mitre_tactics') {
    return getMitreTactics();
  }
  if (field === 'mitre_techniques') {
    return getMitreTechniques();
  }
  return YAML_FIELD_OPTIONS[field] || null;
}

/**
 * Convert YAML options to CodeMirror completions
 */
function yamlOptionsToCompletions(options: YamlOption[], from: number, field?: string): CompletionResult {
  const completions: Completion[] = options.map((opt, index) => ({
    label: opt.value,
    detail: opt.label !== opt.value ? opt.label : undefined,
    info: opt.description,
    boost: options.length - index, // Maintain order
    type: 'constant',
  }));

  return {
    from,
    options: completions,
    // Schedule values contain */spaces — keep popup open while typing cron
    validFor: field === 'schedule' ? /^[*/\d\s,-]*$/ : /^[\w-]*$/,
  };
}

/**
 * Convert query options to CodeMirror completions
 */
function queryOptionsToCompletions(
  options: QueryOption[],
  from: number,
  context: string | null,
  insideQuotes = false,
  toPosition?: number
): CompletionResult {
  const completions: Completion[] = options.map((opt, index) => {
    const completion: Completion = {
      label: opt.value,
      info: opt.description,
      boost: options.length - index,
    };

    // Set type based on context for proper icons
    switch (context) {
      case 'command':
        completion.type = 'function';
        break;
      case 'field':
        completion.type = 'property';
        // Add category as section if available
        if (opt.category) {
          completion.detail = opt.category;
        }
        break;
      case 'function':
        completion.type = 'function';
        // Add parentheses for function completion
        completion.apply = `${opt.value}()`;
        break;
      case 'source_type':
        completion.type = 'enum';
        // Only wrap in quotes if not already inside quotes
        completion.apply = insideQuotes ? opt.value : `"${opt.value}"`;
        break;
      case 'table_wildcard':
        completion.type = 'keyword';
        break;
      default:
        completion.type = 'text';
    }

    return completion;
  });

  const result: CompletionResult = {
    from,
    options: completions,
    validFor: /^[\w*]*$/,
  };

  // If we have a specific end position (e.g., to replace closing quote too)
  if (toPosition !== undefined) {
    result.to = toPosition;
  }

  return result;
}

/**
 * YAML section autocomplete source
 */
async function yamlAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  // Only provide completions in YAML section
  if (!isInYamlSection(doc, pos)) {
    return null;
  }

  // Get the current line
  const line = context.state.doc.lineAt(pos);
  const lineText = line.text;
  const lineStart = line.from;
  const posInLine = pos - lineStart;

  // Check if we're after a colon (completing a field value)
  const colonMatch = lineText.match(/^(\w+):\s*/);
  if (colonMatch) {
    const fieldName = colonMatch[1];
    const colonEnd = colonMatch[0].length;

    // Only trigger if cursor is after the colon+space
    if (posInLine >= colonEnd) {
      const options = getYamlFieldOptions(fieldName);
      if (options) {
        // Calculate from position (start of value)
        const from = lineStart + colonEnd;
        return yamlOptionsToCompletions(options, from, fieldName);
      }
    }
  }

  return null;
}

/**
 * Query section autocomplete source
 */
async function queryAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  // Only provide completions in query section
  if (isInYamlSection(doc, pos)) {
    return null;
  }

  // Get suggestions from existing utility
  const result = await getQueryAutocompleteSuggestions(doc, pos, []);

  if (result.options.length === 0) {
    return null;
  }

  // Calculate the from position based on what the user has typed
  const textBefore = doc.substring(0, pos);
  const textAfter = doc.substring(pos);

  // Find where the current word starts
  let from = pos;
  const wordMatch = textBefore.match(/[\w*]+$/);
  if (wordMatch) {
    from = pos - wordMatch[0].length;
  }

  // For source_type context, check if we're already inside quotes
  let insideQuotes = false;
  let toPosition: number | undefined;

  if (result.context === 'source_type') {
    // Check if there's a quote before the word
    const charBeforeWord = from > 0 ? doc[from - 1] : '';
    if (charBeforeWord === '"') {
      insideQuotes = true;
      // Also check for closing quote and include it in replacement
      const closingQuoteMatch = textAfter.match(/^[\w]*"/);
      if (closingQuoteMatch) {
        toPosition = pos + closingQuoteMatch[0].length - (pos - from);
      }
    }
  }

  return queryOptionsToCompletions(result.options, from, result.context, insideQuotes, toPosition);
}

/**
 * YAML field name completions (for typing new fields)
 */
const yamlFieldSnippets: Completion[] = [
  snippetCompletion('title: ${name}', { label: 'title', info: 'Rule name (snake_case)' }),
  snippetCompletion('description: ${description}', { label: 'description', info: 'Rule description' }),
  snippetCompletion('author: ${author}', { label: 'author', info: 'Rule author' }),
  snippetCompletion('severity: ${1|critical,high,medium,low|}', { label: 'severity', info: 'Alert severity' }),
  snippetCompletion('mode: ${1|staging,live,alerting,paused|}', { label: 'mode', info: 'Rule mode' }),
  snippetCompletion('detection_mode: ${1|realtime,scheduled|}', { label: 'detection_mode', info: 'Detection mode' }),
  snippetCompletion('dataset: ${1|logs,spans,metrics,risk|}', { label: 'dataset', info: 'Dataset the rule queries (non-logs are scheduled-only)' }),
  snippetCompletion('alert_mode: ${1|grouped,per_event|}', { label: 'alert_mode', info: 'Alert mode (grouped or per_event)' }),
  snippetCompletion('schedule: ${1|*/1 * * * *,*/30 * * * * *,*/5 * * * *,*/15 * * * *,0 * * * *|}', { label: 'schedule', info: 'Cron schedule (select or type custom)' }),
  snippetCompletion('lookback: ${1|15m,1h,6h,24h,7d|}', { label: 'lookback', info: 'Lookback window' }),
  snippetCompletion('tags: ${tags}', { label: 'tags', info: 'Comma-separated tags' }),
  snippetCompletion('narrative: ${narrative}', { label: 'narrative', info: 'Detection narrative' }),
  snippetCompletion('mitre_tactics: ${tactics}', { label: 'mitre_tactics', info: 'MITRE ATT&CK tactics' }),
  snippetCompletion('mitre_techniques: ${techniques}', { label: 'mitre_techniques', info: 'MITRE ATT&CK techniques' }),
  snippetCompletion('risk_score: ${1|auto,90,75,50,25|}', { label: 'risk_score', info: 'Risk score' }),
  snippetCompletion('risk_entity: ${1|auto-detect,src_ip,user,hostname|}', { label: 'risk_entity', info: 'Risk entity field' }),
];

/**
 * YAML field name autocomplete for new lines
 */
async function yamlFieldAutocomplete(context: CompletionContext): Promise<CompletionResult | null> {
  const doc = context.state.doc.toString();
  const pos = context.pos;

  // Only in YAML section
  if (!isInYamlSection(doc, pos)) {
    return null;
  }

  // Check if we're at the start of a line (possibly with partial field name)
  const line = context.state.doc.lineAt(pos);
  const lineText = line.text.substring(0, pos - line.from);

  // Only if typing a potential field name (start of line, maybe with partial word)
  if (/^\w*$/.test(lineText)) {
    return {
      from: line.from,
      options: yamlFieldSnippets,
      validFor: /^\w*$/,
    };
  }

  return null;
}

/**
 * Combined autocomplete extension
 */
export function detectionAutocomplete(): Extension {
  return autocompletion({
    override: [yamlAutocomplete, queryAutocomplete, yamlFieldAutocomplete],
    activateOnTyping: true,
    maxRenderedOptions: 50,
    defaultKeymap: true,
    icons: true,
  });
}

export default detectionAutocomplete;
