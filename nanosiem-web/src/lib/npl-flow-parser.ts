// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parse nPL query string into structured pipe stages for flow visualization.
 * Pure function — no React dependencies.
 */

import { PIPE_COMMANDS_SET } from './query-tokens';

export type StageCategory =
  | 'source'
  | 'filter'
  | 'aggregation'
  | 'enrichment'
  | 'risk-scoring'
  | 'output'
  | 'transform'
  | 'shaping'
  | 'visualization'
  | 'advanced';

export interface PipeStage {
  id: string;
  index: number;
  command: string;
  rawText: string;
  category: StageCategory;
  label: string;
  description: string;
}

export interface Branch {
  sourceIndex: number;
  paths: number[][];
  mergeIndex: number;
}

export interface FlowGraph {
  stages: PipeStage[];
  branches: Branch[];
}

const CATEGORY_MAP: Record<string, StageCategory> = {
  where: 'filter',
  search: 'filter',
  stats: 'aggregation',
  streamstats: 'aggregation',
  eventstats: 'aggregation',
  prevalence: 'enrichment',
  lookup: 'enrichment',
  inputlookup: 'enrichment',
  asset: 'enrichment',
  lateral: 'enrichment',
  resolve_identity: 'enrichment',
  risk: 'risk-scoring',
  table: 'output',
  output: 'output',
  fields: 'output',
  eval: 'transform',
  rex: 'transform',
  extract: 'transform',
  regex: 'transform',
  rename: 'transform',
  fillnull: 'transform',
  bin: 'transform',
  bucket: 'transform',
  format: 'transform',
  sort: 'shaping',
  head: 'shaping',
  tail: 'shaping',
  dedup: 'shaping',
  uniq: 'shaping',
  sample: 'shaping',
  top: 'shaping',
  rare: 'shaping',
  reverse: 'shaping',
  timechart: 'visualization',
  chart: 'visualization',
};

/**
 * Split a query string on unquoted, unbracketed pipe characters.
 */
function splitOnPipes(query: string): string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inRegex = false;
  let parenDepth = 0;

  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    const prev = i > 0 ? query[i - 1] : '';

    if (ch === '\\') {
      current += ch + (query[i + 1] ?? '');
      i++;
      continue;
    }

    if (!inDoubleQuote && !inRegex && ch === "'") {
      inSingleQuote = !inSingleQuote;
    } else if (!inSingleQuote && !inRegex && ch === '"') {
      inDoubleQuote = !inDoubleQuote;
    } else if (!inSingleQuote && !inDoubleQuote && ch === '/' && prev !== '\\') {
      // Regex vs division: look at last non-whitespace char before the slash.
      // If it's alphanumeric, '_', ')' or ']' → division. Otherwise → regex start.
      if (inRegex) {
        inRegex = false;
      } else {
        let lastNonSpace = '';
        for (let k = i - 1; k >= 0; k--) {
          if (!/\s/.test(query[k])) {
            lastNonSpace = query[k];
            break;
          }
        }
        if (i === 0 || (lastNonSpace && !/[\w)\]]/.test(lastNonSpace))) {
          inRegex = true;
        }
      }
    }

    if (!inSingleQuote && !inDoubleQuote && !inRegex) {
      if (ch === '(') parenDepth++;
      else if (ch === ')') parenDepth = Math.max(0, parenDepth - 1);
    }

    if (ch === '|' && !inSingleQuote && !inDoubleQuote && !inRegex && parenDepth === 0) {
      segments.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }

  if (current.trim()) {
    segments.push(current.trim());
  }

  return segments;
}

/**
 * Strip comments from query text.
 */
function stripComments(query: string): string {
  // Remove block comments
  let result = query.replace(/\/\*[\s\S]*?\*\//g, '');
  // Remove line comments (but not inside strings — simplified: just from start of line)
  result = result
    .split('\n')
    .map((line) => {
      const idx = line.indexOf('//');
      if (idx === -1) return line;
      // Make sure // isn't inside a string (simplified check)
      const before = line.slice(0, idx);
      const singleQuotes = (before.match(/'/g) || []).length;
      const doubleQuotes = (before.match(/"/g) || []).length;
      if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0) {
        return before;
      }
      return line;
    })
    .join('\n');
  return result;
}

/**
 * Extract the leading command keyword from a pipe segment.
 */
function extractCommand(segment: string): { command: string; rest: string } {
  const match = segment.match(/^(\w+)\s*(.*)/s);
  if (!match) return { command: '', rest: segment };
  const word = match[1].toLowerCase();
  if (PIPE_COMMANDS_SET.has(word)) {
    return { command: word, rest: match[2] };
  }
  return { command: '', rest: segment };
}

/**
 * Classify a command into a stage category.
 */
function classifyCommand(command: string): StageCategory {
  return CATEGORY_MAP[command] || 'advanced';
}

/**
 * Generate a human-readable label for a pipe stage.
 */
function generateLabel(command: string, rest: string, _category: StageCategory): string {
  const trimmed = rest.trim();

  switch (command) {
    case 'where':
    case 'search': {
      if (trimmed.length <= 50) return trimmed;
      return trimmed.slice(0, 47) + '...';
    }
    case 'stats':
    case 'streamstats':
    case 'eventstats': {
      // Extract aggregation functions and "by" clause
      const byMatch = trimmed.match(/\bby\s+(.+)/i);
      const aggPart = byMatch ? trimmed.slice(0, byMatch.index).trim() : trimmed;
      const byPart = byMatch ? byMatch[1].trim() : '';
      const label = aggPart.length > 30 ? aggPart.slice(0, 27) + '...' : aggPart;
      return byPart ? `${label} by ${byPart.length > 20 ? byPart.slice(0, 17) + '...' : byPart}` : label;
    }
    case 'prevalence': {
      // Show key params
      const params: string[] = [];
      const enrichMatch = trimmed.match(/enrich\s*=\s*(\w+)/i);
      const windowMatch = trimmed.match(/window\s*=\s*(\S+)/i);
      if (enrichMatch) params.push(`enrich=${enrichMatch[1]}`);
      if (windowMatch) params.push(`window=${windowMatch[1]}`);
      return params.length ? params.join(' ') : trimmed.slice(0, 40);
    }
    case 'risk': {
      const scoreMatch = trimmed.match(/score\s*=\s*(\S+)/i);
      const entityMatch = trimmed.match(/entity\s*=\s*(\S+)/i);
      const parts: string[] = [];
      if (scoreMatch) parts.push(`score=${scoreMatch[1]}`);
      if (entityMatch) parts.push(`entity=${entityMatch[1]}`);
      return parts.length ? parts.join(' ') : trimmed.slice(0, 40);
    }
    case 'table':
    case 'fields': {
      if (trimmed.length <= 50) return trimmed;
      return trimmed.slice(0, 47) + '...';
    }
    case 'eval': {
      // Show the assignment target
      const eqMatch = trimmed.match(/^(\w+)\s*=/);
      if (eqMatch) return `${eqMatch[1]} = ...`;
      if (trimmed.length <= 40) return trimmed;
      return trimmed.slice(0, 37) + '...';
    }
    case 'sort': {
      if (trimmed.length <= 40) return trimmed;
      return trimmed.slice(0, 37) + '...';
    }
    case 'head':
    case 'tail':
    case 'sample': {
      return trimmed || '10';
    }
    case 'timechart':
    case 'chart': {
      const spanMatch = trimmed.match(/span\s*=\s*(\S+)/i);
      const span = spanMatch ? `span=${spanMatch[1]} ` : '';
      const aggMatch = trimmed.replace(/span\s*=\s*\S+/i, '').trim();
      return `${span}${aggMatch.length > 30 ? aggMatch.slice(0, 27) + '...' : aggMatch}`;
    }
    default: {
      if (trimmed.length <= 40) return trimmed;
      return trimmed.slice(0, 37) + '...';
    }
  }
}

/**
 * Generate source node label from the first segment.
 */
function generateSourceLabel(segment: string): { label: string; description: string } {
  // Look for source_type= or sourcetype=
  const stMatch = segment.match(/source_?type\s*=\s*"?([^"\s|]+)"?/i);
  if (stMatch) {
    return {
      label: stMatch[1].replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      description: segment.length > 60 ? segment.slice(0, 57) + '...' : segment,
    };
  }
  // Short search term
  if (segment.length <= 40) {
    return { label: segment || 'All Events', description: '' };
  }
  return { label: segment.slice(0, 37) + '...', description: segment };
}

/**
 * Detect branching patterns: 2+ consecutive where+risk pairs after enrichment.
 * Only enrichment stages (prevalence, lookup, etc.) produce truly parallel
 * scoring paths. Sequential risk escalation chains stay linear.
 */
function detectBranches(stages: PipeStage[]): Branch[] {
  const branches: Branch[] = [];

  for (let i = 0; i < stages.length - 1; i++) {
    if (stages[i].category !== 'enrichment') continue;

    // Look for consecutive where+risk pairs starting at i+1
    const pairs: number[][] = [];
    let j = i + 1;

    while (j < stages.length - 1) {
      if (stages[j].command === 'where' && stages[j + 1].command === 'risk') {
        pairs.push([j, j + 1]);
        j += 2;
      } else {
        break;
      }
    }

    if (pairs.length >= 2) {
      branches.push({
        sourceIndex: i,
        paths: pairs,
        mergeIndex: j < stages.length ? j : stages.length - 1,
      });
      // Skip past the branch
      i = j - 1;
    }
  }

  return branches;
}

/**
 * Parse an nPL query string into a FlowGraph.
 */
export function parseNplFlow(query: string): FlowGraph {
  if (!query || !query.trim()) {
    return { stages: [], branches: [] };
  }

  const cleaned = stripComments(query);
  const segments = splitOnPipes(cleaned);

  if (segments.length === 0) {
    return { stages: [], branches: [] };
  }

  const stages: PipeStage[] = segments.map((segment, index) => {
    if (index === 0) {
      const { label, description } = generateSourceLabel(segment);
      return {
        id: `stage-${index}`,
        index,
        command: 'source',
        rawText: segment,
        category: 'source' as StageCategory,
        label,
        description,
      };
    }

    const { command, rest } = extractCommand(segment);
    const category = command ? classifyCommand(command) : 'advanced';
    const label = command ? generateLabel(command, rest, category) : segment.slice(0, 40);

    return {
      id: `stage-${index}`,
      index,
      command: command || segment.split(/\s/)[0] || 'unknown',
      rawText: segment,
      category,
      label,
      description: segment.length > 60 ? segment.slice(0, 57) + '...' : segment,
    };
  });

  const branches = detectBranches(stages);

  return { stages, branches };
}
