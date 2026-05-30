// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useRef, useCallback, useEffect, useState, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useScrollContainer } from '@/contexts/ScrollContainerContext';
import { useIsMobile } from '@/hooks/use-mobile';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import {
  ChevronDown,
  ChevronRight,
  Search as SearchIcon,
  Plus,
  Minus,
  Copy,
  Check,
  Loader2,
  Download,
  BookOpen,
  GitBranch,
  Network,
  ChartColumn,
  PanelRight,
  Rows3,
  ExternalLink,
} from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { cn } from '@/lib/utils';
import { EventInspectorPanel } from './EventInspectorPanel';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Checkbox } from '@/components/ui/checkbox';
import { Filter, Clock } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { formatUTCShort, formatCompactNumber } from '@/lib/date-utils';
// Types needed synchronously for casting (type-only imports don't affect bundling)
import type { TreeNode, TreeConfig } from './TreeVisualization';

// Heavy visualization components — lazy-loaded since only one renders at a time
const TreeVisualization = lazy(() => import('./TreeVisualization').then(m => ({ default: m.TreeVisualization })));
const PaginatedTable = lazy(() => import('./PaginatedTable').then(m => ({ default: m.PaginatedTable })));
const TimechartView = lazy(() => import('./TimechartView').then(m => ({ default: m.TimechartView })));
const RankedBarChart = lazy(() => import('./RankedBarChart').then(m => ({ default: m.RankedBarChart })));
const TransactionCards = lazy(() => import('./TransactionCards').then(m => ({ default: m.TransactionCards })));
const FlowVisualization = lazy(() => import('./FlowVisualization').then(m => ({ default: m.FlowVisualization })));
const SequenceView = lazy(() => import('./SequenceView').then(m => ({ default: m.SequenceView })));
const FunnelView = lazy(() => import('./FunnelView').then(m => ({ default: m.FunnelView })));
const AssetView = lazy(() => import('./asset').then(m => ({ default: m.AssetView })));
const CloudOverviewView = lazy(() => import('./cloud-overview').then(m => ({ default: m.CloudOverviewView })));
const CloudPrincipalDossier = lazy(() => import('./cloud-dossier').then(m => ({ default: m.CloudPrincipalDossier })));
const LateralView = lazy(() => import('./lateral').then(m => ({ default: m.LateralView })));
const StatsView = lazy(() => import('./StatsView').then(m => ({ default: m.StatsView })));
import { UDM_COLUMNS } from '@/lib/udm-fields';
import { isClickHouseDefault } from '@/lib/utils';

// ============================================================================
// Detail view mode — persisted to localStorage
// ============================================================================

type DetailViewMode = 'panel' | 'inline';

const DETAIL_VIEW_MODE_KEY = 'nanosiem-detail-view-mode';

function getDetailViewMode(): DetailViewMode {
  try {
    const saved = localStorage.getItem(DETAIL_VIEW_MODE_KEY);
    if (saved === 'panel' || saved === 'inline') return saved;
  } catch {}
  return 'panel';
}

// ============================================================================
// Field utility functions (for inline expand view)
// ============================================================================

function flattenFieldsForExpand(fields: Record<string, unknown>, prefix = ''): [string, unknown][] {
  const result: [string, unknown][] = [];
  for (const [key, value] of Object.entries(fields)) {
    const fullKey = prefix ? `${prefix}_${key}` : key;
    if (key.startsWith('prevalence_') && (value === 255 || value === 65535 || value === 9999)) continue;
    if (key === 'risk_score' && (value === 0 || value === '0')) continue;
    const isPrevalence = key === 'host_count' || key === 'is_rare' || key === 'prevalence_score' ||
                         key === 'prevalence_type' || key === '_prevalence' || key.startsWith('_prevalence.');
    if (!isPrevalence && isClickHouseDefault(value, key)) continue;
    if (key === 'metadata') {
      let metadataObj: Record<string, unknown> | null = null;
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        metadataObj = value as Record<string, unknown>;
      } else if (typeof value === 'string' && value.startsWith('{')) {
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed === 'object' && !Array.isArray(parsed)) metadataObj = parsed;
        } catch { /* not JSON */ }
      }
      if (metadataObj) {
        result.push(...flattenFieldsForExpand(metadataObj, 'metadata'));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (key === '_prevalence') {
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        result.push(...flattenFieldsForExpand(value as Record<string, unknown>, '_prevalence'));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else {
      result.push([fullKey, value]);
    }
  }
  const getFieldCategory = (fieldName: string): number => {
    if (fieldName === 'risk_score' || fieldName === 'risk_entity' ||
        fieldName === 'risk_factors' || fieldName.startsWith('risk_')) return 1;
    if (fieldName.startsWith('ioc_')) return 2;
    if (fieldName.includes('_identity_') || fieldName.startsWith('identity_') || fieldName === 'is_nat_candidate') return 3;
    if (fieldName.startsWith('prevalence_') || fieldName === '_prevalence' ||
        fieldName.startsWith('_prevalence.') || fieldName === 'host_count' ||
        fieldName === 'is_rare' || fieldName === 'prevalence_score' ||
        fieldName === 'prevalence_type' || fieldName === 'prevalence_artifact' ||
        fieldName === 'total_occurrences' || fieldName === 'first_seen' ||
        fieldName === 'last_seen') return 4;
    if (fieldName.startsWith('lookup_')) return 5;
    if (fieldName.startsWith('enriched_')) return 6;
    if (fieldName.startsWith('metadata_')) return 7;
    if (!UDM_COLUMNS.has(fieldName)) return 8;
    return 0;
  };
  return result.sort((a, b) => {
    const catA = getFieldCategory(a[0]);
    const catB = getFieldCategory(b[0]);
    if (catA !== catB) return catA - catB;
    return a[0].localeCompare(b[0]);
  });
}

function isIocFieldExpand(fieldName: string): boolean {
  return fieldName.startsWith('ioc_');
}

function isRiskFieldExpand(fieldName: string): boolean {
  return fieldName === 'risk_score' || fieldName === 'risk_entity' || fieldName === 'risk_factors';
}

function isPrevalenceFieldExpand(fieldName: string): boolean {
  return fieldName === 'host_count' || fieldName === 'is_rare' ||
         fieldName === 'prevalence_score' || fieldName === 'prevalence_type' ||
         fieldName === 'prevalence_artifact' || fieldName === 'total_occurrences' ||
         fieldName === 'first_seen' || fieldName === 'last_seen' ||
         fieldName === '_prevalence' || fieldName.startsWith('_prevalence.') ||
         fieldName === 'prevalence_file_hash' || fieldName === 'prevalence_process_hash' ||
         fieldName === 'prevalence_dest_domain' || fieldName === 'prevalence_dest_ip' ||
         fieldName === 'prevalence_min';
}


const ENRICHMENT_CATEGORIES_EXPAND: Record<string, (k: string) => boolean> = {
  ioc: (k) => k.startsWith('ioc_'),
  custom: (k) => k.startsWith('lookup_custom_'),
  prevalence: (k) => isPrevalenceFieldExpand(k),
  lookup: (k) => k.startsWith('lookup_') && !k.startsWith('lookup_custom_'),
  geo: (k) => k.startsWith('enriched_'),
  identity: (k) => k.includes('_identity_') || k.startsWith('identity_') || k === 'is_nat_candidate',
  metadata: (k) => k.startsWith('metadata_'),
};

function isFieldHiddenExpand(fieldName: string, hiddenEnrichments: Set<string>): boolean {
  for (const [category, check] of Object.entries(ENRICHMENT_CATEGORIES_EXPAND)) {
    if (hiddenEnrichments.has(category) && check(fieldName)) return true;
  }
  return false;
}

// ============================================================================
// Query Parsing Utilities
// ============================================================================

// Extract base query (before pipe commands), being careful not to split on | inside quotes
const getBaseSearch = (q: string): string => {
  let inQuote = false;
  let escapeNext = false;

  for (let i = 0; i < q.length; i++) {
    const c = q[i];

    if (escapeNext) {
      escapeNext = false;
      continue;
    }

    if (c === '\\') {
      escapeNext = true;
      continue;
    }

    if (c === '"') {
      inQuote = !inQuote;
      continue;
    }

    if (c === '|' && !inQuote) {
      return q.substring(0, i).trim();
    }
  }

  return q.trim();
};

// ============================================================================
// Keyword Highlighting Utilities
// ============================================================================

/**
 * Extract keywords from a search query for highlighting.
 * Only extracts free-text keywords, not field=value patterns.
 *
 * Examples:
 * - "c2 beacon" → ["c2", "beacon"]
 * - "src_ip=192.168.1.1" → []
 * - "malware src_ip=10.0.0.1" → ["malware"]
 * - '"exact phrase"' → ["exact phrase"]
 */
function extractKeywordsFromQuery(query: string | undefined): string[] {
  if (!query || !query.trim()) return [];

  // Only extract highlight terms from the search portion (before first pipe).
  // Everything after a pipe is a transformation command (stats, where, table, etc.)
  // and should not generate highlights — those tokens are commands, not search text.
  const searchPortion = query.split('|')[0];
  if (!searchPortion.trim()) return [];

  const keywords: string[] = [];
  const fieldValueRegex = /(\w+)\s*(?:!=|=|<=|>=|<|>)\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|\/((?:\\.|[^/\\])*)\/|(\S+))/g;
  const unescapeQuoted = (value: string): string =>
    value.replace(/\\(["'\\])/g, '$1');

  // Extract values from field=value patterns for highlighting
  // Matches: field="value", field='value', field=value, field=/regex/, field!="value", etc.
  // Skip sourcetype/source_type fields as they're common filters, not search terms
  let match;
  while ((match = fieldValueRegex.exec(searchPortion)) !== null) {
    const fieldName = match[1]?.toLowerCase();
    // Skip sourcetype/source_type - these are filter fields, not search keywords
    if (fieldName === 'sourcetype' || fieldName === 'source_type') {
      continue;
    }
    // match[2] = quoted with ", match[3] = quoted with ', match[4] = regex, match[5] = unquoted
    let value = match[2] || match[3] || match[4] || match[5];
    if (value && value.trim()) {
      value = unescapeQuoted(value);
      // Strip leading/trailing wildcards for highlighting (e.g., *powershell* -> powershell)
      value = value.trim().replace(/^\*+|\*+$/g, '');
      if (value) {
        keywords.push(value);
      }
    }
  }

  // Also extract free-text keywords (not part of field=value)
  // Remove field=value patterns first
  fieldValueRegex.lastIndex = 0;
  const withoutFieldValues = searchPortion.replace(fieldValueRegex, ' ');

  // Remove field IN (...) patterns — extract quoted values as keywords first
  const inRegex = /\w+\s+IN\s*\(\s*((?:"[^"]*"|'[^']*'|[^)]*?))\s*\)/gi;
  let inMatch;
  const withoutIn = withoutFieldValues.replace(inRegex, (_fullMatch, valueList: string) => {
    // Extract quoted values from the IN list
    const quotedInRegex = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g;
    while ((inMatch = quotedInRegex.exec(valueList)) !== null) {
      const val = inMatch[1] || inMatch[2];
      if (val && val.trim()) keywords.push(unescapeQuoted(val.trim()));
    }
    return ' ';
  });

  // Remove operators
  const withoutOperators = withoutIn.replace(/\b(AND|OR|NOT|IN)\b/gi, ' ');

  // Extract quoted phrases
  const quotedRegex = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g;
  while ((match = quotedRegex.exec(withoutOperators)) !== null) {
    const phrase = match[1] || match[2];
    if (phrase && phrase.trim()) {
      keywords.push(unescapeQuoted(phrase.trim()));
    }
  }

  // Extract remaining words — strip parentheses and commas from tokens
  const withoutQuotes = withoutOperators.replace(/"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g, ' ');
  const words = withoutQuotes
    .replace(/[(),]/g, ' ')
    .split(/\s+/)
    .filter(w => w.trim().length > 0);
  keywords.push(...words);

  // Filter out noise: *, operators, empty, punctuation, and short pure numbers (e.g. "2", "10")
  // Short numbers cause excessive false-positive highlights across all results
  return [...new Set(keywords.filter(k =>
    k.length > 0 &&
    k !== '*' &&
    !/^[\\'"`]+$/.test(k) &&
    !/^[=<>!,()]+$/.test(k) &&
    !/^\d{1,4}$/.test(k)
  ))];
}

/**
 * Highlight keywords in text by wrapping them in <mark> elements.
 * Case-insensitive matching.
 */
function highlightText(text: string, keywords: string[]): React.ReactNode {
  if (!keywords.length || !text) return text;

  // Escape special regex characters in keywords
  const escapedKeywords = keywords.map(k =>
    k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  // Build regex that matches any keyword (case-insensitive)
  const regex = new RegExp(`(${escapedKeywords.join('|')})`, 'gi');
  const parts = text.split(regex);

  if (parts.length === 1) return text; // No matches

  return parts.map((part, i) => {
    const isMatch = keywords.some(k => k.toLowerCase() === part.toLowerCase());
    return isMatch ? (
      <mark key={i} className="bg-amber-200/80 text-amber-950 ring-1 ring-amber-500/40 dark:bg-amber-400/25 dark:text-amber-200 dark:ring-amber-400/30 rounded-[2px] px-0.5 py-px -my-px">
        {part}
      </mark>
    ) : (
      part
    );
  });
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

import type { DisplayType } from '@/lib/api/types';

function formatCacheAge(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m`;
}

interface SearchResultsProps {
  results: SearchResult[];
  totalCount: number;
  isSearching: boolean;
  hasSearched: boolean;
  /** @deprecated Use displayType instead */
  isAggregateQuery: boolean;
  /** Display type from backend for visualization routing */
  displayType?: DisplayType;
  histogramHasData?: boolean;
  query?: string;
  executedQuery?: string; // The query that was actually executed (for highlighting)
  onAddToQuery: (field: string, value: string, exclude: boolean) => void;
  onSetQuery?: (query: string) => void;
  onLoadMore: () => void;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  // Pagination for tabular views
  currentPage?: number;
  pageSize?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  // Notebook integration
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
  onAddAllEntitiesToNotebook?: (entities: Array<{ type: string; value: string }>) => void;
  // Table view mode - fetch full log on row expand
  onFetchLog?: (id: string, timestamp: Date, sourceType?: string) => Promise<Record<string, unknown> | null>;
  // Column order from backend (for | table command)
  columnOrder?: string[];
  // Asset prevalence filter (for filtering asset timeline by prevalence artifacts)
  assetPrevalenceFilter?: {
    artifacts: string[];
    filterType: 'include' | 'rare';
    timestamp?: number;
  } | null;
  // Time range for pagination requests (asset view)
  timeRange?: { start: string; end: string };
  // AI Analysis
  melodEnabled?: boolean;
  onSummarize?: () => void;
  // Async job state
  asyncJobId?: string | null;
  asyncJobStatus?: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | null;
  asyncJobProgress?: { rows_scanned: number; rows_total: number; percent: number; elapsed_ms: number } | null;
  queuePosition?: number | null;
  estimatedWait?: number | null;
  onCancelAsyncJob?: () => void;
  // SSE streaming state (results arriving incrementally)
  isStreamingResults?: boolean;
  // Cached results indicator
  cachedAt?: number | null;
  onRefreshCache?: () => void;
  // Fields panel collapse state — shows a "Fields" beacon pill in the Results
  // header when the Field Index is hidden, so the user can restore it.
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// Flatten object for CSV export
function flattenForCSV(obj: Record<string, unknown>, prefix = ''): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value === null || value === undefined) {
      result[fullKey] = '';
    } else if (typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenForCSV(value as Record<string, unknown>, fullKey));
    } else if (Array.isArray(value)) {
      result[fullKey] = JSON.stringify(value);
    } else {
      result[fullKey] = String(value);
    }
  }
  return result;
}

// Escape CSV value (handle commas, quotes, newlines)
function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

// Export results to CSV
function exportToCSV(results: SearchResult[], isAggregate: boolean) {
  if (results.length === 0) return;

  // Flatten all results
  const flattenedResults = results.map(r => {
    const base: Record<string, string> = {};
    if (!isAggregate) {
      base['id'] = r.id;
      base['timestamp'] = r.timestamp instanceof Date ? r.timestamp.toISOString() : String(r.timestamp);
      base['source'] = r.source;
    }
    const flattened = r.fields ? flattenForCSV(r.fields) : {};
    return { ...base, ...flattened };
  });

  // Get all unique columns
  const columns = new Set<string>();
  flattenedResults.forEach(row => {
    Object.keys(row).forEach(key => {
      columns.add(key);
    });
  });

  // Sort columns: id, timestamp, source first, then alphabetically
  const sortedColumns = Array.from(columns).sort((a, b) => {
    const order: Record<string, number> = { id: 0, timestamp: 1, source: 2 };
    const orderA = order[a] ?? 100;
    const orderB = order[b] ?? 100;
    if (orderA !== orderB) return orderA - orderB;
    return a.localeCompare(b);
  });

  // Build CSV
  const header = sortedColumns.map(escapeCSV).join(',');
  const rows = flattenedResults.map(row =>
    sortedColumns.map(col => escapeCSV(row[col] || '')).join(',')
  );
  const csv = [header, ...rows].join('\n');

  // Trigger download
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `nano-export-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// Field to entity type mapping for notebook
const FIELD_TO_ENTITY_TYPE: Record<string, string> = {
  src_ip: 'ip', dest_ip: 'ip', dst_ip: 'ip', source_ip: 'ip', client_ip: 'ip', server_ip: 'ip', dvc_ip: 'ip',
  dest_host: 'domain', dst_host: 'domain', url_domain: 'domain', domain: 'domain',
  src_host: 'host', hostname: 'host', dvc: 'host',
  user: 'user', user_name: 'user', username: 'user', src_user: 'user', dest_user: 'user',
  file_hash: 'hash', process_hash: 'hash', hash: 'hash', md5: 'hash', sha1: 'hash', sha256: 'hash',
  url: 'url', http_referrer: 'url',
};

// ============================================================================
// Field Value Menu - Click-to-open dropdown with contextual actions
// ============================================================================

type FieldType = 'ip' | 'hostname' | 'user' | 'hash' | 'domain' | 'process' | 'url' | 'generic';

// Detect field type based on field name
function getFieldType(fieldName: string): FieldType {
  const lower = fieldName.toLowerCase();

  // IDs are generic - no special actions (process_id, parent_process_id, session_id, etc.)
  if (lower.endsWith('_id') || lower === 'id' || lower.endsWith('_guid')) return 'generic';

  // IP addresses
  if (lower.includes('_ip') || lower === 'ip' || lower.endsWith('ip')) return 'ip';

  // Hostnames
  if (lower.includes('_host') || lower === 'hostname' || lower === 'dvc' || lower === 'computer_name' || lower === 'device_name') return 'hostname';

  // Users
  if (lower.includes('user') || lower === 'account' || lower === 'principal') return 'user';

  // Hashes
  if (lower.includes('hash') || lower === 'md5' || lower === 'sha1' || lower === 'sha256' || lower === 'sha512') return 'hash';

  // Domains
  if (lower === 'domain' || lower.includes('_domain') || lower === 'fqdn') return 'domain';

  // Processes (process_name, process_path, command_line, etc. - but not process_id)
  if (lower.includes('process') || lower === 'image' || lower === 'parent_image') return 'process';

  // URLs
  if (lower === 'url' || lower.includes('_url') || lower === 'http_referrer' || lower === 'uri') return 'url';

  return 'generic';
}

// Field value menu component
interface FieldValueMenuProps {
  fieldName: string;
  value: unknown;
  displayValue: string;
  onAddToQuery: (field: string, value: string, exclude: boolean) => void;
  onSetQuery?: (query: string) => void;
  query?: string;
  highlightKeywords?: string[];
  className?: string;
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
}

// NAN-955: types EntityPage (`/entities/:type/:value`) can actually resolve.
// FIELD_TO_ENTITY_TYPE is broader (covers `domain`/`hash`/`url`/etc. used by
// the notebook surface) but EntityPage's ENTITY_TYPE_TO_FIELD map only knows
// the three below; offering "Open entity page" for the others would land on
// a broken search query.
const ENTITY_PAGE_TYPES = new Set(['ip', 'host', 'user']);

// NAN-955: exported so StatsView (sibling component) can reuse the same
// popover on aggregated GROUP BY cells. Same affordances (Add to filter /
// Exclude / Copy value / Open entity page) regardless of whether the
// value comes from a raw event or a stats row.
export function FieldValueMenu({
  fieldName,
  value,
  displayValue,
  onAddToQuery,
  onSetQuery,
  query,
  highlightKeywords = [],
  className = '',
  notebookActive,
  onAddToNotebook,
}: FieldValueMenuProps) {
  const navigate = useNavigate();
  const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
  const fieldType = getFieldType(fieldName);
  const entityType = FIELD_TO_ENTITY_TYPE[fieldName.toLowerCase()];
  const canOpenEntityPage =
    !!entityType &&
    ENTITY_PAGE_TYPES.has(entityType) &&
    typeof value === 'string' &&
    value.trim().length > 0;

  // Escape value for query (handle quotes and special chars)
  const escapeValue = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  // Build prevalence query: base search + field filter + prevalence command
  const buildPrevalenceQuery = (field: string, val: string) => {
    const baseSearch = query ? getBaseSearch(query) : '';
    const prefix = baseSearch && baseSearch !== '*' ? `${baseSearch} ` : '';
    return `${prefix}${field}="${escapeValue(val)}" | prevalence enrich=true window=24h`;
  };

  // Check if query has host-level scoping (for process trees)
  const hasHostScope = (q: string | undefined): boolean => {
    if (!q) return false;
    const lower = q.toLowerCase();
    return /\bsrc_host\s*=/.test(lower) || /\bhostname\s*=/.test(lower) || /\bdvc\s*=/.test(lower);
  };

  // Check if query has session-level scoping (for web trees)
  const hasSessionScope = (q: string | undefined): boolean => {
    if (!q) return false;
    const lower = q.toLowerCase();
    return /\buser\s*=/.test(lower) || /\bsrc_user\s*=/.test(lower) || /\bsrc_ip\s*=/.test(lower) || /\bsrc_host\s*=/.test(lower);
  };

  // Extract only scope-relevant filters for tree queries
  // This prevents filtering out parent/child events needed for tree context
  const extractScopeFilters = (q: string | undefined, treeType: 'process' | 'web'): string => {
    if (!q) return '*';
    const base = getBaseSearch(q);
    if (!base || base === '*') return '*';

    // Fields to keep for each tree type
    const processScope = ['src_host', 'hostname', 'dvc', 'source_type', 'sourcetype', 'earliest', 'latest'];
    const webScope = ['user', 'src_user', 'src_ip', 'src_host', 'source_type', 'sourcetype', 'earliest', 'latest'];
    const keepFields = treeType === 'process' ? processScope : webScope;

    // Extract field=value patterns from query
    // Match: field="value", field='value', field=value, field=/regex/
    const filterRegex = /(\w+)\s*([!=<>]+)\s*(?:"[^"]*"|'[^']*'|\/[^/]*\/|\S+)/g;
    const filters: string[] = [];
    let match;

    while ((match = filterRegex.exec(base)) !== null) {
      const fieldName = match[0];
      const field = match[1].toLowerCase();
      if (keepFields.some(k => field === k || field.startsWith(k))) {
        filters.push(fieldName);
      }
    }

    return filters.length > 0 ? filters.join(' ') : '*';
  };

  // Contextual actions based on field type
  const getContextualActions = () => {
    const actions: Array<{
      label: string;
      icon: React.ReactNode;
      onClick: () => void;
    }> = [];

    switch (fieldType) {
      case 'ip':
        actions.push({
          label: 'Check prevalence',
          icon: <ChartColumn className="w-4 h-4" />,
          onClick: () => {
            if (onSetQuery) {
              onSetQuery(buildPrevalenceQuery(fieldName, stringValue));
            }
          },
        });
        break;

      case 'hostname':
        // dest_host/url_domain are remote servers - show web tree
        if (fieldName === 'dest_host' || fieldName === 'url_domain') {
          if (hasSessionScope(query)) {
            actions.push({
              label: 'Open as web tree',
              icon: <Network className="w-4 h-4" />,
              onClick: () => {
                if (onSetQuery) {
                  const scopeFilters = extractScopeFilters(query, 'web');
                  onSetQuery(`${scopeFilters} | tree web root=/${escapeValue(stringValue)}/`);
                }
              },
            });
          }
          actions.push({
            label: 'Check prevalence',
            icon: <ChartColumn className="w-4 h-4" />,
            onClick: () => {
              if (onSetQuery) {
                onSetQuery(buildPrevalenceQuery(fieldName, stringValue));
              }
            },
          });
        } else {
          // src_host or other hostnames - local machine, show process tree
          if (hasHostScope(query)) {
            actions.push({
              label: 'Open as process tree',
              icon: <GitBranch className="w-4 h-4" />,
              onClick: () => {
                if (onSetQuery) {
                  const scopeFilters = extractScopeFilters(query, 'process');
                  onSetQuery(`${scopeFilters} | tree process`);
                }
              },
            });
          }
        }
        break;

      case 'user':
        actions.push({
          label: 'Find all events',
          icon: <SearchIcon className="w-4 h-4" />,
          onClick: () => {
            if (onSetQuery) {
              onSetQuery(`user="${escapeValue(stringValue)}"`);
            }
          },
        });
        break;

      case 'hash':
        actions.push({
          label: 'Check prevalence',
          icon: <ChartColumn className="w-4 h-4" />,
          onClick: () => {
            if (onSetQuery) {
              onSetQuery(buildPrevalenceQuery(fieldName, stringValue));
            }
          },
        });
        break;

      case 'domain':
        if (hasSessionScope(query)) {
          actions.push({
            label: 'Open as web tree',
            icon: <Network className="w-4 h-4" />,
            onClick: () => {
              if (onSetQuery) {
                const scopeFilters = extractScopeFilters(query, 'web');
                onSetQuery(`${scopeFilters} | tree web root=/${escapeValue(stringValue)}/`);
              }
            },
          });
        }
        actions.push({
          label: 'Check prevalence',
          icon: <ChartColumn className="w-4 h-4" />,
          onClick: () => {
            if (onSetQuery) {
              onSetQuery(buildPrevalenceQuery(fieldName, stringValue));
            }
          },
        });
        break;

      case 'process':
        if (hasHostScope(query)) {
          actions.push({
            label: 'Open as process tree',
            icon: <GitBranch className="w-4 h-4" />,
            onClick: () => {
              if (onSetQuery) {
                const scopeFilters = extractScopeFilters(query, 'process');
                onSetQuery(`${scopeFilters} | tree process root=/${escapeValue(stringValue)}/`);
              }
            },
          });
        }
        break;

      case 'url':
        if (hasSessionScope(query)) {
          actions.push({
            label: 'Open as web tree',
            icon: <Network className="w-4 h-4" />,
            onClick: () => {
              if (onSetQuery) {
                const scopeFilters = extractScopeFilters(query, 'web');
                onSetQuery(`${scopeFilters} | tree web root=/${escapeValue(stringValue)}/`);
              }
            },
          });
        }
        break;
    }

    return actions;
  };

  const contextualActions = getContextualActions();
  const showContextualActions = contextualActions.length > 0 && onSetQuery;
  const [menuOpen, setMenuOpen] = React.useState(false);

  return (
    <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
      <DropdownMenuTrigger asChild>
        <span
          className={`cursor-pointer hover:underline ${className}`}
          onContextMenu={(e) => {
            e.preventDefault();
            setMenuOpen(true);
          }}
        >
          {highlightKeywords.length > 0 ? highlightText(displayValue, highlightKeywords) : displayValue}
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[200px] p-1">
        <DropdownMenuLabel className="px-2 py-1 text-[11px] tracking-normal normal-case text-muted-foreground font-normal break-all">
          {fieldName} ={' '}
          <span className="text-primary font-medium">{stringValue}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator className="-mx-1 my-1 h-px bg-border" />
        <DropdownMenuItem
          onClick={() => onAddToQuery(fieldName, stringValue, false)}
          className="gap-1.5 px-2 py-1 text-[12px]"
        >
          <Plus className="w-[13px] h-[13px]" />
          <span>Add to filter</span>
          <DropdownMenuShortcut className="text-[10.5px]">⏎</DropdownMenuShortcut>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => onAddToQuery(fieldName, stringValue, true)}
          className="gap-1.5 px-2 py-1 text-[12px]"
        >
          <Minus className="w-[13px] h-[13px]" />
          <span>Exclude</span>
          <DropdownMenuShortcut className="text-[10.5px]">⇧⏎</DropdownMenuShortcut>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => navigator.clipboard.writeText(stringValue)}
          className="gap-1.5 px-2 py-1 text-[12px]"
        >
          <Copy className="w-[13px] h-[13px]" />
          <span>Copy value</span>
          <DropdownMenuShortcut className="text-[10.5px]">⌘C</DropdownMenuShortcut>
        </DropdownMenuItem>

        {/* NAN-955: drill to the entity dossier page when the field maps to
            a type EntityPage can resolve (ip / host / user). Other entityTypes
            in FIELD_TO_ENTITY_TYPE (domain / hash / url) are notebook-only
            today — exposing them here would land on a broken search query. */}
        {canOpenEntityPage && (
          <DropdownMenuItem
            onClick={() => navigate(`/entities/${entityType}/${encodeURIComponent(stringValue)}`)}
            className="gap-1.5 px-2 py-1 text-[12px]"
          >
            <ExternalLink className="w-[13px] h-[13px]" />
            <span>Open entity page</span>
          </DropdownMenuItem>
        )}

        {/* Add to notebook if available */}
        {notebookActive && onAddToNotebook && entityType && typeof value === 'string' && value.trim() && (
          <DropdownMenuItem
            data-notebook-action
            onClick={() => onAddToNotebook(entityType, value)}
            className="gap-1.5 px-2 py-1 text-[12px]"
          >
            <BookOpen className="w-[13px] h-[13px]" />
            <span>Add to notebook</span>
          </DropdownMenuItem>
        )}

        {/* Contextual actions */}
        {showContextualActions && (
          <>
            <DropdownMenuSeparator className="-mx-1 my-1 h-px bg-border" />
            {contextualActions.map((action, idx) => (
              <DropdownMenuItem
                key={idx}
                onClick={action.onClick}
                className="gap-1.5 px-2 py-1 text-[12px]"
              >
                {action.icon}
                {action.label}
              </DropdownMenuItem>
            ))}
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// Extract entities from search results
function extractEntitiesFromResults(results: SearchResult[]): Array<{ type: string; value: string }> {
  const entities = new Map<string, { type: string; value: string }>();

  for (const result of results.slice(0, 100)) { // Limit to first 100 results
    if (!result.fields) continue;

    for (const [field, value] of Object.entries(result.fields)) {
      if (typeof value !== 'string' || !value.trim()) continue;

      const fieldLower = field.toLowerCase();
      const entityType = FIELD_TO_ENTITY_TYPE[fieldLower];

      if (entityType) {
        const key = `${entityType}:${value}`;
        if (!entities.has(key)) {
          entities.set(key, { type: entityType, value });
        }
      }
    }
  }

  return Array.from(entities.values()).slice(0, 50); // Limit to 50 unique entities
}

export function SearchResults({
  results,
  totalCount,
  isSearching,
  hasSearched,
  isAggregateQuery,
  displayType,
  histogramHasData,
  query,
  executedQuery,
  onAddToQuery,
  onSetQuery,
  onLoadMore,
  onDrilldown,
  currentPage,
  pageSize,
  onPageChange,
  onPageSizeChange,
  notebookActive,
  onAddToNotebook,
  onAddAllEntitiesToNotebook,
  onFetchLog,
  columnOrder,
  assetPrevalenceFilter,
  timeRange,
  melodEnabled,
  onSummarize,
  asyncJobId,
  asyncJobStatus,
  asyncJobProgress,
  queuePosition,
  estimatedWait,
  onCancelAsyncJob,
  isStreamingResults: _isStreamingResults,
  cachedAt,
  onRefreshCache,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: SearchResultsProps) {
  // Determine effective display type - prefer backend hint, fall back to isAggregateQuery
  const effectiveDisplayType: DisplayType = displayType ?? (isAggregateQuery ? 'table' : 'events');

  // Stats queries get a dedicated view (sortable bar-in-cell table) that owns its
  // own chrome — so when this is true we skip the outer card header and padding.
  const isStatsView =
    effectiveDisplayType === 'table' && /\|\s*stats\s+/i.test(executedQuery ?? query ?? '');

  // Views that render their own header chrome (per the redesign mockups)
  // suppress the outer card header so we don't stack two headers.
  const embeddedHeaderView =
    isStatsView ||
    effectiveDisplayType === 'timechart' ||
    effectiveDisplayType === 'ranked_bar' ||
    effectiveDisplayType === 'transaction';

  // ── Detail view mode (panel vs inline) ─────────────────────────────────
  const isMobile = useIsMobile();
  const [detailViewModeRaw, setDetailViewModeRaw] = React.useState<DetailViewMode>(getDetailViewMode);
  // Force inline mode on mobile — side panel doesn't fit
  const detailViewMode = isMobile ? 'inline' : detailViewModeRaw;
  const toggleDetailViewMode = React.useCallback(() => {
    setDetailViewModeRaw(prev => {
      const next = prev === 'panel' ? 'inline' : 'panel';
      localStorage.setItem(DETAIL_VIEW_MODE_KEY, next);
      return next;
    });
    // Clear inspector selection when switching modes
    setSelectedEvent(null);
  }, []);

  // ── Inspector panel state ──────────────────────────────────────────────
  const [selectedEvent, setSelectedEvent] = React.useState<SearchResult | null>(null);
  const [selectedEventIndex, setSelectedEventIndex] = React.useState<number>(0);
  // Shared full log data cache — populated by RawView hover-prefetch, consumed by inspector
  const [sharedFullLogData, setSharedFullLogData] = React.useState<Map<string, Record<string, unknown>>>(new Map());
  const [sharedLoadingLogs, setSharedLoadingLogs] = React.useState<Set<string>>(new Set());
  const sharedFullLogDataRef = React.useRef(sharedFullLogData);
  sharedFullLogDataRef.current = sharedFullLogData;
  const sharedLoadingLogsRef = React.useRef(sharedLoadingLogs);
  sharedLoadingLogsRef.current = sharedLoadingLogs;

  // Prefetch full log data — called by RawView on hover and by inspector on selection.
  // sourceType (NAN-1032) lets the backend use the (source_type, timestamp, ...) PK
  // for a tight range read on S3-backed historical partitions.
  const sharedPrefetchLog = React.useCallback((id: string, logId?: string, timestamp?: Date, sourceType?: string) => {
    if (!onFetchLog || !logId || !timestamp || sharedFullLogDataRef.current.has(id) || sharedLoadingLogsRef.current.has(id)) return;
    setSharedLoadingLogs(prev => new Set(prev).add(id));
    onFetchLog(logId, timestamp, sourceType)
      .then(fullData => {
        if (fullData) {
          setSharedFullLogData(prev => new Map(prev).set(id, fullData));
        }
      })
      .catch(error => {
        console.error('Failed to fetch full log:', error);
      })
      .finally(() => {
        setSharedLoadingLogs(prev => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      });
  }, [onFetchLog]);

  const handleSelectEvent = React.useCallback((event: SearchResult, index: number) => {
    setSelectedEvent(event);
    setSelectedEventIndex(index);
    // Trigger full data fetch for the selected event
    sharedPrefetchLog(event.id, event.fields?.id as string, event.timestamp, event.fields?.source_type as string | undefined);
  }, [sharedPrefetchLog]);

  const handleCloseInspector = React.useCallback(() => {
    setSelectedEvent(null);
  }, []);

  const handleInspectorNavigate = React.useCallback((direction: 'prev' | 'next') => {
    const newIndex = direction === 'prev'
      ? Math.max(0, selectedEventIndex - 1)
      : Math.min(results.length - 1, selectedEventIndex + 1);
    if (newIndex !== selectedEventIndex && results[newIndex]) {
      const event = results[newIndex];
      setSelectedEvent(event);
      setSelectedEventIndex(newIndex);
      sharedPrefetchLog(event.id, event.fields?.id as string, event.timestamp, event.fields?.source_type as string | undefined);
    }
  }, [selectedEventIndex, results, sharedPrefetchLog]);

  // Preserve the inspector across incremental result appends.
  // Only clear selection/cache when the selected event is no longer present,
  // which indicates a genuinely new result set rather than infinite-scroll growth.
  React.useEffect(() => {
    if (!selectedEvent) {
      setSharedFullLogData(new Map());
      setSharedLoadingLogs(new Set());
      return;
    }

    const nextIndex = results.findIndex(result => result.id === selectedEvent.id);
    if (nextIndex >= 0) {
      setSelectedEvent(results[nextIndex]);
      setSelectedEventIndex(nextIndex);
      return;
    }

    setSelectedEvent(null);
    setSharedFullLogData(new Map());
    setSharedLoadingLogs(new Set());
  }, [results, selectedEvent]);

  // Enrichment visibility preferences - persisted to localStorage
  const [hiddenEnrichments, setHiddenEnrichments] = React.useState<Set<string>>(() => {
    try {
      const saved = localStorage.getItem('nanosiem-hidden-enrichments');
      if (saved) {
        return new Set(JSON.parse(saved));
      }
    } catch {}
    // Default: hide lookup tables and metadata
    return new Set(['lookup', 'metadata']);
  });

  // Save to localStorage when changed
  React.useEffect(() => {
    localStorage.setItem('nanosiem-hidden-enrichments', JSON.stringify([...hiddenEnrichments]));
  }, [hiddenEnrichments]);

  const toggleEnrichmentCategory = (category: string) => {
    setHiddenEnrichments(prev => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const [expandAllCells, setExpandAllCells] = React.useState(true);

  // Extract entities for bulk add
  const extractedEntities = React.useMemo(() => {
    if (!notebookActive || !onAddAllEntitiesToNotebook) return [];
    return extractEntitiesFromResults(results);
  }, [results, notebookActive, onAddAllEntitiesToNotebook]);

  // Check if aggregate results have any long values (for showing expand toggle)
  const hasExpandableCells = React.useMemo(() => {
    if (effectiveDisplayType === 'events' || results.length === 0) return false;
    return results.some(result =>
      result.fields && Object.values(result.fields).some(value => {
        const displayValue = value === null || value === undefined ? '' :
          typeof value === 'object' ? JSON.stringify(value) : String(value);
        return displayValue.length > 20;
      })
    );
  }, [effectiveDisplayType, results]);

  const isInspectorOpen = selectedEvent !== null && effectiveDisplayType === 'events' && detailViewMode === 'panel';

  return (
    <div className={`flex w-full min-w-0 ${isInspectorOpen ? 'items-start' : ''}`}>
    <Card className={`search-workspace-section bg-card border border-border min-w-0 overflow-hidden flex flex-col ${
      isInspectorOpen ? 'flex-1 rounded-l-lg rounded-r-none border-r-0' : 'w-full rounded-lg'
    }`}>
      <CardContent className="p-0 w-full min-w-0 flex flex-col min-h-0">
        {!embeddedHeaderView && (
        <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-1.5 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
          <span className="mr-1">Results</span>
          {fieldsCollapsed && onExpandFields && (
            <button
              onClick={onExpandFields}
              className="inline-flex items-center gap-1.5 py-1 px-2 rounded-md border border-primary/25 bg-primary/8 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/14 transition-colors normal-case tracking-normal shrink-0"
              title="Show field index"
            >
              <span className="relative flex w-[7px] h-[7px] items-center justify-center">
                <span className="absolute inset-0 rounded-full bg-primary/50 animate-ping" />
                <span className="relative w-[4px] h-[4px] rounded-full bg-primary" />
              </span>
              <span className="font-mono uppercase tracking-[0.12em] text-[9.5px]">Fields</span>
              {fieldsCount !== undefined && (
                <span className="text-primary/70 tabular-nums text-[10px]">{fieldsCount}</span>
              )}
              <ChevronRight className="w-[10px] h-[10px]" />
            </button>
          )}
          <div className="contents">
            {/* Cached results indicator */}
            {cachedAt && onRefreshCache && (
              <button
                onClick={onRefreshCache}
                className="text-amber-500 dark:text-amber-400 text-xs hover:underline cursor-pointer"
                title="Click to refresh from server"
              >
                cached {formatCacheAge(cachedAt)} ago · refresh
              </button>
            )}
            {/* AI Analysis button */}
            {melodEnabled && onSummarize && results.length > 0 && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={onSummarize}
                      className="h-7 px-2 gap-1.5 text-foreground/70 hover:text-foreground hover:bg-accent/50"
                    >
                      <PivtIcon className="w-3.5 h-3.5" />
                      <span className="text-xs hidden md:inline">Analyze</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="bg-card border-border text-xs">
                    <p>Generate AI analysis of these results</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
            {/* Panel/Inline toggle - hidden on mobile (forced to inline) */}
            {effectiveDisplayType === 'events' && !isMobile && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={toggleDetailViewMode}
                      className={`h-7 px-2 gap-1.5 text-muted-foreground hover:text-primary hover:bg-accent`}
                    >
                      {detailViewMode === 'panel' ? (
                        <PanelRight className="w-3.5 h-3.5" />
                      ) : (
                        <Rows3 className="w-3.5 h-3.5" />
                      )}
                      <span className="text-xs">{detailViewMode === 'panel' ? 'Panel' : 'Inline'}</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="bg-card border-border text-xs">
                    <p>Switch to {detailViewMode === 'panel' ? 'inline expand' : 'side panel'} view</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
            {effectiveDisplayType === 'events' && (
              <Popover>
                <PopoverTrigger asChild>
                  <button
                    className="py-1 px-2 inline-flex items-center gap-1.5 rounded-sm text-[10px] font-medium cursor-pointer transition-colors text-primary bg-primary/8 hover:bg-primary/14 normal-case tracking-normal"
                  >
                    <Filter className="w-[11px] h-[11px]" />
                    <span className="hidden md:inline">Enrichments</span>
                    <span className="rounded-lg text-[9px] px-1 font-bold bg-primary/15 text-primary">
                      {Object.keys(ENRICHMENT_CATEGORIES).length - hiddenEnrichments.size}
                    </span>
                  </button>
                </PopoverTrigger>
                <PopoverContent align="end" className="w-56 p-2">
                  <div className="space-y-1">
                    <div className="flex items-center justify-between px-2 py-1">
                      <span className="text-xs font-medium text-foreground">Show Enrichments</span>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-5 px-1.5 text-[10px]"
                          onClick={() => setHiddenEnrichments(new Set())}
                        >
                          All
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-5 px-1.5 text-[10px]"
                          onClick={() => setHiddenEnrichments(new Set(Object.keys(ENRICHMENT_CATEGORIES)))}
                        >
                          None
                        </Button>
                      </div>
                    </div>
                    <div className="border-t border-border my-1" />
                    {(Object.entries(ENRICHMENT_CATEGORIES) as [EnrichmentCategory, { label: string; description: string }][]).map(([key, { label, description }]) => (
                      <label
                        key={key}
                        className="flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-accent cursor-pointer"
                      >
                        <Checkbox
                          checked={!hiddenEnrichments.has(key)}
                          onCheckedChange={() => toggleEnrichmentCategory(key)}
                          className="h-3.5 w-3.5"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium">{label}</div>
                          <div className="text-[10px] text-muted-foreground">{description}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </PopoverContent>
              </Popover>
            )}
            {/* Expand all toggle for tabular views with long values */}
            {effectiveDisplayType === 'table' && hasExpandableCells && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex items-center gap-1.5 mr-1">
                      <ChevronDown className={`w-3.5 h-3.5 ${expandAllCells ? 'text-primary' : 'text-muted-foreground'}`} />
                      <Switch
                        checked={expandAllCells}
                        onCheckedChange={setExpandAllCells}
                        className="data-[state=checked]:bg-primary h-4 w-7"
                      />
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="bg-card border-border text-xs">
                    <p>{expandAllCells ? 'Collapse' : 'Expand'} long cell values</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
            <span className="flex-1" aria-hidden />
            {effectiveDisplayType === 'tree' || results[0]?.fields?._display_type === 'tree' ? (
              <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px] font-medium tracking-wide normal-case">
                <GitBranch className="w-3 h-3" />
                Temporal Analysis
              </span>
            ) : (
              <span className="text-foreground/70 text-[11px] font-medium tracking-wide">
                {results.length}{totalCount > results.length ? ` of ${totalCount}` : ''} {effectiveDisplayType !== 'events' ? 'rows' : 'events'}
              </span>
            )}
            {results.length > 0 && (
              <>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => exportToCSV(results, isAggregateQuery)}
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-primary hover:bg-accent"
                      >
                        <Download className="w-4 h-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" className="bg-card border-border text-xs">
                      <p>Export to CSV</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                {/* Add entities to notebook button - only visible when notebook is active */}
                {notebookActive && onAddAllEntitiesToNotebook && extractedEntities.length > 0 && (
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          data-notebook-action
                          onClick={() => onAddAllEntitiesToNotebook(extractedEntities)}
                          className="h-7 w-7 p-0 text-amber-500 hover:text-amber-400 hover:bg-amber-500/10"
                        >
                          <BookOpen className="w-4 h-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" className="bg-card border-border text-xs">
                        <p>Add {extractedEntities.length} entities to notebook</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                )}
              </>
            )}
          </div>
        </div>
        )}

        <div className={cn(
          'flex-1 min-w-0',
          embeddedHeaderView
            ? 'flex flex-col min-h-0 overflow-hidden'
            : 'p-3 space-y-0 overflow-x-auto md:overflow-x-hidden',
        )}>
          {((isSearching || asyncJobId) && results.length === 0) ? (
            // Loading state while searching (includes async job progress and queue status)
            <div className="text-center py-16 bg-muted/50 rounded-xl border border-border">
              {asyncJobStatus === 'queued' ? (
                <>
                  <Clock className="w-12 h-12 text-amber-500/70 mx-auto mb-3" />
                  <p className="text-foreground text-base font-medium">Search queued</p>
                  <p className="text-muted-foreground text-sm mt-2">
                    {queuePosition ? (
                      <>Position {queuePosition} in queue</>
                    ) : (
                      <>Waiting for available slot...</>
                    )}
                  </p>
                  {estimatedWait != null && estimatedWait > 0 && (
                    <p className="text-xs text-muted-foreground mt-1">
                      ~{estimatedWait}s estimated wait
                    </p>
                  )}
                </>
              ) : (
                <>
                  <Loader2 className="w-12 h-12 text-primary/50 mx-auto mb-3 animate-spin" />
                  <p className="text-foreground text-base font-medium">Processing query...</p>
                  <p className="text-muted-foreground text-sm mt-2">
                    {asyncJobProgress ? (
                      asyncJobProgress.rows_total > 0 ? (
                        <>{formatCompactNumber(asyncJobProgress.rows_scanned)} of {formatCompactNumber(asyncJobProgress.rows_total)} rows scanned</>
                      ) : (
                        <>Scanning rows...</>
                      )
                    ) : query?.includes('| tree') ? (
                      <>Building tree visualization...</>
                    ) : (
                      <>Starting search...</>
                    )}
                  </p>
                  {asyncJobProgress && (
                    <div className="mt-4 flex flex-col items-center gap-2">
                      <div className="w-64 h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary transition-all duration-300"
                          style={{ width: `${asyncJobProgress.percent}%` }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {asyncJobProgress.percent}% complete · {(asyncJobProgress.elapsed_ms / 1000).toFixed(1)}s elapsed
                      </p>
                    </div>
                  )}
                </>
              )}
              {asyncJobId && onCancelAsyncJob && (
                <button
                  onClick={onCancelAsyncJob}
                  className="mt-4 px-3 py-1.5 text-sm border border-border rounded-md hover:bg-muted transition-colors"
                >
                  Cancel
                </button>
              )}
            </div>
          ) : results.length === 0 ? (
            <EmptyState
              hasSearched={hasSearched}
              isAggregateQuery={isAggregateQuery}
              histogramHasData={histogramHasData}
              query={query}
            />
          ) : (
            <Suspense fallback={<div className="flex items-center justify-center py-12"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>}>
            {effectiveDisplayType === 'tree' || results[0]?.fields?._display_type === 'tree' ? (
            // Tree visualization mode
            <TreeVisualization
              nodes={(results[0]?.fields?._tree_nodes as TreeNode[]) || []}
              config={(results[0]?.fields?._tree_config as TreeConfig) || { parent_field: '', child_field: '', label_field: '' }}
              onFilter={(field, value) => {
                // Tree clicks: keep base search, add filter, drop pipe commands
                const escapedValue = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
                const newFilter = `${field}="${escapedValue}"`;
                // Extract base search (before pipes) from current query
                const baseSearch = query ? getBaseSearch(query) : '';
                const newQuery = baseSearch ? `${baseSearch} ${newFilter}` : newFilter;
                if (onSetQuery) {
                  onSetQuery(newQuery);
                } else {
                  onAddToQuery(field, value, false);
                }
              }}
              fieldsCollapsed={fieldsCollapsed}
              fieldsCount={fieldsCount}
              onExpandFields={onExpandFields}
            />
          ) : effectiveDisplayType === 'timechart' ? (
            // Timechart: stacked area with cyan ramp, legend sidebar, span chip, pivot table
            <TimechartView
              results={results}
              query={executedQuery ?? query}
              onSetQuery={onSetQuery}
              onDrilldown={onDrilldown}
              fieldsCollapsed={fieldsCollapsed}
              fieldsCount={fieldsCount}
              onExpandFields={onExpandFields}
            />
          ) : effectiveDisplayType === 'ranked_bar' ? (
            // Ranked bar chart for | top / | rare commands
            <RankedBarChart
              results={results}
              query={executedQuery ?? query}
              onDrilldown={onDrilldown}
              fieldsCollapsed={fieldsCollapsed}
              fieldsCount={fieldsCount}
              onExpandFields={onExpandFields}
            />
          ) : effectiveDisplayType === 'transaction' ? (
            // Transaction cards for | transaction <fields> queries
            <TransactionCards
              results={results}
              query={executedQuery ?? query}
              onDrilldown={onDrilldown}
              fieldsCollapsed={fieldsCollapsed}
              fieldsCount={fieldsCount}
              onExpandFields={onExpandFields}
            />
          ) : effectiveDisplayType === 'flow' ? (
            // Sequence and Funnel both produce the "flow" display type; route
            // by the distinguishing metadata field each one emits.
            results[0]?.fields && 'sequence_count' in results[0].fields ? (
              <SequenceView
                results={results}
                query={executedQuery ?? query}
                fieldsCollapsed={fieldsCollapsed}
                fieldsCount={fieldsCount}
                onExpandFields={onExpandFields}
              />
            ) : results[0]?.fields && 'funnel_level' in results[0].fields ? (
              <FunnelView
                results={results}
                query={executedQuery ?? query}
                fieldsCollapsed={fieldsCollapsed}
                fieldsCount={fieldsCount}
                onExpandFields={onExpandFields}
              />
            ) : (
              <FlowVisualization
                results={results}
                onDrilldown={onDrilldown}
              />
            )
          ) : effectiveDisplayType === 'asset' || results[0]?.fields?._display_type === 'asset' ? (
            // Asset view for asset command
            <AssetView
              results={results}
              onDrilldown={onDrilldown}
              onAddToQuery={onAddToQuery}
              prevalenceFilter={assetPrevalenceFilter}
              timeRange={timeRange}
              onFetchLog={onFetchLog}
            />
          ) : effectiveDisplayType === 'cloud' || results[0]?.fields?._display_type === 'cloud' ? (
            // Cloud: overview (NAN-394) when no principal is scoped, otherwise
            // the principal dossier (NAN-395). The backend emits
            // `_cloud_principal` (and `_cloud_account`) onto the marker result
            // from `| cloud principal=X` so the dispatch is data-driven.
            typeof results[0]?.fields?._cloud_principal === 'string' &&
            (results[0].fields._cloud_principal as string).trim().length > 0 ? (
              <CloudPrincipalDossier
                principal={results[0].fields._cloud_principal as string}
                account={(results[0].fields._cloud_account as string | null) ?? null}
                timeRange={timeRange}
                query={executedQuery ?? query}
                fieldsCount={fieldsCollapsed ? fieldsCount : undefined}
                onExpandFields={onExpandFields}
                onAddToQuery={onAddToQuery}
                onSetQuery={onSetQuery}
              />
            ) : (
              <CloudOverviewView
                timeRange={timeRange}
                query={executedQuery ?? query}
                fieldsCount={fieldsCollapsed ? fieldsCount : undefined}
                onExpandFields={onExpandFields}
                onAddToQuery={onAddToQuery}
                onSetQuery={onSetQuery}
              />
            )
          ) : effectiveDisplayType === 'lateral' || results[0]?.fields?._display_type === 'lateral' ? (
            <LateralView
              results={results}
              query={executedQuery ?? query}
              onSetQuery={onSetQuery}
              onAddToQuery={onAddToQuery}
              fieldsCount={fieldsCollapsed ? fieldsCount : undefined}
              onExpandFields={onExpandFields}
            />
          ) : isStatsView ? (
            <StatsView
              results={results}
              query={executedQuery ?? query}
              columnOrder={columnOrder}
              fieldsCollapsed={fieldsCollapsed}
              fieldsCount={fieldsCount}
              onExpandFields={onExpandFields}
              onDownload={results.length > 0 ? () => exportToCSV(results, isAggregateQuery) : undefined}
              onAddToQuery={onAddToQuery}
              onSetQuery={onSetQuery}
              notebookActive={notebookActive}
              onAddToNotebook={onAddToNotebook}
            />
          ) : effectiveDisplayType === 'table' ? (
            // Paginated table for non-stats aggregations (| table, | top, etc.)
            <PaginatedTable
              results={results}
              totalCount={totalCount}
              currentPage={currentPage ?? 0}
              pageSize={pageSize ?? 50}
              onPageChange={onPageChange}
              onPageSizeChange={onPageSizeChange}
              onDrilldown={onDrilldown}
              expandAll={expandAllCells}
              notebookActive={notebookActive}
              onAddToNotebook={onAddToNotebook}
              columnOrder={columnOrder}
            />
          ) : (
            // Events view - raw log display with infinite scroll
            <RawView
              results={results}
              onAddToQuery={onAddToQuery}
              onSetQuery={onSetQuery}
              query={query}
              hiddenEnrichments={hiddenEnrichments}
              highlightKeywords={extractKeywordsFromQuery(executedQuery)}
              notebookActive={notebookActive}
              onAddToNotebook={onAddToNotebook}
              totalCount={totalCount}
              isSearching={isSearching}
              onLoadMore={onLoadMore}
              onFetchLog={onFetchLog}
              selectedEventId={selectedEvent?.id}
              onSelectEvent={handleSelectEvent}
              fullLogData={sharedFullLogData}
              loadingLogs={sharedLoadingLogs}
              onPrefetchLog={sharedPrefetchLog}
              detailViewMode={detailViewMode}
            />
          )}
            </Suspense>
          )}
        </div>

      </CardContent>
    </Card>
    {/* Event Inspector Panel - slides in from right when an event is selected */}
    {isInspectorOpen && selectedEvent && (
      <EventInspectorPanel
        event={selectedEvent}
        fullLogData={sharedFullLogData.get(selectedEvent.id)}
        isLoadingFullData={sharedLoadingLogs.has(selectedEvent.id)}
        onClose={handleCloseInspector}
        onNavigate={handleInspectorNavigate}
        onAddToQuery={onAddToQuery}
        onSetQuery={onSetQuery}
        query={query}
        highlightKeywords={extractKeywordsFromQuery(executedQuery)}
        notebookActive={notebookActive}
        onAddToNotebook={onAddToNotebook}
        hiddenEnrichments={hiddenEnrichments}
        eventIndex={selectedEventIndex}
        totalCount={totalCount}
        FieldValueMenu={FieldValueMenu}
      />
    )}
    </div>
  );
}

interface EmptyStateProps {
  hasSearched: boolean;
  isAggregateQuery?: boolean;
  histogramHasData?: boolean;
  query?: string;
}

function EmptyState({ hasSearched, isAggregateQuery, histogramHasData, query }: EmptyStateProps) {
  // Detect if query has a threshold (where clause with comparison)
  const hasThreshold = query?.toLowerCase().includes('| where') &&
    (query.includes('>') || query.includes('<') || query.includes('>=') || query.includes('<='));

  // Detect if query uses prevalence filtering
  const hasPrevalence = query?.toLowerCase().includes('| prevalence');

  return (
    <div className="text-center py-16 bg-muted/50 rounded-xl border border-border">
      {hasSearched ? (
        (isAggregateQuery || hasPrevalence) && histogramHasData ? (
          // Aggregation/prevalence query with data but no results above threshold
          <>
            <SearchIcon className="w-12 h-12 text-amber-500/50 mx-auto mb-3" />
            <p className="text-foreground text-base font-medium">No results matched your criteria</p>
            <p className="text-muted-foreground text-sm mt-2 max-w-md mx-auto">
              {hasPrevalence && hasThreshold ? (
                <>The base query found events (see histogram), but after prevalence enrichment, none matched your filter. Try adjusting the threshold or checking the prevalence field values.</>
              ) : hasPrevalence ? (
                <>The base query found events (see histogram), but prevalence enrichment filtered all results. This can happen when no matching prevalence data exists for the time window.</>
              ) : hasThreshold ? (
                <>The base query found events (see histogram), but none exceeded your threshold. Try lowering the threshold or checking if the aggregated field has values.</>
              ) : (
                <>The aggregation returned no rows. This can happen if the field you're aggregating on is empty or null for all events.</>
              )}
            </p>
            <div className="mt-4 text-xs text-muted-foreground">
              {hasThreshold ? (
                <>Tip: Remove the <code className="bg-muted/30 px-1.5 py-0.5 rounded">| where</code> clause to see all results</>
              ) : hasPrevalence ? (
                <>Tip: Try <code className="bg-muted/30 px-1.5 py-0.5 rounded">enrich=true</code> without a where clause to see all prevalence data</>
              ) : null}
            </div>
          </>
        ) : (
          // Regular empty results
          <>
            <SearchIcon className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
            <p className="text-foreground text-base font-medium">No results found</p>
            <p className="text-muted-foreground text-sm mt-2">Try adjusting your query or expanding the time range</p>
          </>
        )
      ) : (
        <>
          <SearchIcon className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-muted-foreground text-sm">Run a search to see results</p>
        </>
      )}
    </div>
  );
}


// Enrichment category definitions
const ENRICHMENT_CATEGORIES = {
  ioc: { label: 'IOC (Threat Intel)', description: 'Threat intelligence indicators' },
  custom: { label: 'Custom Enrichments', description: 'User-defined enrichments' },
  prevalence: { label: 'Prevalence', description: 'Prevalence/rarity data' },
  identity: { label: 'Identity', description: 'Resolved identity from the user registry' },
  geo: { label: 'Geo/ASN', description: 'Geographic and network info' },
  lookup: { label: 'Lookup Tables', description: 'Lookup table enrichments' },
  ext: { label: 'Extended Fields', description: 'Parser-extracted fields (ext JSON)' },
  metadata: { label: 'Metadata', description: 'System metadata fields' },
} as const;

type EnrichmentCategory = keyof typeof ENRICHMENT_CATEGORIES;

// Format value for display - handle objects, arrays, etc.
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function RawView({
  results,
  onAddToQuery,
  onSetQuery,
  query,
  hiddenEnrichments: _hiddenEnrichments = new Set(),
  highlightKeywords = [],
  notebookActive,
  onAddToNotebook,
  totalCount,
  isSearching,
  onLoadMore,
  onFetchLog: _onFetchLog,
  selectedEventId,
  onSelectEvent,
  fullLogData,
  loadingLogs,
  onPrefetchLog,
  detailViewMode,
}: {
  results: SearchResult[];
  onAddToQuery: (field: string, value: string, exclude: boolean) => void;
  onSetQuery?: (query: string) => void;
  query?: string;
  highlightKeywords?: string[];
  hiddenEnrichments?: Set<string>;
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
  totalCount?: number;
  isSearching?: boolean;
  onLoadMore?: () => void;
  onFetchLog?: (id: string, timestamp: Date, sourceType?: string) => Promise<Record<string, unknown> | null>;
  /** Currently selected event ID (for inspector panel highlighting) */
  selectedEventId?: string;
  /** Callback when an event row is clicked to open inspector */
  onSelectEvent?: (event: SearchResult, index: number) => void;
  /** Shared full log data cache (lifted to SearchResults for inspector access) */
  fullLogData?: Map<string, Record<string, unknown>>;
  /** Shared loading state for full log fetches */
  loadingLogs?: Set<string>;
  /** Shared prefetch function (lifted to SearchResults) */
  onPrefetchLog?: (id: string, logId?: string, timestamp?: Date, sourceType?: string) => void;
  /** Detail view mode - panel (side drawer) or inline (expand in place) */
  detailViewMode?: DetailViewMode;
}) {
  const [expandedMessages, setExpandedMessages] = React.useState<Set<string>>(new Set());
  // Inline expand state (only used when detailViewMode === 'inline')
  const [expandedFields, setExpandedFields] = React.useState<Set<string>>(new Set());
  const [expandedDetailValues, setExpandedDetailValues] = React.useState<Set<string>>(new Set());
  const [copiedInlineField, setCopiedInlineField] = React.useState<string | null>(null);
  const isInlineMode = detailViewMode === 'inline';

  // Use shared data from parent, or fallback empty collections
  const fullLogDataMap = fullLogData ?? new Map<string, Record<string, unknown>>();
  const loadingLogsSet = loadingLogs ?? new Set<string>();
  const fullLogDataRef = useRef(fullLogDataMap);
  fullLogDataRef.current = fullLogDataMap;
  const loadingLogsRef = useRef(loadingLogsSet);
  loadingLogsRef.current = loadingLogsSet;

  // Expand message - one way only, can't collapse
  const expandMessage = (id: string) => {
    setExpandedMessages(prev => new Set(prev).add(id));
  };

  // Prefetch: delegate to shared parent handler.
  // sourceType (NAN-1032) lets the backend use the (source_type, timestamp, ...) PK
  // for a tight range read on S3-backed historical partitions.
  const prefetchLog = useCallback((id: string, logId?: string, timestamp?: Date, sourceType?: string) => {
    if (onPrefetchLog) {
      onPrefetchLog(id, logId, timestamp, sourceType);
    }
  }, [onPrefetchLog]);

  // Hover prefetch with debounce + scroll suppression to avoid firing during scroll
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isScrollingRef = useRef(false);
  const scrollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleRowMouseEnter = useCallback((id: string, logId?: string, timestamp?: Date, sourceType?: string) => {
    if (fullLogDataRef.current?.has(id) || loadingLogsRef.current?.has(id) || isScrollingRef.current) return;
    hoverTimerRef.current = setTimeout(() => {
      if (!isScrollingRef.current) {
        prefetchLog(id, logId, timestamp, sourceType);
      }
    }, 400);
  }, [prefetchLog]);

  const handleRowMouseLeave = useCallback(() => {
    if (hoverTimerRef.current) {
      clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = null;
    }
  }, []);

  // Toggle inline expand for a row
  const toggleFields = useCallback((id: string, logId?: string, timestamp?: Date, sourceType?: string) => {
    const isExpanding = !expandedFields.has(id);
    setExpandedFields(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
    if (isExpanding) {
      prefetchLog(id, logId, timestamp, sourceType);
    }
  }, [expandedFields, prefetchLog]);

  // Handle row click - select event for inspector panel or toggle inline expand
  const handleRowClick = useCallback((result: SearchResult, index: number) => {
    const sourceType = result.fields?.source_type as string | undefined;
    if (isInlineMode) {
      toggleFields(result.id, result.fields?.id as string, result.timestamp, sourceType);
    } else if (onSelectEvent) {
      onSelectEvent(result, index);
      prefetchLog(result.id, result.fields?.id as string, result.timestamp, sourceType);
    }
  }, [isInlineMode, toggleFields, onSelectEvent, prefetchLog]);


  // Virtualization setup - uses AppLayout's scroll container for free page scrolling
  const scrollContainerRef = useScrollContainer();
  const listRef = useRef<HTMLDivElement>(null);
  const [scrollMargin, setScrollMargin] = useState(0);

  // Track scroll activity to suppress prefetch during scrolling
  useEffect(() => {
    const el = scrollContainerRef?.current;
    if (!el) return;
    const onScroll = () => {
      isScrollingRef.current = true;
      if (hoverTimerRef.current) {
        clearTimeout(hoverTimerRef.current);
        hoverTimerRef.current = null;
      }
      if (scrollTimerRef.current) clearTimeout(scrollTimerRef.current);
      scrollTimerRef.current = setTimeout(() => { isScrollingRef.current = false; }, 200);
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      el.removeEventListener('scroll', onScroll);
      if (scrollTimerRef.current) clearTimeout(scrollTimerRef.current);
    };
  }, [scrollContainerRef]);

  // Calculate offset from scroll container to the list
  useEffect(() => {
    const updateScrollMargin = () => {
      if (listRef.current && scrollContainerRef?.current) {
        const listRect = listRef.current.getBoundingClientRect();
        const containerRect = scrollContainerRef.current.getBoundingClientRect();
        setScrollMargin(listRect.top - containerRect.top + scrollContainerRef.current.scrollTop);
      }
    };
    updateScrollMargin();
    window.addEventListener('resize', updateScrollMargin);
    return () => window.removeEventListener('resize', updateScrollMargin);
  }, [scrollContainerRef, results.length]);

  const virtualizer = useVirtualizer({
    count: results.length,
    getScrollElement: () => scrollContainerRef?.current ?? null,
    estimateSize: () => 120, // Estimate collapsed row height
    overscan: 5, // Render 5 extra items above/below viewport
    scrollMargin,
  });

  const virtualItems = virtualizer.getVirtualItems();

  // Infinite scroll - load more when near bottom
  const hasMore = totalCount !== undefined && results.length < totalCount;
  useEffect(() => {
    if (!hasMore || isSearching || !onLoadMore) return;

    const scrollElement = scrollContainerRef?.current;
    if (!scrollElement) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = scrollElement;
      // Load more when within 300px of bottom
      if (scrollHeight - scrollTop - clientHeight < 300) {
        onLoadMore();
      }
    };

    scrollElement.addEventListener('scroll', handleScroll);
    return () => scrollElement.removeEventListener('scroll', handleScroll);
  }, [hasMore, isSearching, onLoadMore, scrollContainerRef]);

  return (
    <TooltipProvider>
      <div
        ref={listRef}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {virtualItems.map(virtualRow => {
            const result = results[virtualRow.index];
            // Merge: start with query result fields (includes computed fields from
            // commands like prevalence), then overlay full ClickHouse data on expand
            const fullData = fullLogDataMap.get(result.id);
            const displayFields = fullData
              ? { ...result.fields, ...fullData }
              : result.fields;
        // Extract key UDM fields for the summary row
        const keyFields = {
          source_type: displayFields?.source_type as string | undefined,
          src_ip: displayFields?.src_ip as string | undefined,
          src_host: displayFields?.src_host as string | undefined,
          dest_ip: displayFields?.dest_ip as string | undefined,
          dest_host: displayFields?.dest_host as string | undefined,
          user: displayFields?.user as string | undefined,
          dest_user: displayFields?.dest_user as string | undefined,
          event_type: (displayFields?.event_type ?? displayFields?.action) as string | undefined,
        };
        const hasKeyFields = Object.values(keyFields).some(v => v !== undefined);

        return (
          <div
            key={virtualRow.key}
            data-index={virtualRow.index}
            ref={virtualizer.measureElement}
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              transform: `translateY(${virtualRow.start - scrollMargin}px)`,
            }}
          >
            <div
              className={`border-b border-border cursor-pointer transition-colors ${
                (isInlineMode ? expandedFields.has(result.id) : selectedEventId === result.id)
                  ? 'border-l-2 border-l-primary'
                  : 'hover:bg-muted/20'
              }`}
              onMouseEnter={() => handleRowMouseEnter(result.id, result.fields?.id as string, result.timestamp, result.fields?.source_type as string | undefined)}
              onMouseLeave={handleRowMouseLeave}
              onClick={() => handleRowClick(result, virtualRow.index)}
            >
            <div className="px-3 py-2">
                {/* Timestamp row on top — expand chevron + date */}
                <div className="text-muted-foreground text-[11.5px] font-mono mb-1 flex items-center gap-1">
                  <ChevronRight className={`w-3 h-3 flex-shrink-0 transition-transform ${(isInlineMode ? expandedFields.has(result.id) : selectedEventId === result.id) ? 'rotate-90 text-primary' : ''}`} />
                  <span>{formatUTCShort(result.timestamp)}</span>
                </div>
                {/* Event body below */}
                {(() => {
                  const messageValue = displayFields?.message;
                  if (!messageValue) return null;
                  const displayValue = formatValue(messageValue);
                  const isMessageExpanded = expandedMessages.has(result.id);
                  const shouldTruncate = !isMessageExpanded && displayValue.length > 500;
                  const messageDisplayValue = shouldTruncate
                    ? displayValue.substring(0, 500)
                    : displayValue;
                  return (
                    <div className="text-foreground font-mono text-[12px] leading-[1.55] break-words whitespace-pre-wrap">
                      {highlightKeywords.length > 0
                        ? highlightText(messageDisplayValue, highlightKeywords)
                        : messageDisplayValue}
                      {shouldTruncate && (
                        <button
                          onClick={(e) => { e.stopPropagation(); expandMessage(result.id); }}
                          className="text-muted-foreground hover:text-primary cursor-pointer ml-1"
                          title="Expand"
                        >
                          ...
                        </button>
                      )}
                    </div>
                  );
                })()}
                {/* Key UDM fields summary row - hidden when inline-expanded */}
                {hasKeyFields && !(isInlineMode && expandedFields.has(result.id)) && (() => {
                  const chipFields: Array<{ field: string; value: string | null | undefined; accent?: boolean }> = [
                    { field: 'sourcetype', value: keyFields.source_type },
                    { field: 'src_ip', value: keyFields.src_ip },
                    { field: 'src_host', value: keyFields.src_host },
                    { field: 'dest_ip', value: keyFields.dest_ip },
                    { field: 'dest_host', value: keyFields.dest_host },
                    { field: 'user', value: keyFields.user },
                    { field: 'dest_user', value: keyFields.dest_user },
                    { field: 'event_type', value: keyFields.event_type, accent: true },
                  ];
                  return (
                    <div className="flex flex-wrap gap-1 mt-3 font-mono text-[10.5px]">
                      {chipFields.map(({ field, value, accent }) => {
                        if (!value) return null;
                        const apiField = field === 'sourcetype' ? 'source_type' : field;
                        return (
                          <span
                            key={field}
                            className={cn(
                              'inline-flex rounded-sm overflow-hidden border transition-colors',
                              accent ? 'border-primary/25 hover:border-primary/50' : 'border-border hover:border-border/80',
                            )}
                          >
                            <span
                              className={cn(
                                'px-1.5 py-0 border-r',
                                accent
                                  ? 'bg-primary/15 text-primary border-primary/25'
                                  : 'text-muted-foreground bg-foreground/[0.03] border-border',
                              )}
                            >
                              {field}
                            </span>
                            <span className={cn('px-1.5 py-0', accent ? 'text-primary font-semibold' : 'text-str')}>
                              <FieldValueMenu
                                fieldName={apiField}
                                value={value}
                                displayValue={value}
                                onAddToQuery={onAddToQuery}
                                onSetQuery={onSetQuery}
                                query={query}
                                highlightKeywords={[]}
                                className={accent ? 'text-primary font-semibold' : 'text-str'}
                                notebookActive={notebookActive}
                                onAddToNotebook={onAddToNotebook}
                              />
                            </span>
                          </span>
                        );
                      })}
                    </div>
                  );
                })()}
                {/* Inline expanded fields table */}
                {isInlineMode && expandedFields.has(result.id) && (() => {
                  const isLoadingFullData = loadingLogsSet.has(result.id);
                  let flattenedFields = displayFields ? flattenFieldsForExpand(displayFields) : [];
                  if (_hiddenEnrichments.size > 0) {
                    flattenedFields = flattenedFields.filter(([k]) => !isFieldHiddenExpand(k, _hiddenEnrichments));
                  }
                  return (
                    <div className="mt-3 pt-3 border-t border-border/30 -mx-3 px-3 md:mx-0 md:px-0 overflow-x-auto md:overflow-x-visible">
                      {isLoadingFullData && !fullData ? (
                        <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                          <div className="w-3 h-3 border-2 border-muted-foreground/30 border-t-muted-foreground rounded-full animate-spin" />
                          Loading fields...
                        </div>
                      ) : flattenedFields.length > 0 ? (
                      <>
                      {isLoadingFullData && (
                        <div className="flex items-center gap-2 pb-2 text-xs text-muted-foreground">
                          <div className="w-3 h-3 border-2 border-muted-foreground/30 border-t-muted-foreground rounded-full animate-spin" />
                          Loading remaining fields...
                        </div>
                      )}
                      <table className="min-w-full md:w-full md:table-fixed text-xs font-mono">
                        <thead>
                          <tr className="text-muted-foreground">
                            <th className="text-left py-1 pr-4 md:pr-6 font-medium w-32 md:w-64 whitespace-nowrap">Field</th>
                            <th className="text-left py-1 font-medium">Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {flattenedFields
                            .filter(([, v]) => !(Array.isArray(v) && v.length === 0))
                            .map(([k, v]) => {
                            const dv = formatValue(v);
                            const isIoc = isIocFieldExpand(k);
                            const isRisk = isRiskFieldExpand(k);
                            // Field names always render muted grey (matches parsed k:v style)
                            const fieldColor = 'text-muted-foreground';
                            const detailKey = `${result.id}:${k}`;
                            const isValueExpanded = expandedDetailValues.has(detailKey);
                            const shouldTruncate = !isValueExpanded && dv.length > 200;
                            const truncatedValue = shouldTruncate ? dv.substring(0, 200) : dv;
                            return (
                              <tr key={k} className="group/irow border-t border-border/20 hover:bg-muted/20">
                                <td className={`py-1.5 pr-4 md:pr-6 align-top whitespace-nowrap md:truncate ${fieldColor}`} title={k}>
                                  <div className="flex items-center gap-1">
                                    <span className="truncate">{k}</span>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        navigator.clipboard.writeText(dv);
                                        setCopiedInlineField(detailKey);
                                        setTimeout(() => setCopiedInlineField(null), 1500);
                                      }}
                                      className="opacity-0 group-hover/irow:opacity-100 transition-opacity flex-shrink-0"
                                      title="Copy value"
                                    >
                                      {copiedInlineField === detailKey ? (
                                        <Check className="w-3 h-3 text-green-400" />
                                      ) : (
                                        <Copy className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-1.5 align-top whitespace-nowrap md:whitespace-pre-wrap md:break-all">
                                  <FieldValueMenu
                                    fieldName={k}
                                    value={v}
                                    displayValue={truncatedValue}
                                    onAddToQuery={onAddToQuery}
                                    onSetQuery={onSetQuery}
                                    query={query}
                                    highlightKeywords={highlightKeywords}
                                    className={isIoc ? "text-red-400" : isRisk ? "text-orange-400" : "text-str"}
                                    notebookActive={notebookActive}
                                    onAddToNotebook={onAddToNotebook}
                                  />
                                  {shouldTruncate && (
                                    <button
                                      onClick={(e) => { e.stopPropagation(); setExpandedDetailValues(prev => new Set(prev).add(detailKey)); }}
                                      className="ml-1 text-muted-foreground hover:text-primary cursor-pointer"
                                      title="Show full value"
                                    >
                                      ...
                                    </button>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                      </>) : null}
                    </div>
                  );
                })()}
            </div>
          </div>
          </div>
        );
      })}
        </div>
        {/* Infinite scroll loading indicator */}
        {hasMore && (
          <div className="flex items-center justify-center py-4 text-sm text-muted-foreground">
            {isSearching ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Loading more...
              </>
            ) : (
              <span>Scroll for more ({results.length} of {totalCount})</span>
            )}
          </div>
        )}
        {!hasMore && results.length > 0 && totalCount !== undefined && (
          <div className="flex items-center justify-center py-4 text-sm text-muted-foreground">
            All {totalCount} results loaded
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}
