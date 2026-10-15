// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ChevronDown, Plus, Minus, Copy, Search, X, Filter, ChevronLeft, BarChart2, EyeOff, Group as GroupIcon } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import {
  canonicalSpillFieldName,
  hasObservedSpillValue,
  isSpillFieldName,
  sortFieldStatsByName,
} from './field-rail-policy';

interface FieldValueInfo {
  value: string;
  count: number;
  percentage: number;
}

export interface FieldStat {
  field: string;
  count: number;
  uniqueCount: number;  // Total unique values (cardinality) for this field
  topValues: FieldValueInfo[];  // Client-side stats from visible results
  // NAN-1503: synthetic entry for an `ext.*` / OCSF-unmapped JSON key. Field
  // stats never enumerate JSON sub-keys (too costly across hundreds of keys),
  // so these carry no precomputed counts — cardinality and values are fetched
  // on demand when the row is expanded (the get_field_values path resolves
  // `ext.{field}` correctly via field_access_expr).
  onDemand?: boolean;
  // NAN-3566: count/uniqueCount/topValues were counted over a sample of this
  // many newest events, not the whole window. Unset = exact.
  sampledRows?: number;
}

/** "sample · 1,000 events" for a field counted over a row sample (NAN-3566). */
function sampledRowsLabel(rows: number): string {
  return `sample · ${rows.toLocaleString()} events`;
}

// Server-side field values (fetched on-demand)
interface ServerFieldValues {
  values: FieldValueInfo[];
  loading: boolean;
  error?: string;
  /** NAN-3093: counted over the newest slice of the window only. */
  sampled?: { start: string; end: string };
}

/** "last 1h" for a sampled slice of the window (NAN-3093). */
function sampledSliceLabel(sampled: { start: string; end: string }): string {
  const minutes = Math.round((Date.parse(sampled.end) - Date.parse(sampled.start)) / 60_000);
  if (!Number.isFinite(minutes) || minutes <= 0) return 'sample';
  return minutes % 60 === 0 ? `sample · last ${minutes / 60}h` : `sample · last ${minutes}m`;
}

// Format cardinality display - just show the unique count.
function formatCardinality(uniqueCount: number): string {
  return uniqueCount.toLocaleString();
}

interface FieldsPanelProps {
  fieldStats: FieldStat[];
  baseFieldStats: FieldStat[];
  isAggregateQuery: boolean;
  showBaseFields: boolean;
  onToggleShowBaseFields: () => void;
  expandedFields: Set<string>;
  onToggleField: (field: string) => void;
  onAddToQuery: (field: string, value: string, exclude: boolean) => void;
  /**
   * Replace the query with a one-click group-by on `field` (NAN-2209). Optional
   * so embeddings that cannot rewrite the query simply omit the action.
   */
  onGroupBy?: (field: string) => void;
  isExpanded: boolean;
  onToggleExpanded: () => void;
  isLoading?: boolean;
  isLoadingMore?: boolean;  // Field stats still loading in background (fields already visible)
  // For on-demand field value fetching
  query?: string;
  timeRange?: { start: string; end: string };
  onFetchFieldValues?: (field: string, query: string, start: string, end: string) => Promise<{
    values: FieldValueInfo[];
    total_count: number;
    approximate?: boolean;
    sampled_start?: string;
    sampled_end?: string;
  }>;
  // NAN-1427: the server stats were computed over a reduced column set
  // (visible + pinned columns); offer "Index all fields" to fetch the rest.
  isReducedFieldSet?: boolean;
  onLoadAllFields?: () => void;
}

const INITIAL_VALUES_SHOWN = 10;
// Per-field on-demand value fetch cap. MUST match the `limit` the parent passes
// to `onFetchFieldValues` (Search.tsx) — when a loaded value list hits this many
// entries the distinct count is "N+", not exact (NAN-1506).
const ON_DEMAND_VALUE_LIMIT = 100;

// Key fields pinned to the "Selected" section at the top of the field index — the
// ones analysts land on for most searches. Any field in this list that the
// current result set produced gets surfaced first; the rest fall under
// "Available". The set is profile-aware (OCSF Phase 7, NAN-1241): under OCSF a
// row carries canonical OCSF paths, so no Nano serving aliases belong here.
export const SELECTED_FIELDS_UDM = new Set([
  'source_type',
  'sourcetype',
  'src_ip',
  'src_host',
  'dest_ip',
  'dest_host',
  'dest_port',
  'protocol',
  'user',
  'event_type',
  'process_name',
  'command_line',
  'auth_result',
  'timestamp',
  '_time',
]);
// Host identity mirrors the UDM set (NAN-3251): src_host/dest_host are
// src_endpoint.hostname/dst_endpoint.hostname, and device.hostname is the host
// of endpoint-class events (Sysmon, Windows Event Log). protocol_name is the
// OCSF analog of UDM `protocol`.
export const SELECTED_FIELDS_OCSF = new Set([
  'metadata.log_source',
  'time',
  'class_uid',
  'activity_name',
  'severity',
  'device.hostname',
  'src_endpoint.ip',
  'src_endpoint.hostname',
  'dst_endpoint.ip',
  'dst_endpoint.hostname',
  'dst_endpoint.port',
  'connection_info.protocol_name',
  'user.name',
  'actor.user.name',
  'actor.process.name',
  'actor.process.cmd_line',
  'status',
]);

// NAN-1427: pinned columns always included in the reduced field-stats request
// so the "Selected" section stays complete. Union of both schemas — the server
// intersects with the live table inventory, so the other schema's names are
// dropped harmlessly.
export const FIELD_STATS_PINNED_COLUMNS: string[] = Array.from(
  new Set([...SELECTED_FIELDS_UDM, ...SELECTED_FIELDS_OCSF])
);

function SectionHdr({
  label,
  count,
  collapsible,
  open,
  onToggle,
}: {
  label: string;
  count: number;
  collapsible?: boolean;
  open?: boolean;
  onToggle?: () => void;
}) {
  const cls =
    'pt-2 pb-1 px-1 font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/60 font-semibold flex items-center gap-1.5';
  const inner = (
    <>
      {collapsible && (
        <ChevronDown
          className={cn('w-3 h-3 transition-transform', open ? '' : '-rotate-90')}
        />
      )}
      {label}
      <span className="ml-auto tabular-nums">{count}</span>
    </>
  );
  return collapsible ? (
    <button
      type="button"
      onClick={onToggle}
      className={cn(cls, 'w-full hover:text-muted-foreground transition-colors')}
    >
      {inner}
    </button>
  ) : (
    <div className={cls}>{inner}</div>
  );
}

export function FieldsPanel({
  fieldStats,
  baseFieldStats,
  isAggregateQuery,
  showBaseFields,
  onToggleShowBaseFields,
  expandedFields,
  onToggleField,
  onAddToQuery,
  onGroupBy,
  isExpanded,
  onToggleExpanded,
  isLoading = false,
  isLoadingMore = false,
  query,
  timeRange,
  onFetchFieldValues,
  isReducedFieldSet = false,
  onLoadAllFields,
}: FieldsPanelProps) {
  const [searchTerm, setSearchTerm] = useState('');
  // Extended/Unmapped (on-demand JSON fields) collapse to a single header by
  // default — there can be dozens and they'd swamp the rail. A filter term
  // force-opens the section so matches always surface.
  const [extExpanded, setExtExpanded] = useState(false);
  const [openMenuKey, setOpenMenuKey] = useState<string | null>(null);
  // Whether the open value-menu's label shows the full (un-clamped) value.
  // Resets whenever a different menu opens — only one menu is open at a time.
  const [labelValueExpanded, setLabelValueExpanded] = useState(false);
  const [expandedValueFields, setExpandedValueFields] = useState<Set<string>>(new Set());
  // Pin the active schema's key fields under "Selected" (NAN-1241). Cached app-wide.
  const { data: schemaFields } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const selectedFieldSet =
    schemaFields?.schema === 'ocsf' ? SELECTED_FIELDS_OCSF : SELECTED_FIELDS_UDM;
  // Per-source RBAC scoping (NAN-1802): mark restricted source_type values in
  // the field-value picker so analysts see which sources are visibility-scoped.
  // Only fetched for admins with `source_scopes:view` — others get an empty set
  // (and no 403). An empty restricted registry = allow-all.
  const { hasPermission } = useAuth();
  const { data: restrictedResp } = useQuery({
    queryKey: ['source-scopes-restricted'],
    queryFn: () => api.sourceScopes.listRestricted(),
    enabled: hasPermission('source_scopes:view'),
    staleTime: 5 * 60 * 1000,
  });
  const restrictedSourceTypes = useMemo(
    () => new Set((restrictedResp?.restricted ?? []).map((r) => r.source_type)),
    [restrictedResp],
  );
  // Server-side field values (fetched on-demand when field is expanded)
  const [serverFieldValues, setServerFieldValues] = useState<Map<string, ServerFieldValues>>(new Map());

  // Fetch field values when a field is expanded
  useEffect(() => {
    if (!onFetchFieldValues || !query || !timeRange) return;

    // Find fields that are expanded but don't have server values yet
    for (const field of expandedFields) {
      const existing = serverFieldValues.get(field);
      if (!existing) {
        // Start loading
        setServerFieldValues(prev => new Map(prev).set(field, { values: [], loading: true }));

        onFetchFieldValues(field, query, timeRange.start, timeRange.end)
          .then(response => {
            setServerFieldValues(prev => new Map(prev).set(field, {
              // Empty string is "field absent", not a value — don't render
              // "-" rows (percentages stay server-relative: "X% of all
              // matching events", which remains honest after the drop).
              values: response.values.filter(v => v.value !== ''),
              loading: false,
              sampled: response.approximate && response.sampled_start && response.sampled_end
                ? { start: response.sampled_start, end: response.sampled_end }
                : undefined,
            }));
          })
          .catch(error => {
            setServerFieldValues(prev => new Map(prev).set(field, {
              values: [],
              loading: false,
              error: error.message
            }));
          });
      }
    }
  }, [expandedFields, query, timeRange, onFetchFieldValues, serverFieldValues]);

  // Clear server values when field stats change (i.e., new search completed)
  // Don't clear on query keystroke - only when actual results change
  useEffect(() => {
    setServerFieldValues(new Map());
  }, [fieldStats]);

  // Helper to get values to display for a field (server values if available, else client-side)
  const getFieldValues = useCallback((stat: FieldStat): { values: FieldValueInfo[]; loading: boolean; isServerData: boolean; sampled?: { start: string; end: string } } => {
    const serverData = serverFieldValues.get(stat.field);
    if (serverData && serverData.values.length > 0) {
      return { values: serverData.values, loading: false, isServerData: true, sampled: serverData.sampled };
    }
    if (serverData?.loading) {
      return { values: stat.topValues, loading: true, isServerData: false };
    }
    // Fall back to client-side values
    return { values: stat.topValues, loading: false, isServerData: false };
  }, [serverFieldValues]);

  // NAN-1503: legacy UDM ext.* JSON keys never come back in field stats. The
  // OCSF lake instead returns its stable struct shape, including null
  // `unmapped.*` placeholders. Pull legacy names on demand, but show OCSF spill
  // leaves only when this search's sample observed a real value.
  // NAN-1505/1510: scope enumeration to the active search QUERY + window (keyed on
  // both) so the list matches what a field expand can return. Keying on the window
  // alone (1505) listed ext keys from other source types in the window that then
  // expanded empty; passing the query scopes it to the same predicate as the
  // per-field value fetch. Only fetch while the panel is open.
  // NAN-3299: the names only merge into a built field index (see mergedStats),
  // so wait for one — before it the panel would fetch for the pre-run window
  // and again for the run's own. The signal aborts a superseded fetch.
  const hasFieldIndex = (showBaseFields ? baseFieldStats : fieldStats).length > 0;
  const { data: extFieldNames } = useQuery({
    // Version the key so a hot-reloaded UI cannot retain the old lake response
    // that mixed schema-only names into this observed-field list.
    queryKey: ['ext-field-names-observed-v2', query, timeRange?.start, timeRange?.end],
    queryFn: ({ signal }) => api.getExtFieldNames(query, timeRange?.start, timeRange?.end, signal),
    staleTime: 5 * 60 * 1000,
    enabled: !!onFetchFieldValues && !!timeRange && isExpanded && hasFieldIndex,
  });

  const isOcsf = schemaFields?.schema === 'ocsf';
  const unfilteredBaseStats = showBaseFields ? baseFieldStats : fieldStats;
  const baseStats = useMemo(
    () => unfilteredBaseStats.filter((stat) => {
      if (!isOcsf) return true;
      const isUnmapped = stat.field === 'unmapped' || isSpillFieldName(stat.field, true);
      return !isUnmapped || hasObservedSpillValue(stat.topValues);
    }),
    [unfilteredBaseStats, isOcsf],
  );
  // Merge in ext keys (deduped against real columns) once a search has produced
  // a field index — before that we keep the clean "run a query" empty state.
  // NAN-1504: render with the namespace prefix the inspector/results already use
  // — `ext.` (UDM) / `unmapped.` (OCSF) — so the picker name matches the row
  // view. The prefixed form is also the query form: field_access_expr strips the
  // `ext.` prefix (NAN-1411) and OcsfProfile::resolve strips `unmapped.`, so
  // expand + add-to-filter resolve to the same spill access as the bare key.
  const mergedStats = useMemo<FieldStat[]>(() => {
    if (!extFieldNames || extFieldNames.length === 0 || baseStats.length === 0) {
      return baseStats;
    }
    const present = new Set(baseStats.map(s => s.field));
    const extStats: FieldStat[] = extFieldNames
      .filter(name => !!name)
      // ClickHouse returns relative ext paths while the lake returns canonical
      // `unmapped.*` paths. Never prefix an already-canonical path a second
      // time; also heal stale cached `unmapped.unmapped.*` responses.
      .map(name => canonicalSpillFieldName(name, !!isOcsf))
      .filter(name => isSpillFieldName(name, !!isOcsf))
      .filter(name => !present.has(name))
      .map(name => ({ field: name, count: 0, uniqueCount: 0, topValues: [], onDemand: true }));
    return extStats.length > 0 ? [...baseStats, ...extStats] : baseStats;
  }, [baseStats, extFieldNames, isOcsf]);

  const displayStats = searchTerm
    ? mergedStats.filter(stat =>
        stat.field.toLowerCase().includes(searchTerm.toLowerCase()) ||
        stat.topValues.some(v => v.value.toLowerCase().includes(searchTerm.toLowerCase()))
      )
    : mergedStats;

  // NAN-1503: filtering for a field that isn't in the reduced column set used to
  // dead-end on "Execute a query to build the field index" — the full-inventory
  // fetch ("Show all fields") lived only in the non-empty branch, so it was
  // unreachable. When a filter term matches no *real* column and the set is
  // still reduced, auto-trigger the full fetch so the field surfaces. (ext
  // matches don't count — a real column may still be hiding in the unindexed
  // remainder.) isReducedFieldSet flips false once the full set arrives, so this
  // fires at most once per search.
  const hasRealMatch = displayStats.some(s => !s.onDemand);
  // Fetch at most once per distinct (search, filter-term): isLoadingMore toggles
  // true→false around the request, and a failed fetch leaves isReducedFieldSet
  // true, either of which would otherwise re-fire this effect into a loop.
  // NAN-1509: key by query+time-range too, not just the term — otherwise the same
  // filter term across a NEW reduced search (component still mounted) is blocked
  // forever and never auto-fetches.
  const autoFetchKey = `${query ?? ''}|${timeRange?.start ?? ''}|${timeRange?.end ?? ''}|${searchTerm}`;
  const autoFetchedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (
      searchTerm &&
      isReducedFieldSet &&
      !isLoadingMore &&
      !hasRealMatch &&
      onLoadAllFields &&
      autoFetchedForRef.current !== autoFetchKey
    ) {
      autoFetchedForRef.current = autoFetchKey;
      onLoadAllFields();
    }
  }, [autoFetchKey, searchTerm, isReducedFieldSet, isLoadingMore, hasRealMatch, onLoadAllFields]);

  return (
    <div className="search-workspace-section flex flex-col min-h-0 border-r border-border pr-2 max-h-[calc(100vh-8rem)] overflow-y-auto">
      <div className={isExpanded ? 'p-1' : 'p-2'}>
        <div className="flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold pb-2 border-b border-border mb-1 pt-1 px-1">
          <button
            onClick={onToggleExpanded}
            className={cn('flex items-center gap-2 transition-colors', isExpanded ? 'hover:text-foreground' : 'text-primary hover:text-primary/80')}
            title={isExpanded ? 'Collapse field index' : 'Expand field index'}
          >
            <Filter className="w-[12px] h-[12px] text-muted-foreground"/>
            <span>Fields</span>
            <span className="text-muted-foreground/60 text-[10px] normal-case tracking-normal">{displayStats.length}</span>
          </button>
          {isExpanded && (
            <div className="ml-auto flex items-center gap-2">
              {isAggregateQuery && baseFieldStats.length > 0 && (
                <button
                  onClick={onToggleShowBaseFields}
                  className={cn(
                    'text-[10px] px-2 py-0.5 rounded-sm transition-all normal-case tracking-normal',
                    showBaseFields ? 'bg-primary/15 text-primary' : 'bg-foreground/5 text-muted-foreground hover:text-primary'
                  )}
                  title="Show fields from base search"
                >
                  Base scan
                </button>
              )}
              <button
                onClick={onToggleExpanded}
                aria-label="Collapse fields"
                className="w-5 h-5 flex items-center justify-center rounded-sm text-muted-foreground hover:bg-foreground/5 hover:text-foreground"
              >
                <ChevronLeft className="w-[11px] h-[11px]"/>
              </button>
            </div>
          )}
        </div>
        {isExpanded && (
          <div className="mb-1">
            <div className="relative px-2 py-1.5 my-1 flex items-center gap-1.5 font-mono text-[12px] bg-foreground/[0.02] border border-border rounded-sm">
              <Search className="w-[12px] h-[12px] text-muted-foreground/70 flex-shrink-0" />
              <input
                type="text"
                placeholder="Filter…"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="flex-1 bg-transparent outline-none text-foreground placeholder:text-muted-foreground/50 font-mono text-[12px] min-w-0"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="w-4 h-4 flex items-center justify-center rounded-sm hover:bg-foreground/5 text-muted-foreground hover:text-foreground flex-shrink-0"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
            {isLoadingMore && (
              <div className="flex items-center gap-1.5 px-2 py-1 text-[10.5px] text-muted-foreground animate-in fade-in duration-300">
                <LoadingIcon className="w-3 h-3" />
                <span>Indexing more fields…</span>
              </div>
            )}
          </div>
        )}
        {isExpanded && <div>
          {isLoading ? (
            <div className="flex items-center justify-center gap-2 py-4 text-muted-foreground">
              <LoadingIcon className="w-4 h-4" />
              <span className="text-[12px] font-mono">Indexing fields...</span>
            </div>
          ) : displayStats.length === 0 ? (
            isLoadingMore ? (
              // NAN-1503: filter matched nothing in the reduced set and the
              // full-inventory fetch is in flight — show progress, not the
              // "run a query" dead-end.
              <div className="flex items-center justify-center gap-2 py-4 text-muted-foreground">
                <LoadingIcon className="w-4 h-4" />
                <span className="text-[12px] font-mono">Indexing all fields…</span>
              </div>
            ) : searchTerm ? (
              <p className="text-muted-foreground text-[11.5px] font-mono py-4 text-center">No fields match “{searchTerm}”</p>
            ) : (
              <p className="text-muted-foreground text-[11.5px] font-mono py-4 text-center">Execute a query to build the field index</p>
            )
          ) : (() => {
            const selectedStats = sortFieldStatsByName(
              displayStats.filter(s => selectedFieldSet.has(s.field)),
            );
            // On-demand ext/unmapped JSON fields get their own section (below),
            // matching the inspector's Extended/Unmapped buckets — keep them out
            // of "Available" (which is promoted/indexed schema columns).
            const availableStats = sortFieldStatsByName(
              displayStats.filter(
                s => !selectedFieldSet.has(s.field) && !isSpillFieldName(s.field, !!isOcsf),
              ),
            );
            // Categorize by the canonical namespace, not by whether the row was
            // synthetically discovered. Populated `unmapped.*` leaves derived
            // from visible OCSF events belong here too.
            const extStats = sortFieldStatsByName(
              displayStats.filter(s => isSpillFieldName(s.field, !!isOcsf)),
            );
            const renderRow = (stat: FieldStat) => {
              const isOpen = expandedFields.has(stat.field);
              // Expanding a field fetches its values on-demand over the FULL
              // window (exact, unbounded). Once loaded, derive cardinality/events
              // from them: this both populates on-demand ext fields (which carry
              // no precomputed stats, NAN-1503) AND corrects real-column stats,
              // whose bulk numbers are a fast bounded sample on large windows
              // (NAN-1506). Exact unless the value list hit the fetch cap → "N+".
              const serverData = serverFieldValues.get(stat.field);
              const loadedValues = serverData?.values ?? [];
              const hasLoaded = loadedValues.length > 0;
              // NAN-1510: an on-demand (ext) field whose fetch completed with no
              // values (a key present but empty in the matched rows) → read "No
              // values" instead of a stuck "loaded on demand". Scoped to
              // stat.onDemand so a real column (which falls back to client-side
              // topValues when server values are empty) doesn't claim "No values"
              // while still rendering rows; excludes the error case so a failed
              // fetch isn't masked as empty.
              const loadedEmpty =
                !!stat.onDemand && !!serverData && !serverData.loading && !serverData.error && loadedValues.length === 0;
              const loadedCapped = loadedValues.length >= ON_DEMAND_VALUE_LIMIT;
              const plus = hasLoaded && loadedCapped ? '+' : '';
              const displayUnique = hasLoaded
                ? loadedValues.length
                : stat.onDemand
                  ? null
                  : stat.uniqueCount;
              const displayCount = hasLoaded
                ? loadedValues.reduce((s, v) => s + v.count, 0)
                : stat.onDemand
                  ? null
                  : stat.count;
              // NAN-3566: until the exact drill-in loads, a sampled field's
              // unique count only covers the newest events: disclose in the tooltip.
              const sampledRows = !hasLoaded && !stat.onDemand ? stat.sampledRows : undefined;
              return (
              <div key={stat.field}>
                <div
                  className={cn(
                    'flex items-center py-1.5 px-1 font-mono text-[12px] gap-2 cursor-pointer rounded-sm transition-colors',
                    isOpen ? 'bg-primary/8 text-primary' : 'text-foreground hover:bg-foreground/[0.03]'
                  )}
                  onClick={() => onToggleField(stat.field)}
                >
                  <span className={cn(
                    'text-[14px] leading-none w-3 inline-block text-center transition-transform shrink-0',
                    isOpen ? 'text-primary rotate-90' : 'text-muted-foreground/70'
                  )}>›</span>
                  <span className="flex-1 whitespace-nowrap overflow-hidden text-ellipsis">{stat.field}</span>
                  <span
                    className={cn('text-[10.5px]', isOpen ? 'text-primary' : 'text-muted-foreground')}
                    title={
                      stat.onDemand && !hasLoaded
                        ? 'Expand to load values'
                        : sampledRows != null
                          ? `${(displayUnique ?? 0).toLocaleString()} unique values in a sample of ${sampledRows.toLocaleString()} events. Expand to load field statistics.`
                          : `${(displayUnique ?? 0).toLocaleString()}${plus} unique values`
                    }
                  >
                    {serverData?.loading ? (
                      <LoadingIcon className="w-3 h-3" />
                    ) : hasLoaded ? (
                      `${formatCardinality(displayUnique ?? 0)}${plus}`
                    ) : stat.onDemand ? (
                      // Values load on expand: a distribution glyph (previews the
                      // value bars the expanded view shows) instead of a bare
                      // `{ }` glyph that read as a value.
                      <BarChart2 className="w-3 h-3 text-muted-foreground/50" />
                    ) : isLoadingMore && stat.uniqueCount === 0 ? (
                      <LoadingIcon className="w-3 h-3" />
                    ) : (
                      formatCardinality(stat.uniqueCount)
                    )}
                  </span>
                </div>

                {isOpen && (
                  <div className="mt-1 mb-2 pl-3 pr-1 py-1 border-l border-primary/25 anim-slide space-y-0.5">
                    <div className="flex items-center gap-2 pb-1 mb-1 font-mono text-[10px] text-muted-foreground">
                      <span className="text-muted-foreground/80">
                        {loadedEmpty
                          ? 'No values in this search'
                          : displayUnique == null
                            ? 'Values loaded on demand'
                            : `${displayUnique.toLocaleString()}${plus} unique · ${(displayCount ?? 0).toLocaleString()}${plus} events`}
                      </span>
                      {/* NAN-2209: field-scoped group-by. The value rows below
                          filter on ONE value; this aggregates the whole field,
                          which is the move analysts previously had to hand-write
                          as `| stats count by <field>`. */}
                      {onGroupBy && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); onGroupBy(stat.field); }}
                          className="ml-auto flex items-center gap-1 text-muted-foreground/70 cursor-pointer px-0.5 hover:text-primary"
                          title={`Group results by ${stat.field}`}
                          aria-label={`Group by ${stat.field}`}
                        >
                          <GroupIcon className="w-3 h-3" />
                          <span>group by</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onToggleField(stat.field); }}
                        className={cn(
                          'text-muted-foreground/60 cursor-pointer px-0.5 hover:text-foreground',
                          !onGroupBy && 'ml-auto'
                        )}
                        aria-label={`Collapse ${stat.field}`}
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                    {(() => {
                      const { values: fieldValues, loading: fieldLoading, sampled: fieldSampled, isServerData } = getFieldValues(stat);
                      // NAN-3566: values shown from the field-stats row sample
                      // (the drill-in is loading or failed) are not the window's.
                      const rowSampled = !isServerData && stat.sampledRows != null ? stat.sampledRows : undefined;
                      const isShowingAll = expandedValueFields.has(stat.field);
                      const valuesToShow = isShowingAll
                        ? fieldValues
                        : fieldValues.slice(0, INITIAL_VALUES_SHOWN);
                      const hasMore = fieldValues.length > INITIAL_VALUES_SHOWN;
                      const remainingCount = fieldValues.length - INITIAL_VALUES_SHOWN;

                      return (
                        <>
                          {fieldLoading && valuesToShow.length === 0 && (
                            <div className="flex items-center gap-2 p-1.5 text-xs text-muted-foreground">
                              <LoadingIcon className="w-3 h-3" />
                              <span>Loading values...</span>
                            </div>
                          )}
                          {fieldLoading && valuesToShow.length > 0 && (
                            <div className="flex items-center gap-1.5 px-1.5 pb-1 text-[11px] text-muted-foreground">
                              <LoadingIcon className="w-3 h-3" />
                              <span>Loading full stats…</span>
                            </div>
                          )}
                          {valuesToShow.map((valueInfo, idx) => {
                            const menuKey = `${stat.field}-${idx}`;
                            return (
                              <DropdownMenu
                                key={idx}
                                open={openMenuKey === menuKey}
                                onOpenChange={(open) => { setOpenMenuKey(open ? menuKey : null); setLabelValueExpanded(false); }}
                              >
                                <DropdownMenuTrigger asChild>
                                  <div
                                    className={cn(
                                      'grid grid-cols-[1fr_auto] gap-1.5 items-center py-[3px] px-1.5 font-mono text-[11px] cursor-pointer rounded-sm relative transition-colors isolate',
                                      openMenuKey === menuKey ? 'bg-primary/8' : 'hover:bg-foreground/5'
                                    )}
                                    onContextMenu={(e) => {
                                      e.preventDefault();
                                      setOpenMenuKey(menuKey);
                                      setLabelValueExpanded(false);
                                    }}
                                  >
                                    <span className="min-w-0 flex items-center gap-1.5">
                                      <span className="text-str whitespace-nowrap overflow-hidden text-ellipsis" title={valueInfo.value}>
                                        {valueInfo.value}
                                      </span>
                                      {(stat.field === 'metadata.log_source' || stat.field === 'source_type' || stat.field === 'sourcetype') &&
                                        restrictedSourceTypes.has(valueInfo.value) && (
                                          <span
                                            title="Visibility-scoped source — only granted groups can see its events"
                                            className="shrink-0 inline-flex items-center gap-0.5 h-[13px] px-1 rounded-[3px] bg-amber-500/12 text-amber-500 text-[8.5px] uppercase tracking-wider"
                                          >
                                            <EyeOff className="w-[8px] h-[8px]" />
                                            Restricted
                                          </span>
                                        )}
                                    </span>
                                    <span className="text-muted-foreground text-right text-[10px] tabular-nums">
                                      {valueInfo.percentage.toFixed(1)}%
                                    </span>
                                    <span
                                      aria-hidden
                                      className="absolute bottom-0 left-0 h-full rounded-sm -z-10 pointer-events-none"
                                      style={{
                                        width: `${Math.min(100, Math.max(0, valueInfo.percentage))}%`,
                                        background: 'color-mix(in srgb, var(--foreground) 4%, transparent)',
                                      }}
                                    />
                                  </div>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="start" className="min-w-[180px] max-w-[340px] p-1">
                                  <DropdownMenuLabel className="px-2 py-1 text-[11px] tracking-normal normal-case text-muted-foreground font-normal">
                                    {stat.field} ={' '}
                                    <span
                                      className={cn(
                                        'text-primary font-medium break-all',
                                        // Only box/clamp large values — short ones stay
                                        // inline (`duration = 358` reads on one line).
                                        valueInfo.value.length > 240 &&
                                          (labelValueExpanded
                                            ? 'block max-h-[40vh] overflow-y-auto'
                                            : 'line-clamp-6')
                                      )}
                                    >
                                      {valueInfo.value}
                                    </span>
                                    {valueInfo.value.length > 240 && (
                                      <button
                                        type="button"
                                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setLabelValueExpanded(v => !v); }}
                                        className="mt-1 flex items-center gap-1 text-[10.5px] text-muted-foreground hover:text-primary transition-colors"
                                      >
                                        <ChevronDown className={cn('w-3 h-3 transition-transform', labelValueExpanded && 'rotate-180')} />
                                        {labelValueExpanded ? 'Show less' : 'Show all'}
                                      </button>
                                    )}
                                  </DropdownMenuLabel>
                                  <DropdownMenuSeparator className="-mx-1 my-1 h-px bg-border" />
                                  <DropdownMenuItem
                                    onClick={() => onAddToQuery(stat.field, valueInfo.value, false)}
                                    className="cursor-pointer gap-1.5 px-2 py-1 text-[12px]"
                                  >
                                    <Plus className="w-[13px] h-[13px]" />
                                    <span>Add to filter</span>
                                    <DropdownMenuShortcut className="text-[10.5px]">⏎</DropdownMenuShortcut>
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() => onAddToQuery(stat.field, valueInfo.value, true)}
                                    className="cursor-pointer gap-1.5 px-2 py-1 text-[12px]"
                                  >
                                    <Minus className="w-[13px] h-[13px]" />
                                    <span>Exclude</span>
                                    <DropdownMenuShortcut className="text-[10.5px]">⇧⏎</DropdownMenuShortcut>
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() => navigator.clipboard.writeText(valueInfo.value)}
                                    className="cursor-pointer gap-1.5 px-2 py-1 text-[12px]"
                                  >
                                    <Copy className="w-[13px] h-[13px]" />
                                    <span>Copy value</span>
                                    <DropdownMenuShortcut className="text-[10.5px]">⌘C</DropdownMenuShortcut>
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            );
                          })}
                          {!fieldLoading && hasMore && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedValueFields(prev => {
                                  const next = new Set(prev);
                                  if (isShowingAll) {
                                    next.delete(stat.field);
                                  } else {
                                    next.add(stat.field);
                                  }
                                  return next;
                                });
                              }}
                              className="w-full text-left p-1.5 text-xs text-primary hover:bg-accent rounded-lg transition-all flex items-center gap-2"
                            >
                              <ChevronDown className={`w-3 h-3 transition-transform ${isShowingAll ? 'rotate-180' : ''}`} />
                              <span>{isShowingAll ? 'Show less' : `Show ${remainingCount} more`}</span>
                            </button>
                          )}
                          {fieldSampled && (
                            <div
                              className="px-1.5 pt-1 font-mono text-[10.5px] text-muted-foreground"
                              title={`Approximate: counted over ${fieldSampled.start} – ${fieldSampled.end}, the newest slice of this window. Narrow the window for exact values.`}
                            >
                              {sampledSliceLabel(fieldSampled)}
                            </div>
                          )}
                          {!fieldSampled && rowSampled != null && valuesToShow.length > 0 && (
                            <div
                              className="px-1.5 pt-1 font-mono text-[10.5px] text-muted-foreground"
                              title={`Approximate: counted over a sample of ${rowSampled.toLocaleString()} matching events. Rare values can be missing.`}
                            >
                              {sampledRowsLabel(rowSampled)}
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </div>
                )}
              </div>
              );
            };
            return (
              <>
                {selectedStats.length > 0 && (
                  <>
                    <SectionHdr label="Selected" count={selectedStats.length} />
                    {selectedStats.map(renderRow)}
                  </>
                )}
                {availableStats.length > 0 && (
                  <>
                    <SectionHdr label="Available" count={availableStats.length} />
                    {availableStats.map(renderRow)}
                  </>
                )}
                {extStats.length > 0 && (() => {
                  /* On-demand JSON spill fields — UDM `ext.*` (Extended) /
                     OCSF `unmapped.*` (Unmapped), matching the inspector's
                     buckets. Collapsed by default (there can be dozens); a
                     filter term force-opens so matches always show. Values
                     load on expand (NAN-1506). */
                  const extOpen = !!searchTerm || extExpanded;
                  return (
                    <>
                      <SectionHdr
                        label={isOcsf ? 'Unmapped' : 'Extended'}
                        count={extStats.length}
                        collapsible
                        open={extOpen}
                        onToggle={() => setExtExpanded(v => !v)}
                      />
                      {extOpen && extStats.map(renderRow)}
                    </>
                  );
                })()}
                {isReducedFieldSet && onLoadAllFields && (
                  /* Teaser for the unindexed remainder (NAN-1427 reduced
                     fetch): kept LAST so the fading ghost rows trail off at the
                     bottom of the list — above a populated section they read as
                     "hidden content" contradicting the rows right below. Ghosts
                     pulse while the full-inventory fetch is in flight. */
                  <div className="relative mt-1 pb-1">
                    <div
                      aria-hidden
                      className="px-1 pt-0.5 [mask-image:linear-gradient(to_bottom,black_20%,transparent)]"
                    >
                      {[68, 46, 72].map((w, i) => (
                        <div
                          key={w}
                          className={`flex items-center justify-between gap-8 py-[7px] ${
                            isLoadingMore ? 'animate-pulse' : ''
                          }`}
                          style={{ opacity: 0.65 - i * 0.2 }}
                        >
                          <span
                            className="h-[7px] rounded-full bg-foreground/15"
                            style={{ width: `${w}%` }}
                          />
                          <span className="h-[7px] w-7 rounded-full bg-foreground/10" />
                        </div>
                      ))}
                    </div>
                    <div className="absolute inset-x-0 bottom-0 flex justify-center">
                      {isLoadingMore ? (
                        <span className="inline-flex items-center gap-1.5 font-mono text-[10.5px] text-muted-foreground bg-card border border-border rounded-md px-2.5 py-1">
                          <LoadingIcon className="w-3 h-3" />
                          Indexing fields…
                        </span>
                      ) : (
                        <button
                          onClick={onLoadAllFields}
                          title="Stats currently cover the columns in your results — load stats for every table column"
                          className="inline-flex items-center gap-1.5 font-mono text-[10.5px] text-foreground bg-card border border-border-2 rounded-md px-2.5 py-1 hover:border-primary/50 hover:text-primary transition-colors"
                        >
                          <ChevronDown className="w-3 h-3" />
                          Show all fields
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </>
            );
          })()}
        </div>}
        {!isExpanded && (
          <div className="flex items-center justify-center mt-2">
            <span className="font-mono text-[10.5px] text-muted-foreground px-1.5 py-0.5 border border-border rounded-sm">
              {displayStats.length}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
