// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useCallback } from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ChevronDown, Plus, Minus, Copy, Search, X, Loader2, Filter, ChevronLeft } from 'lucide-react';
import { cn } from '@/lib/utils';

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
}

// Server-side field values (fetched on-demand)
interface ServerFieldValues {
  values: FieldValueInfo[];
  loading: boolean;
  error?: string;
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
  isExpanded: boolean;
  onToggleExpanded: () => void;
  isLoading?: boolean;
  isLoadingMore?: boolean;  // Field stats still loading in background (fields already visible)
  // For on-demand field value fetching
  query?: string;
  timeRange?: { start: string; end: string };
  onFetchFieldValues?: (field: string, query: string, start: string, end: string) => Promise<{ values: FieldValueInfo[]; total_count: number }>;
}

const INITIAL_VALUES_SHOWN = 10;

// Common UDM fields pinned to a "Selected" section at the top of the field
// index — the fields analysts land on for most searches. Any field in this
// list that the current result set produced gets surfaced first; the rest
// fall under "Available".
const SELECTED_FIELDS = new Set([
  'source_type',
  'sourcetype',
  'src_ip',
  'src_host',
  'dest_ip',
  'dest_host',
  'user',
  'event_type',
  'timestamp',
  '_time',
]);

function SectionHdr({ label, count }: { label: string; count: number }) {
  return (
    <div className="pt-2 pb-1 px-1 font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/60 font-semibold flex items-center gap-1.5">
      {label}
      <span className="ml-auto tabular-nums">{count}</span>
    </div>
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
  isExpanded,
  onToggleExpanded,
  isLoading = false,
  isLoadingMore = false,
  query,
  timeRange,
  onFetchFieldValues,
}: FieldsPanelProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [openMenuKey, setOpenMenuKey] = useState<string | null>(null);
  const [expandedValueFields, setExpandedValueFields] = useState<Set<string>>(new Set());
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
              values: response.values,
              loading: false
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
  const getFieldValues = useCallback((stat: FieldStat): { values: FieldValueInfo[]; loading: boolean; isServerData: boolean } => {
    const serverData = serverFieldValues.get(stat.field);
    if (serverData && serverData.values.length > 0) {
      return { values: serverData.values, loading: false, isServerData: true };
    }
    if (serverData?.loading) {
      return { values: stat.topValues, loading: true, isServerData: false };
    }
    // Fall back to client-side values
    return { values: stat.topValues, loading: false, isServerData: false };
  }, [serverFieldValues]);

  const baseStats = showBaseFields ? baseFieldStats : fieldStats;
  const displayStats = searchTerm
    ? baseStats.filter(stat => 
        stat.field.toLowerCase().includes(searchTerm.toLowerCase()) ||
        stat.topValues.some(v => v.value.toLowerCase().includes(searchTerm.toLowerCase()))
      )
    : baseStats;

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
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>Indexing more fields…</span>
              </div>
            )}
          </div>
        )}
        {isExpanded && <div>
          {isLoading ? (
            <div className="flex items-center justify-center gap-2 py-4 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-[12px] font-mono">Indexing fields...</span>
            </div>
          ) : displayStats.length === 0 ? (
            <p className="text-muted-foreground text-[11.5px] font-mono py-4 text-center">Execute a query to build the field index</p>
          ) : (() => {
            const selectedStats = displayStats.filter(s => SELECTED_FIELDS.has(s.field));
            const availableStats = displayStats.filter(s => !SELECTED_FIELDS.has(s.field));
            const renderRow = (stat: FieldStat) => {
              const isOpen = expandedFields.has(stat.field);
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
                    'text-[10px] w-2 inline-block transition-transform shrink-0',
                    isOpen ? 'text-primary rotate-90' : 'text-muted-foreground/50'
                  )}>›</span>
                  <span className="flex-1 whitespace-nowrap overflow-hidden text-ellipsis">{stat.field}</span>
                  <span
                    className={cn('text-[10.5px]', isOpen ? 'text-primary' : 'text-muted-foreground')}
                    title={`${stat.uniqueCount.toLocaleString()} unique values`}
                  >
                    {isLoadingMore && stat.uniqueCount === 0 ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      formatCardinality(stat.uniqueCount)
                    )}
                  </span>
                </div>

                {isOpen && (
                  <div className="mt-1 mb-2 pl-3 pr-1 py-1 border-l border-primary/25 anim-slide space-y-0.5">
                    <div className="flex items-center gap-2 pb-1 mb-1 font-mono text-[10px] text-muted-foreground">
                      <span className="text-muted-foreground/80">
                        {stat.uniqueCount.toLocaleString()} unique · {stat.count.toLocaleString()} events
                      </span>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onToggleField(stat.field); }}
                        className="ml-auto text-muted-foreground/60 cursor-pointer px-0.5 hover:text-foreground"
                        aria-label={`Collapse ${stat.field}`}
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                    {(() => {
                      const { values: fieldValues, loading: fieldLoading } = getFieldValues(stat);
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
                              <Loader2 className="w-3 h-3 animate-spin" />
                              <span>Loading values...</span>
                            </div>
                          )}
                          {fieldLoading && valuesToShow.length > 0 && (
                            <div className="flex items-center gap-1.5 px-1.5 pb-1 text-[11px] text-muted-foreground">
                              <Loader2 className="w-3 h-3 animate-spin" />
                              <span>Loading full stats…</span>
                            </div>
                          )}
                          {valuesToShow.map((valueInfo, idx) => {
                            const menuKey = `${stat.field}-${idx}`;
                            return (
                              <DropdownMenu
                                key={idx}
                                open={openMenuKey === menuKey}
                                onOpenChange={(open) => setOpenMenuKey(open ? menuKey : null)}
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
                                    }}
                                  >
                                    <span className="text-str whitespace-nowrap overflow-hidden text-ellipsis" title={valueInfo.value}>
                                      {valueInfo.value}
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
                                <DropdownMenuContent align="start" className="min-w-[180px] p-1">
                                  <DropdownMenuLabel className="px-2 py-1 text-[11px] tracking-normal normal-case text-muted-foreground font-normal">
                                    {stat.field} ={' '}
                                    <span className="text-primary font-medium">
                                      {valueInfo.value}
                                    </span>
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
