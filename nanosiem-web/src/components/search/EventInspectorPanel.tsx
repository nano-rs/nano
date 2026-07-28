// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { X, Copy, Check, ChevronLeft, ChevronRight, GripVertical, ScanEye, GitBranch } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { formatUTCShort } from '@/lib/date-utils';
import { isClickHouseDefault } from '@/lib/utils';
import { api } from '@/lib/api';
import {
  flattenEventFields,
  buildFieldCategories,
  isFieldHidden,
  splitFieldKey,
} from './event-flatten';

// ============================================================================
// Types
// ============================================================================

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

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

export interface EventInspectorPanelProps {
  event: SearchResult;
  fullLogData?: Record<string, unknown>;
  isLoadingFullData?: boolean;
  onClose: () => void;
  onNavigate: (direction: 'prev' | 'next') => void;
  onAddToQuery: (field: string, value: string, exclude: boolean) => void;
  onSetQuery?: (query: string) => void;
  query?: string;
  highlightKeywords?: string[];
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
  hiddenEnrichments?: Set<string>;
  /** Index in results list (for display) */
  eventIndex?: number;
  totalCount?: number;
  /** FieldValueMenu component passed from parent to reuse existing implementation */
  FieldValueMenu: React.ComponentType<FieldValueMenuProps>;
}

// ============================================================================
// Field utilities
//
// The flattening + categorization logic is shared with the inline expanded-row
// view in SearchResults — both live in ./event-flatten so they can't drift.
// ============================================================================

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  // NAN-1466: Array(String) columns (url.categories, tags, *_tags) arrive as
  // real arrays — render a scalar list as a comma-join, not a JSON blob. Nested
  // arrays/objects (e.g. threat_signals) still fall through to JSON.
  if (Array.isArray(value)) {
    if (value.every((v) => v === null || typeof v !== 'object')) {
      return value.filter((v) => v !== null && v !== undefined).map(String).join(', ');
    }
    return JSON.stringify(value, null, 2);
  }
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

// ============================================================================
// Tabs
// ============================================================================

type InspectorTab = 'fields' | 'raw' | 'json';

// ============================================================================
// Component
// ============================================================================

const MIN_WIDTH = 360;
const MAX_WIDTH = 900;
const DEFAULT_WIDTH = 480;
const STORAGE_KEY = 'nanosiem-inspector-width';

function getStoredWidth(): number {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const w = parseInt(stored, 10);
      if (w >= MIN_WIDTH && w <= MAX_WIDTH) return w;
    }
  } catch { /* ignore */ }
  return DEFAULT_WIDTH;
}

export function EventInspectorPanel({
  event,
  fullLogData,
  isLoadingFullData,
  onClose,
  onNavigate,
  onAddToQuery,
  onSetQuery,
  query,
  highlightKeywords = [],
  notebookActive,
  onAddToNotebook,
  hiddenEnrichments = new Set(),
  eventIndex,
  totalCount,
  FieldValueMenu,
}: EventInspectorPanelProps) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<InspectorTab>('fields');
  const [expandedValues, setExpandedValues] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [width, setWidth] = useState(getStoredWidth);

  // Active schema profile's field universe (OCSF Phase 7, NAN-1241). Used to
  // categorize fields for the active deployment instead of assuming UDM: under
  // OCSF, promoted fields (`src_endpoint.ip`, `class_uid`, …) are "known" and
  // must land in Core, not the "Extended" (ext spill) bucket. Cached app-wide.
  const { data: schemaFields } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  // Only consult the schema field universe under a NON-UDM profile. Under UDM the
  // backend field universe is a superset of the hand-maintained frontend
  // `UDM_COLUMNS` list (drift is expected — see NAN-1155), so OR-ing it into the
  // Core/Extended decision would silently move some fields from "Extended" to
  // "Core" versus the old `!UDM_COLUMNS.has()` behavior. Gate to non-UDM so UDM
  // categorization stays byte-identical (mirrors AssetView's schemaFieldNames).
  const knownSchemaFields = React.useMemo(
    () =>
      schemaFields && schemaFields.schema !== 'udm'
        ? new Set(schemaFields.fields.map((f) => f.name))
        : new Set<string>(),
    [schemaFields],
  );
  // Per-event key-field summary chips follow the active schema (NAN-1241): under
  // OCSF the same row carries src_endpoint.ip/user.name/activity rather than the
  // UDM src_ip/src_host/user/event_type, so the spec must switch on the profile
  // or only `source_type` survives. Mirrors SearchResults RawView keyChipSpecs.
  const keyChipSpecs: Array<{ label: string; field: string; accent?: boolean }> =
    schemaFields?.schema === 'ocsf'
      ? [
          { label: 'sourcetype', field: 'source_type' },
          { label: 'src_ip', field: 'src_endpoint.ip' },
          { label: 'dest_ip', field: 'dst_endpoint.ip' },
          { label: 'user', field: 'user.name' },
          { label: 'status', field: 'status' },
          { label: 'activity', field: 'activity', accent: true },
        ]
      : [
          { label: 'sourcetype', field: 'source_type' },
          { label: 'src_ip', field: 'src_ip' },
          { label: 'src_host', field: 'src_host' },
          { label: 'dest_ip', field: 'dest_ip' },
          { label: 'dest_host', field: 'dest_host' },
          { label: 'user', field: 'user' },
          { label: 'dest_user', field: 'dest_user' },
          { label: 'event_type', field: 'event_type', accent: true },
        ];
  const widthRef = useRef(width);
  widthRef.current = width;
  const panelRef = useRef<HTMLDivElement>(null);
  const isResizing = useRef(false);

  // Measure the panel's actual top offset to compute an accurate height
  const [_panelTopOffset, setPanelTopOffset] = useState(96); // fallback ~6rem
  useEffect(() => {
    if (!panelRef.current) return;
    const measure = () => {
      const rect = panelRef.current?.getBoundingClientRect();
      if (rect) setPanelTopOffset(Math.max(rect.top, 48));
    };
    measure();
    // Re-measure on resize (browser chrome changes, etc.)
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [event.id]); // re-measure when switching events

  // Merge query fields with full log data
  const displayFields = fullLogData
    ? { ...event.fields, ...fullLogData }
    : event.fields;

  // NAN-1528: OTLP log↔trace correlation. When a log row carries a non-empty
  // trace_id (the column added to logs/ocsf_logs), surface a "View trace" pivot
  // that opens the distributed-trace waterfall.
  const rawTraceId = displayFields?.['trace_id'];
  const traceId =
    typeof rawTraceId === 'string' && rawTraceId.trim() && !isClickHouseDefault(rawTraceId, 'trace_id')
      ? rawTraceId.trim()
      : null;

  const isOcsf = schemaFields?.schema === 'ocsf';
  let flattenedFields = displayFields ? flattenEventFields(displayFields, isOcsf, '', knownSchemaFields) : [];
  if (hiddenEnrichments.size > 0) {
    flattenedFields = flattenedFields.filter(([k]) => !isFieldHidden(k, hiddenEnrichments));
  }

  // Reset expanded values when event changes
  useEffect(() => {
    setExpandedValues(new Set());
  }, [event.id]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't capture if user is typing in an input or CodeMirror editor
      const target = e.target as HTMLElement;
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) return;
      if (target.closest?.('.cm-editor')) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowUp' || e.key === 'k') {
        e.preventDefault();
        onNavigate('prev');
      } else if (e.key === 'ArrowDown' || e.key === 'j') {
        e.preventDefault();
        onNavigate('next');
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose, onNavigate]);

  // Resize handling
  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isResizing.current = true;
    const startX = e.clientX;
    const startWidth = width;

    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing.current) return;
      // Dragging left increases width (panel is on the right)
      const delta = startX - e.clientX;
      const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth + delta));
      setWidth(newWidth);
    };

    const handleMouseUp = () => {
      isResizing.current = false;
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      // Persist using ref to get the latest width (avoids stale closure)
      try { localStorage.setItem(STORAGE_KEY, String(widthRef.current)); } catch { /* ignore */ }
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, []);

  // Persist width on unmount
  useEffect(() => {
    return () => {
      try { localStorage.setItem(STORAGE_KEY, String(widthRef.current)); } catch { /* ignore */ }
    };
  }, []);

  const copyToClipboard = useCallback((text: string, fieldName: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 1500);
    });
  }, []);

  // Raw message
  const rawMessage = displayFields?.message as string | undefined;

  // OTLP/structured records (spans/metrics) have no raw-text `message`. The
  // structured record IS the raw, so build it from the row's REAL ingested
  // fields (internal `_*`/id/timestamp excluded) and show that in the Raw tab
  // instead of "No raw message available" (NAN-1568). Frontend-only.
  const syntheticRaw = !rawMessage
    ? (() => {
        const obj: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(displayFields ?? {})) {
          if (k.startsWith('_') || k === 'id' || k === 'timestamp') continue;
          if (v == null || v === '') continue;
          obj[k] = v;
        }
        return Object.keys(obj).length ? JSON.stringify(obj, null, 2) : null;
      })()
    : null;

  // Full JSON
  const fullJson = JSON.stringify(displayFields, null, 2);

  // Group fields by category for the Fields tab (shared with the inline view).
  const fieldCategories = React.useMemo(
    () => buildFieldCategories(flattenedFields, knownSchemaFields, isOcsf),
    [flattenedFields, knownSchemaFields, isOcsf],
  );

  const tabs: { id: InspectorTab; label: string; count?: number }[] = [
    { id: 'fields', label: 'Fields', count: flattenedFields.length },
    { id: 'raw', label: 'Raw' },
    { id: 'json', label: 'JSON' },
  ];


  return (
    <div className="flex-shrink-0 sticky top-0 border border-border rounded-r-lg overflow-hidden" style={{ width }}>
    <div
      ref={panelRef}
      className="search-workspace-section relative max-h-[calc(100dvh-8rem)] overflow-y-auto"
      style={{ background: 'var(--card)' }}
    >
      {/* Resize handle */}
      <div
        className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary/40 active:bg-primary/60 z-10 flex items-center justify-center"
        onMouseDown={handleResizeStart}
      >
        <GripVertical className="w-3 h-3 text-muted-foreground/20 translate-x-[-4px]" />
      </div>

      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2.5 sticky top-0 z-10" style={{ background: 'var(--card)' }}>
        <div className="min-w-0">
          <div className="min-w-0">
            <div className="search-console-section-header truncate"><ScanEye />Event Inspector</div>
            <div className="mt-1 flex items-center gap-2 min-w-0">
              <div className="search-console-section-meta truncate">
                {formatUTCShort(event.timestamp)}
              </div>
              {eventIndex !== undefined && totalCount !== undefined && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-border shrink-0">
                  {eventIndex + 1} / {totalCount}
                </Badge>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-0 shrink-0 text-muted-foreground">
          {traceId && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={() => navigate(`/trace/${encodeURIComponent(traceId)}`)}
                    className="h-5 px-1.5 mr-1 flex items-center gap-1 rounded-sm cursor-pointer text-primary bg-primary/10 hover:bg-primary/16 transition-colors text-[10px] font-medium"
                  >
                    <GitBranch className="w-3 h-3" />
                    <span>Trace</span>
                  </button>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="text-xs">View distributed trace</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={() => onNavigate('prev')}
                  className="w-5 h-5 flex items-center justify-center rounded-sm cursor-pointer hover:bg-foreground/5 hover:text-foreground transition-colors"
                >
                  <ChevronLeft className="w-3 h-3" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="text-xs">Previous event (↑)</TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={() => onNavigate('next')}
                  className="w-5 h-5 flex items-center justify-center rounded-sm cursor-pointer hover:bg-foreground/5 hover:text-foreground transition-colors"
                >
                  <ChevronRight className="w-3 h-3" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="text-xs">Next event (↓)</TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close inspector"
            className="w-5 h-5 flex items-center justify-center rounded-sm cursor-pointer hover:bg-foreground/5 hover:text-foreground transition-colors"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Key fields summary */}
      <div className="px-3 py-2 sticky top-[45px] z-10" style={{ background: 'var(--card)' }}>
        <div className="flex flex-wrap gap-1 font-mono text-[10.5px]">
          {keyChipSpecs.map(({ label: displayField, field, accent }) => {
            // NAN-2208: `event_type` is UDM's canonical name for the physical
            // `action` column. Both read paths now emit `event_type`, but a row
            // cached from before the fix (or a hand-built payload) may still
            // carry only `action` — mirror SearchResults' fallback rather than
            // rendering a blank chip. Harmless under OCSF, which has neither.
            const value =
              field === 'event_type'
                ? (displayFields?.event_type ?? displayFields?.action)
                : displayFields?.[field];
            if (!value || isClickHouseDefault(value, field)) return null;
            return (
              <span
                key={field}
                className={`inline-flex rounded-sm overflow-hidden border transition-colors ${
                  accent ? 'border-primary/25 hover:border-primary/50' : 'border-border hover:border-border/80'
                }`}
              >
                <span
                  className={`px-1.5 py-0 border-r ${
                    accent
                      ? 'bg-primary/15 text-primary border-primary/25'
                      : 'text-muted-foreground bg-foreground/[0.03] border-border'
                  }`}
                >
                  {displayField}
                </span>
                <span className={`px-1.5 py-0 ${accent ? 'text-primary font-semibold' : 'text-str'}`}>
                  <FieldValueMenu
                    fieldName={field}
                    value={value}
                    displayValue={String(value)}
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
      </div>

      {/* Tabs */}
      <div className="px-3 py-2 border-b border-border sticky top-[73px] z-10" style={{ background: 'var(--card)' }}>
        <div className="inline-flex items-center gap-0.5 p-0.5 rounded-md bg-foreground/[0.03] border border-border w-fit">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`h-auto py-0.5 px-2.5 rounded-sm text-[10.5px] font-mono tracking-[0.08em] font-semibold transition-colors inline-flex items-center gap-1 ${
                activeTab === tab.id
                  ? 'bg-primary/15 text-primary ring-1 ring-primary/25'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className="text-[9.5px] opacity-70">{tab.count}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div>
        {isLoadingFullData && (
          <div className="flex items-center gap-2 px-4 py-2 text-xs text-muted-foreground border-b border-border/30">
            <div className="w-3 h-3 border-2 border-muted-foreground/30 border-t-muted-foreground rounded-full animate-spin" />
            Hydrating full event...
          </div>
        )}

        {activeTab === 'fields' && (
          <div className="divide-y divide-border/20">
            {fieldCategories.map(category => (
              <div key={category.label}>
                <div className="px-4 py-1.5 bg-muted/30 sticky top-0 z-[1]">
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className={`text-[10px] font-semibold uppercase tracking-wider cursor-default ${category.color}`}>
                          {category.label}
                          <span className="text-muted-foreground ml-1">({category.fields.length})</span>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="right" className="text-xs max-w-60">
                        {category.tooltip}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
                <div className="text-xs font-mono">
                  {category.fields
                    .filter(([, v]) => !(Array.isArray(v) && (v as unknown[]).length === 0))
                    .map(([k, v]) => {
                      const displayValue = formatValue(v);
                      const detailKey = `inspector:${k}`;
                      const isValueExpanded = expandedValues.has(detailKey);
                      const shouldTruncate = !isValueExpanded && displayValue.length > 200;
                      const truncatedValue = shouldTruncate ? displayValue.substring(0, 200) : displayValue;

                      return (
                        <div
                          key={k}
                          className="group hover:bg-muted/20 px-4 py-1.5 flex flex-col gap-0.5"
                        >
                          {/* Key: full name always visible on its own line —
                              wraps instead of truncating, no matter how long the
                              OCSF dotted path (or UDM name) is. */}
                          <div className="flex items-start gap-1 text-muted-foreground min-w-0">
                            <span className="break-all leading-tight" title={k}>
                              {(() => {
                                const { namespace, leaf } = splitFieldKey(k);
                                return namespace
                                  ? <><span className="opacity-50">{namespace}</span>{leaf}</>
                                  : leaf;
                              })()}
                            </span>
                            <button
                              onClick={() => copyToClipboard(displayValue, k)}
                              className="opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 mt-px"
                              title="Copy value"
                            >
                              {copiedField === k ? (
                                <Check className="w-3 h-3 text-green-400" />
                              ) : (
                                <Copy className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                              )}
                            </button>
                          </div>
                          {/* Value: full panel width on its own line, slightly
                              indented to separate it from the next field's key. */}
                          <div className="min-w-0 break-all whitespace-pre-wrap pl-3">
                            <FieldValueMenu
                              fieldName={k}
                              value={v}
                              displayValue={truncatedValue}
                              onAddToQuery={onAddToQuery}
                              onSetQuery={onSetQuery}
                              query={query}
                              highlightKeywords={highlightKeywords}
                              className="text-str"
                              notebookActive={notebookActive}
                              onAddToNotebook={onAddToNotebook}
                            />
                            {shouldTruncate && (
                              <button
                                onClick={() => setExpandedValues(prev => new Set(prev).add(detailKey))}
                                className="ml-1 text-muted-foreground hover:text-primary cursor-pointer"
                                title="Show full value"
                              >
                                ...
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'raw' && (
          <div className="p-4">
            <div className="flex justify-end mb-2">
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 gap-1 text-xs"
                onClick={() => copyToClipboard(rawMessage || '', '_raw')}
              >
                {copiedField === '_raw' ? (
                  <><Check className="w-3 h-3" /> Copied</>
                ) : (
                  <><Copy className="w-3 h-3" /> Copy</>
                )}
              </Button>
            </div>
            {!rawMessage && syntheticRaw && (
              <div className="text-[10.5px] text-muted-foreground italic mb-1">
                structured record (OTLP — no raw text)
              </div>
            )}
            <pre className="text-xs font-mono text-foreground whitespace-pre-wrap break-all bg-muted/30 rounded-lg p-3 border border-border/30">
              {rawMessage || syntheticRaw || <span className="text-muted-foreground italic">No raw message available</span>}
            </pre>
          </div>
        )}

        {activeTab === 'json' && (
          <div className="p-4">
            <div className="flex justify-end mb-2">
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 gap-1 text-xs"
                onClick={() => copyToClipboard(fullJson, '_json')}
              >
                {copiedField === '_json' ? (
                  <><Check className="w-3 h-3" /> Copied</>
                ) : (
                  <><Copy className="w-3 h-3" /> Copy</>
                )}
              </Button>
            </div>
            <pre className="text-xs font-mono text-foreground whitespace-pre-wrap break-all bg-muted/30 rounded-lg p-3 border border-border/30 max-h-[calc(100vh-300px)] overflow-y-auto">
              {fullJson}
            </pre>
          </div>
        )}
      </div>

      {/* Footer with keyboard hints */}
      <div className="px-4 py-2 border-t border-border flex-shrink-0 flex items-center gap-3 text-[10px] text-muted-foreground sticky bottom-0 bg-card">
        <span><kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">↑↓</kbd> step</span>
        <span><kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">Esc</kbd> close</span>
      </div>
    </div>
    </div>
  );
}
