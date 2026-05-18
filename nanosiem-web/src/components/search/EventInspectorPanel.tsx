// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { X, Copy, Check, ChevronLeft, ChevronRight, GripVertical, ScanEye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { formatUTCShort } from '@/lib/date-utils';
import { UDM_COLUMNS } from '@/lib/udm-fields';
import { isClickHouseDefault } from '@/lib/utils';

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
// Field utilities (mirrors SearchResults.tsx logic)
// ============================================================================

function flattenFields(fields: Record<string, unknown>, prefix = ''): [string, unknown][] {
  const result: [string, unknown][] = [];

  for (const [key, value] of Object.entries(fields)) {
    const fullKey = prefix ? `${prefix}_${key}` : key;

    if (key.startsWith('prevalence_') && (value === 255 || value === 65535 || value === 9999)) continue;
    if (key === 'risk_score' && (value === 0 || value === '0')) continue;

    const isPrevalence = key === 'host_count' || key === 'is_rare' || key === 'prevalence_score' ||
                         key === 'prevalence_type' || key === 'total_occurrences' ||
                         key === '_prevalence' || key.startsWith('_prevalence.');
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
        result.push(...flattenFields(metadataObj, 'metadata'));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (key === '_prevalence') {
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        result.push(...flattenFields(value as Record<string, unknown>, '_prevalence'));
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (typeof value === 'object' && !Array.isArray(value) && prefix === '') {
      result.push([fullKey, value]);
    } else {
      result.push([fullKey, value]);
    }
  }

  const getFieldCategory = (fieldName: string): number => {
    if (fieldName === 'risk_score' || fieldName === 'risk_entity' ||
        fieldName === 'risk_factors' || fieldName.startsWith('risk_')) return 1;
    if (fieldName.startsWith('ioc_')) return 2;
    if (fieldName.startsWith('identity_') || fieldName === 'is_nat_candidate') return 3;
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

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

function isIocField(fieldName: string): boolean {
  return fieldName.startsWith('ioc_');
}

function isRiskField(fieldName: string): boolean {
  return fieldName === 'risk_score' || fieldName === 'risk_entity' || fieldName === 'risk_factors';
}

function isPrevalenceField(fieldName: string): boolean {
  return fieldName === 'host_count' || fieldName === 'is_rare' ||
         fieldName === 'prevalence_score' || fieldName === 'prevalence_type' ||
         fieldName === 'prevalence_artifact' || fieldName === 'total_occurrences' ||
         fieldName === 'first_seen' || fieldName === 'last_seen' ||
         fieldName === '_prevalence' || fieldName.startsWith('_prevalence.') ||
         fieldName === 'prevalence_file_hash' || fieldName === 'prevalence_process_hash' ||
         fieldName === 'prevalence_dest_domain' || fieldName === 'prevalence_dest_ip' ||
         fieldName === 'prevalence_min';
}

function isLookupField(fieldName: string): boolean {
  return fieldName.startsWith('lookup_');
}

function isIdentityField(fieldName: string): boolean {
  return fieldName.startsWith('identity_') || fieldName === 'is_nat_candidate';
}

function isExtField(fieldName: string): boolean {
  return !UDM_COLUMNS.has(fieldName) && !fieldName.startsWith('enriched_') &&
         !fieldName.startsWith('ioc_') && !fieldName.startsWith('lookup_') &&
         !fieldName.startsWith('metadata_') && !fieldName.startsWith('identity_') &&
         !fieldName.startsWith('prevalence_') && !fieldName.startsWith('_prevalence') &&
         !fieldName.startsWith('risk_') && fieldName !== 'is_nat_candidate';
}

// Enrichment category check (mirrors SearchResults)
const ENRICHMENT_CATEGORIES: Record<string, (k: string) => boolean> = {
  ioc: (k) => k.startsWith('ioc_'),
  custom: (k) => k.startsWith('lookup_custom_'),
  prevalence: (k) => isPrevalenceField(k),
  lookup: (k) => k.startsWith('lookup_') && !k.startsWith('lookup_custom_'),
  geo: (k) => k.startsWith('enriched_'),
  identity: (k) => k.startsWith('identity_') || k === 'is_nat_candidate',
  metadata: (k) => k.startsWith('metadata_'),
};

function isFieldHidden(fieldName: string, hiddenEnrichments: Set<string>): boolean {
  for (const [category, check] of Object.entries(ENRICHMENT_CATEGORIES)) {
    if (hiddenEnrichments.has(category) && check(fieldName)) return true;
  }
  return false;
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
  const [activeTab, setActiveTab] = useState<InspectorTab>('fields');
  const [expandedValues, setExpandedValues] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [width, setWidth] = useState(getStoredWidth);
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

  let flattenedFields = displayFields ? flattenFields(displayFields) : [];
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

  // Full JSON
  const fullJson = JSON.stringify(displayFields, null, 2);

  // Group fields by category for the Fields tab
  const fieldCategories = React.useMemo(() => {
    // Core (base UDM columns) stays neutral; everything else — derived /
    // enriched / extended data — shares one subtle brand accent so a reader
    // can tell at a glance which fields are "added on top" of the base event.
    const NEUTRAL = 'text-muted-foreground';
    const ACCENT = 'text-primary/80';
    const categories: { label: string; color: string; tooltip: string; fields: [string, unknown][] }[] = [
      { label: 'Core', color: NEUTRAL, tooltip: 'Indexed UDM columns with bloom filters for fast search', fields: [] },
      { label: 'Risk', color: ACCENT, tooltip: 'Risk scores and factors from detection rules', fields: [] },
      { label: 'IOC', color: ACCENT, tooltip: 'Indicators of compromise from threat intelligence feeds', fields: [] },
      { label: 'Identity', color: ACCENT, tooltip: 'Identity resolution fields (NAT detection, user mapping)', fields: [] },
      { label: 'Prevalence', color: ACCENT, tooltip: 'Rarity metrics — how common this artifact is across your environment', fields: [] },
      { label: 'Lookup', color: ACCENT, tooltip: 'Enrichments from lookup tables', fields: [] },
      { label: 'Enrichment', color: ACCENT, tooltip: 'Auto-enriched fields (geo, ASN, reputation)', fields: [] },
      { label: 'Metadata', color: ACCENT, tooltip: 'Parser metadata and processing info', fields: [] },
      { label: 'Extended', color: ACCENT, tooltip: 'Additional fields from the ext JSON column', fields: [] },
    ];

    for (const field of flattenedFields) {
      const [k] = field;
      if (Array.isArray(field[1]) && (field[1] as unknown[]).length === 0) continue;
      if (isRiskField(k)) categories[1].fields.push(field);
      else if (isIocField(k)) categories[2].fields.push(field);
      else if (isIdentityField(k)) categories[3].fields.push(field);
      else if (isPrevalenceField(k)) categories[4].fields.push(field);
      else if (isLookupField(k)) categories[5].fields.push(field);
      else if (k.startsWith('enriched_')) categories[6].fields.push(field);
      else if (k.startsWith('metadata_')) categories[7].fields.push(field);
      else if (isExtField(k)) categories[8].fields.push(field);
      else categories[0].fields.push(field);
    }

    return categories.filter(c => c.fields.length > 0);
  }, [flattenedFields]);

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
          {(['source_type', 'src_ip', 'src_host', 'dest_ip', 'dest_host', 'user', 'event_type'] as const).map(field => {
            const value = displayFields?.[field];
            if (!value || isClickHouseDefault(value, field)) return null;
            const accent = field === 'event_type';
            const displayField = field === 'source_type' ? 'sourcetype' : field;
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
                <table className="w-full text-xs font-mono">
                  <tbody>
                    {category.fields
                      .filter(([, v]) => !(Array.isArray(v) && (v as unknown[]).length === 0))
                      .map(([k, v]) => {
                        const displayValue = formatValue(v);
                        const detailKey = `inspector:${k}`;
                        const isValueExpanded = expandedValues.has(detailKey);
                        const shouldTruncate = !isValueExpanded && displayValue.length > 200;
                        const truncatedValue = shouldTruncate ? displayValue.substring(0, 200) : displayValue;

                        return (
                          <tr key={k} className="group hover:bg-muted/20">
                            <td className="py-1.5 pl-4 pr-2 align-top w-40 text-muted-foreground font-mono">
                              <div className="flex items-center gap-1">
                                <span className="truncate">{k}</span>
                                <button
                                  onClick={() => copyToClipboard(displayValue, k)}
                                  className="opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
                                  title="Copy value"
                                >
                                  {copiedField === k ? (
                                    <Check className="w-3 h-3 text-green-400" />
                                  ) : (
                                    <Copy className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="py-1.5 pr-4 align-top break-all whitespace-pre-wrap">
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
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
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
            <pre className="text-xs font-mono text-foreground whitespace-pre-wrap break-all bg-muted/30 rounded-lg p-3 border border-border/30">
              {rawMessage || <span className="text-muted-foreground italic">No raw message available</span>}
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
