// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { Cloud, Shield, ChevronDown, ChevronRight, Server, Globe, MapPin, User, KeyRound, Search, X, Loader2, AlertTriangle, Users } from 'lucide-react';
import { api } from '@/lib/api';
import type { CloudEventFilters, CloudFacets, CloudEventsRequest, CloudUserActivity } from '@/lib/api/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { formatUTCShort, formatCompactNumber } from '@/lib/date-utils';
import { CloudUserTimelineSheet } from './CloudUserTimelineSheet';
import { CloudEntityPivotSheet } from './CloudEntityPivotSheet';
import { CopyableValue } from './CopyableValue';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';

// ============================================================================
// Types
// ============================================================================

interface FacetValue {
  value: string;
  count: number;
}

interface CloudSummary {
  cloud_provider?: FacetValue[];
  cloud_service?: FacetValue[];
  cloud_region?: FacetValue[];
  cloud_account_id?: FacetValue[];
  resource_type?: FacetValue[];
  change_type?: FacetValue[];
}

// Schema-agnostic cloud event (NAN-1241): the backend normalizes its cloud
// SELECT back to these canonical UDM keys under both UDM and OCSF, so the named
// fields stay strongly typed; the index signature admits extra schema-specific
// keys without breaking the contract.
interface CloudEvent {
  timestamp: string;
  cloud_provider: string;
  cloud_service: string;
  cloud_region: string;
  cloud_account_id: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  change_type: string;
  mfa_used: number;
  user: string;
  src_ip: string;
  http_user_agent: string;
  source_type: string;
  event_type: string;
  [key: string]: unknown;
}

interface CloudPagination {
  total_count: number;
  offset: number;
  limit: number;
  has_more: boolean;
  facets?: CloudFacets;
}

interface CloudResource {
  resource_id: string;
  resource_name: string;
  resource_type: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  change_types: string[];
}

interface MfaUser {
  user: string;
  services: string[];
  mfa_count: number;
  no_mfa_count: number;
}

interface CloudMfa {
  users: MfaUser[];
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface CloudViewProps {
  results: SearchResult[];
  onDrilldown?: (filters: Record<string, unknown>) => void;
  timeRange?: { start: string; end: string };
  query?: string;
}

// Map from facet dimension name to CloudEventFilters key
const FACET_TO_FILTER_KEY: Record<string, keyof CloudEventFilters> = {
  cloud_provider: 'cloud_providers',
  cloud_service: 'cloud_services',
  cloud_region: 'cloud_regions',
  cloud_account_id: 'cloud_account_ids',
  resource_type: 'resource_types',
  change_type: 'change_types',
};

// ============================================================================
// Helpers
// ============================================================================

function ChangeTypeBadge({ type: changeType }: { type: string }) {
  return (
    <Badge variant="outline" className="text-xs">
      {changeType}
    </Badge>
  );
}

const FACET_ICONS: Record<string, React.ReactNode> = {
  cloud_provider: <Cloud className="h-3.5 w-3.5" />,
  cloud_service: <Server className="h-3.5 w-3.5" />,
  cloud_region: <MapPin className="h-3.5 w-3.5" />,
  cloud_account_id: <User className="h-3.5 w-3.5" />,
  resource_type: <Globe className="h-3.5 w-3.5" />,
  change_type: <Shield className="h-3.5 w-3.5" />,
};

const FACET_LABELS: Record<string, string> = {
  cloud_provider: 'Provider',
  cloud_service: 'Service',
  cloud_region: 'Region',
  cloud_account_id: 'Account',
  resource_type: 'Resource Type',
  change_type: 'Change Type',
};

const EVT_COLS = ['Timestamp','Provider','Service','Region','Resource','Change','User','Source IP','User Agent'] as const;

const USR_COLS = [
  { label: 'User', align: '' },
  { label: 'Hits', align: 'text-right' },
  { label: 'Svc', align: 'text-right' },
  { label: 'Regions', align: 'text-right' },
  { label: 'IPs', align: 'text-right' },
  { label: 'Fails', align: 'text-right' },
  { label: 'Perm', align: 'text-right' },
  { label: 'Del', align: 'text-right' },
  { label: 'MFA %', align: 'text-right' },
  { label: 'Risk', align: '' },
] as const;

// ============================================================================
// Resizable column hook
// ============================================================================

function useResizableColumns(initialWidths: number[]) {
  const [widths, setWidths] = useState<number[]>(initialWidths);
  const widthsRef = useRef(widths);
  widthsRef.current = widths;
  const dragging = useRef<{ col: number; startX: number; startW: number } | null>(null);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragging.current) return;
      const { col, startX, startW } = dragging.current;
      const newW = Math.max(40, startW + (e.clientX - startX));
      setWidths(prev => { const n = [...prev]; n[col] = newW; return n; });
    };
    const onUp = () => {
      if (!dragging.current) return;
      dragging.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    return () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); };
  }, []);

  const onResizeStart = useCallback((col: number, e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = { col, startX: e.clientX, startW: widthsRef.current[col] };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  const totalWidth = widths.reduce((a, b) => a + b, 0);

  return { widths, totalWidth, onResizeStart };
}

/** Thin draggable handle rendered inside each <th> */
function ResizeHandle({ onMouseDown }: { onMouseDown: (e: React.MouseEvent) => void }) {
  return (
    <div
      className="absolute right-0 top-1.5 bottom-1.5 w-1.5 cursor-col-resize border-r border-border hover:border-primary/50 active:border-primary z-10"
      onMouseDown={onMouseDown}
    />
  );
}

// ============================================================================
// Facet Panel (with exclude-on-click)
// ============================================================================

function FacetPanel({
  dimension,
  values,
  excludedValues,
  onToggleExclude,
}: {
  dimension: string;
  values: FacetValue[];
  excludedValues: Set<string>;
  onToggleExclude: (dimension: string, value: string) => void;
}) {
  const maxCount = values[0]?.count || 1;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-1">
        {FACET_ICONS[dimension]}
        {FACET_LABELS[dimension] || dimension}
      </div>
      {values.slice(0, 8).map((v) => {
        const isExcluded = excludedValues.has(v.value);
        return (
          <button
            key={v.value}
            className={`w-full group flex items-center gap-2 text-left rounded px-1.5 py-0.5 transition-colors ${
              isExcluded
                ? 'opacity-40 hover:opacity-60 line-through'
                : 'hover:bg-accent/50'
            }`}
            onClick={() => onToggleExclude(dimension, v.value)}
            title={isExcluded ? `Include: ${v.value}` : `Exclude: ${v.value}`}
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs truncate">{v.value || '(empty)'}</span>
                <span className="text-xs text-muted-foreground shrink-0">
                  {formatCompactNumber(v.count)}
                </span>
              </div>
              <div className="h-1 bg-muted rounded-full mt-0.5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-colors ${
                    isExcluded
                      ? 'bg-destructive/30'
                      : 'bg-primary/40 group-hover:bg-primary/60'
                  }`}
                  style={{ width: `${(v.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

// ============================================================================
// Resource Card
// ============================================================================

function ResourceCard({ resource }: { resource: CloudResource }) {
  const [open, setOpen] = useState(false);
  const displayName = resource.resource_name || resource.resource_id;
  const primaryChange = resource.change_types[0] || 'activity';
  const additionalChangeCount = Math.max(0, resource.change_types.length - 1);

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="w-full">
        <div className="grid grid-cols-[18px_minmax(0,1.6fr)_minmax(0,1fr)_110px] items-center gap-3 px-3 py-3 hover:bg-accent/40 rounded transition-colors text-left">
          <div className="text-muted-foreground">
            {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" />}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-sm font-medium truncate">
                {displayName}
              </span>
              {resource.resource_type && (
                <Badge variant="outline" className="text-[10px] font-mono">
                  {resource.resource_type}
                </Badge>
              )}
            </div>
            <div className="search-console-section-meta mt-1 truncate">
              {resource.resource_id}
            </div>
          </div>
          <div className="min-w-0">
            <div className="text-xs text-foreground truncate">
              {primaryChange}
              {additionalChangeCount > 0 ? ` +${additionalChangeCount}` : ''}
            </div>
            <div className="search-console-section-meta mt-1 truncate">
              First {formatUTCShort(new Date(resource.first_seen))} · Last {formatUTCShort(new Date(resource.last_seen))}
            </div>
          </div>
          <div className="justify-self-end text-right">
            <div className="text-sm font-mono text-foreground">{formatCompactNumber(resource.event_count)}</div>
            <div className="search-console-section-meta mt-1">events</div>
          </div>
        </div>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="pl-[33px] pr-3 pb-3">
          <div className="grid gap-3 rounded-lg border border-border/60 bg-muted/10 p-3 md:grid-cols-2">
            <div>
              <div className="search-console-section-meta mb-1">Resource ID</div>
              <div className="font-mono text-xs text-foreground break-all">{resource.resource_id}</div>
            </div>
            <div>
              <div className="search-console-section-meta mb-1">Resource Type</div>
              <div className="text-xs text-foreground">{resource.resource_type || '-'}</div>
            </div>
            <div>
              <div className="search-console-section-meta mb-1">First Seen</div>
              <div className="font-mono text-xs text-foreground">{formatUTCShort(new Date(resource.first_seen))}</div>
            </div>
            <div>
              <div className="search-console-section-meta mb-1">Last Seen</div>
              <div className="font-mono text-xs text-foreground">{formatUTCShort(new Date(resource.last_seen))}</div>
            </div>
          </div>
          <div className="mt-3">
            <div className="search-console-section-meta mb-1.5">Change Types</div>
            <div className="flex flex-wrap gap-1">
            {resource.change_types.map((ct) => (
              <ChangeTypeBadge key={ct} type={ct} />
            ))}
            </div>
          </div>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

// ============================================================================
// MFA Panel
// ============================================================================

function MfaPanel({ mfa, onUserClick }: { mfa: CloudMfa; onUserClick?: (user: string) => void }) {
  if (!mfa.users || mfa.users.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            MFA Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">All users used MFA for every request.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <KeyRound className="h-4 w-4" />
          MFA Analysis — Users Without MFA
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs">User</TableHead>
              <TableHead className="text-xs">Services</TableHead>
              <TableHead className="text-xs text-right">With MFA</TableHead>
              <TableHead className="text-xs text-right">Without MFA</TableHead>
              <TableHead className="text-xs text-right w-32">MFA %</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {mfa.users.map((u) => {
              const total = u.mfa_count + u.no_mfa_count;
              const pct = total > 0 ? Math.round((u.mfa_count / total) * 100) : 0;
              return (
                <TableRow key={u.user}>
                  <TableCell className="text-xs font-medium">
                    {onUserClick ? (
                      <CopyableValue value={u.user} className="text-primary hover:underline" onClick={() => onUserClick(u.user)} />
                    ) : <CopyableValue value={u.user} />}
                  </TableCell>
                  <TableCell className="text-xs">
                    <div className="flex flex-wrap gap-1">
                      {u.services.map((s) => (
                        <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-right">{formatCompactNumber(u.mfa_count)}</TableCell>
                  <TableCell className={`text-xs text-right ${u.no_mfa_count > 0 ? 'font-medium' : ''}`}>
                    {formatCompactNumber(u.no_mfa_count)}
                  </TableCell>
                  <TableCell className="text-xs text-right">
                    <div className="flex items-center gap-2 justify-end">
                      <Progress value={pct} className="h-1.5 w-16" />
                      <span className={pct < 30 ? 'text-destructive' : 'text-muted-foreground'}>{pct}%</span>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Cloud View (Main Component)
// ============================================================================

export function CloudView({ results, onDrilldown: _onDrilldown, timeRange, query }: CloudViewProps) {
  const data = results[0]?.fields || {};

  const groupBy = (data._cloud_group_by as string) || 'service';
  const initialEvents = (data._cloud_events as CloudEvent[]) || [];
  const initialPagination = (data._cloud_pagination as CloudPagination) || { total_count: 0, offset: 0, limit: 200, has_more: false };
  const initialResources = (data._cloud_resources as CloudResource[]) || [];
  const initialMfa = data._cloud_mfa as CloudMfa | undefined;
  const cloudQuery = (data._cloud_query as string) || query || '';

  // Parse initial facets from _cloud_summary — use JSON key for stable memo
  const initialSummary = (data._cloud_summary as CloudSummary) || {};
  const summaryKey = JSON.stringify(initialSummary);
  const initialFacets = React.useMemo<Record<string, FacetValue[]>>(() => {
    const result: Record<string, FacetValue[]> = {};
    for (const dim of ['cloud_provider', 'cloud_service', 'cloud_region', 'cloud_account_id', 'resource_type', 'change_type']) {
      const vals = initialSummary[dim as keyof CloudSummary];
      if (vals && vals.length > 0) {
        result[dim] = vals;
      }
    }
    return result;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summaryKey]);

  // Paginated events state
  const [paginatedEvents, setPaginatedEvents] = useState<CloudEvent[]>(initialEvents);
  const [paginatedPagination, setPaginatedPagination] = useState<CloudPagination>(initialPagination);
  const [isLoadingMore, setIsLoadingMore] = useState(false);

  // Panel data state (resources, MFA, users) — updated when filters change
  const [resources, setResources] = useState<CloudResource[]>(initialResources);
  const [mfa, setMfa] = useState<CloudMfa | undefined>(initialMfa);
  const initialUserActivity = (data._cloud_user_activity as CloudUserActivity[]) || [];
  const [userActivity, setUserActivity] = useState<CloudUserActivity[]>(initialUserActivity);

  // Sync paginatedEvents when results prop changes (e.g. new search delivers new envelope)
  const eventsKey = initialEvents.length > 0 ? (initialEvents[0] as CloudEvent)?.timestamp : '';
  useEffect(() => {
    if (initialEvents.length > 0) {
      setPaginatedEvents(initialEvents);
      setPaginatedPagination(initialPagination);
      setResources(initialResources);
      setMfa(initialMfa);
      setUserActivity(initialUserActivity);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventsKey]);

  // Server-side filters state
  const [searchText, setSearchText] = useState('');

  // Excluded facet values: dimension -> Set of excluded values
  const [excludedFacets, setExcludedFacets] = useState<Record<string, Set<string>>>({});

  // Current facet counts (updated from server responses)
  const [currentFacets, setCurrentFacets] = useState<Record<string, FacetValue[]>>(initialFacets);

  const [activeTab, setActiveTab] = useState<'events' | 'resources' | 'users'>('events');

  // Resizable column widths
  const evtCols = useResizableColumns([140, 90, 100, 110, 180, 80, 180, 110, 200]);
  const userCols = useResizableColumns([200, 70, 70, 70, 50, 50, 100, 65, 80, 160]);

  // Sheet state
  const [timelineUser, setTimelineUser] = useState<string | null>(null);
  const [pivotEntity, setPivotEntity] = useState<{ type: 'user' | 'ip' | 'resource'; value: string } | null>(null);

  // Navigation stack for back button in drawers
  type NavState = { timelineUser: string | null; pivotEntity: { type: 'user' | 'ip' | 'resource'; value: string } | null };
  const [navStack, setNavStack] = useState<NavState[]>([]);

  // Push current state before navigating
  const pushNav = useCallback(() => {
    setNavStack((prev) => [...prev, { timelineUser, pivotEntity }]);
  }, [timelineUser, pivotEntity]);

  // Entity click handler: opens pivot sheet (or user timeline for user entities)
  const handleEntityClick = useCallback((entityType: 'user' | 'ip' | 'resource', entityValue: string) => {
    pushNav();
    if (entityType === 'user') {
      setPivotEntity(null);
      setTimelineUser(entityValue);
    } else {
      setTimelineUser(null);
      setPivotEntity({ type: entityType, value: entityValue });
    }
  }, [pushNav]);

  // User click handler from entity pivot: switches to user timeline
  const handleUserClick = useCallback((user: string) => {
    pushNav();
    setPivotEntity(null);
    setTimelineUser(user);
  }, [pushNav]);

  // Back handler: pop nav stack
  const handleBack = useCallback(() => {
    setNavStack((prev) => {
      const next = [...prev];
      const last = next.pop();
      if (last) {
        setTimelineUser(last.timelineUser);
        setPivotEntity(last.pivotEntity);
      }
      return next;
    });
  }, []);

  // Clear nav stack when closing drawers entirely
  const handleCloseTimeline = useCallback(() => {
    setTimelineUser(null);
    setNavStack([]);
  }, []);
  const handleClosePivot = useCallback(() => {
    setPivotEntity(null);
    setNavStack([]);
  }, []);

  // Infinite scroll sentinel
  const sentinelRef = useRef<HTMLDivElement>(null);

  // Track whether user has interacted with filters (to skip initial debounce)
  const userInteracted = useRef(false);

  // Total count to display (from paginated state)
  const displayTotalCount = paginatedPagination.total_count;

  // Build filters from excluded facets
  const buildFiltersFromExclusions = useCallback((
    excluded: Record<string, Set<string>>,
    text?: string,
  ): CloudEventFilters => {
    const filters: CloudEventFilters = {};
    for (const [dimension, excludedSet] of Object.entries(excluded)) {
      if (excludedSet.size === 0) continue;
      // Include everything EXCEPT the excluded values
      const facetKey = FACET_TO_FILTER_KEY[dimension];
      if (!facetKey) continue;
      const allValues = initialFacets[dimension] || [];
      const included = allValues
        .map((v) => v.value)
        .filter((v) => !excludedSet.has(v));
      if (included.length > 0 && included.length < allValues.length) {
        (filters as Record<string, unknown>)[facetKey] = included;
      }
    }
    if (text) {
      filters.search_text = text;
    }
    return filters;
  }, [initialFacets]);

  // Apply filters — resets to offset 0, replaces events
  const applyFilters = useCallback(async (filters: CloudEventFilters) => {
    if (!cloudQuery || !timeRange) return;

    setIsLoadingMore(true);
    try {
      const request: CloudEventsRequest = {
        query: cloudQuery,
        time_range: {
          start: timeRange.start,
          end: timeRange.end,
        },
        offset: 0,
        limit: 200,
        filters: Object.keys(filters).length > 0 ? filters : undefined,
      };

      const response = await api.getCloudEvents(request);
      const events = (response.events || []) as unknown as CloudEvent[];
      setPaginatedEvents(events);
      setPaginatedPagination({
        total_count: response.total_count,
        offset: response.offset,
        limit: response.limit,
        has_more: response.has_more,
      });

      // Update current facet counts from response
      if (response.facets) {
        const newFacets: Record<string, FacetValue[]> = {};
        for (const dim of ['cloud_provider', 'cloud_service', 'cloud_region', 'cloud_account_id', 'resource_type', 'change_type'] as const) {
          const tuples = response.facets[dim] as [string, number][] | undefined;
          if (tuples && tuples.length > 0) {
            newFacets[dim] = tuples.map(([value, count]) => ({ value, count }));
          }
        }
        setCurrentFacets(newFacets);
      }

      // Update panel data when returned (offset=0 filter changes)
      if (response.resources) {
        setResources(response.resources as unknown as CloudResource[]);
      }
      if (response.user_activity) {
        setUserActivity(response.user_activity as unknown as CloudUserActivity[]);
      }
    } catch (e) {
      console.error('Failed to apply cloud filters:', e);
    } finally {
      setIsLoadingMore(false);
    }
  }, [cloudQuery, timeRange]);

  // Load more events (infinite scroll)
  const loadMore = useCallback(async () => {
    if (!cloudQuery || !timeRange || !paginatedPagination.has_more || isLoadingMore) return;

    setIsLoadingMore(true);
    try {
      const newOffset = paginatedEvents.length;
      const filters = buildFiltersFromExclusions(excludedFacets, searchText || undefined);

      const request: CloudEventsRequest = {
        query: cloudQuery,
        time_range: {
          start: timeRange.start,
          end: timeRange.end,
        },
        offset: newOffset,
        limit: 200,
        filters: Object.keys(filters).length > 0 ? filters : undefined,
      };

      const response = await api.getCloudEvents(request);
      const newEvents = (response.events || []) as unknown as CloudEvent[];
      setPaginatedEvents((prev) => [...prev, ...newEvents]);
      setPaginatedPagination({
        total_count: response.total_count,
        offset: response.offset,
        limit: response.limit,
        has_more: response.has_more,
      });
    } catch (e) {
      console.error('Failed to load more cloud events:', e);
    } finally {
      setIsLoadingMore(false);
    }
  }, [cloudQuery, timeRange, paginatedEvents.length, paginatedPagination.has_more, isLoadingMore, excludedFacets, searchText, buildFiltersFromExclusions]);

  // Facet toggle handler (exclude-on-click)
  const handleToggleExclude = useCallback((dimension: string, value: string) => {
    setExcludedFacets((prev) => {
      const next = { ...prev };
      const set = new Set(prev[dimension] || []);
      if (set.has(value)) {
        set.delete(value);
      } else {
        set.add(value);
      }
      next[dimension] = set;

      // Apply filters with new exclusions
      const filters = buildFiltersFromExclusions(next, searchText || undefined);
      applyFilters(filters);

      return next;
    });
  }, [buildFiltersFromExclusions, searchText, applyFilters]);

  // Debounced search text — only fires after user has typed (not on mount/re-render)
  useEffect(() => {
    if (!userInteracted.current) return;

    const timeout = setTimeout(() => {
      const filters = buildFiltersFromExclusions(excludedFacets, searchText || undefined);
      applyFilters(filters);
    }, 300);

    return () => clearTimeout(timeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchText]);

  // Infinite scroll observer
  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && paginatedPagination.has_more && !isLoadingMore) {
          loadMore();
        }
      },
      { rootMargin: '200px' }
    );

    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [paginatedPagination.has_more, isLoadingMore, loadMore]);

  // Provider badges for the summary bar
  const providers = initialFacets.cloud_provider || [];

  const facetOrder = ['cloud_provider', 'cloud_service', 'cloud_region', 'cloud_account_id', 'resource_type', 'change_type'];

  // Merge initial facets with current counts for display
  // When filters are active, use currentFacets directly so stale values are removed
  const displayFacets = React.useMemo(() => {
    const filtersActive = Object.values(excludedFacets).some((s) => s.size > 0) || !!searchText;
    const merged: Record<string, FacetValue[]> = {};
    for (const dim of facetOrder) {
      const initial = initialFacets[dim] || [];
      const current = currentFacets[dim] || [];
      if (filtersActive && current.length > 0) {
        // When filtering, show server-returned values (only relevant to filtered data)
        // but keep excluded values visible so user can re-include them
        const currentMap = new Map(current.map((v) => [v.value, v.count]));
        const excludedSet = excludedFacets[dim] || new Set();
        // Start with current filtered values
        const result = [...current];
        // Add back excluded values (with count 0) so user can toggle them back
        for (const v of initial) {
          if (excludedSet.has(v.value) && !currentMap.has(v.value)) {
            result.push({ value: v.value, count: 0 });
          }
        }
        merged[dim] = result;
      } else {
        // No filters: use initial for the set of values (stable), update counts from current
        const currentMap = new Map(current.map((v) => [v.value, v.count]));
        merged[dim] = initial.map((v) => ({
          value: v.value,
          count: currentMap.get(v.value) ?? v.count,
        }));
      }
    }
    return merged;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialFacets, currentFacets, excludedFacets, searchText]);

  const activeFacets = facetOrder.filter((d) => {
    const vals = displayFacets[d] || initialFacets[d];
    return vals && vals.length > 0;
  });

  const hasActiveFilters = Object.values(excludedFacets).some((s) => s.size > 0) || !!searchText;

  return (
    <div className="space-y-4 p-1">
      {/* Summary Bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="search-console-section-header"><Cloud />Cloud Investigation</div>
        <Badge variant="outline" className="text-xs">
          {formatCompactNumber(displayTotalCount)} events
        </Badge>
        <Badge variant="outline" className="text-xs">
          group by: {groupBy}
        </Badge>
        {providers.map((p) => (
          <Badge key={p.value} variant="outline" className="text-xs">
            {p.value} ({formatCompactNumber(p.count)})
          </Badge>
        ))}
        {hasActiveFilters && (
          <button
            className="text-xs text-muted-foreground hover:text-foreground underline"
            onClick={() => {
              setExcludedFacets({});
              setSearchText('');
              setResources(initialResources);
              setMfa(initialMfa);
              setUserActivity(initialUserActivity);
              applyFilters({});
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Facet Panels */}
      {activeFacets.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {activeFacets.map((dim) => (
            <FacetPanel
              key={dim}
              dimension={dim}
              values={displayFacets[dim] || []}
              excludedValues={excludedFacets[dim] || new Set()}
              onToggleExclude={handleToggleExclude}
            />
          ))}
        </div>
      )}

      {/* MFA Panel (conditional) */}
      {mfa && <MfaPanel mfa={mfa} onUserClick={handleUserClick} />}

      {/* Tab Toggle */}
      <div className="flex gap-1 border-b">
        <button
          className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'events'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setActiveTab('events')}
        >
          Events ({formatCompactNumber(displayTotalCount)})
        </button>
        <button
          className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'resources'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setActiveTab('resources')}
        >
          Resources ({resources.length})
        </button>
        {userActivity.length > 0 && (
          <button
            className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors ${
              activeTab === 'users'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
            onClick={() => setActiveTab('users')}
          >
            <span className="inline-flex items-center gap-1">
              <Users className="h-3 w-3" />
              Users ({userActivity.length})
            </span>
          </button>
        )}
      </div>

      {/* Events Table */}
      {activeTab === 'events' && (
        <>
          {/* Search input */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              className="h-8 pl-8 pr-8 text-xs"
              placeholder="Search events (user, IP, resource, action...)"
              value={searchText}
              onChange={(e) => { userInteracted.current = true; setSearchText(e.target.value); }}
            />
            {searchText && (
              <button
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                onClick={() => { userInteracted.current = true; setSearchText(''); }}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Status bar */}
          <div className="text-xs text-muted-foreground flex items-center gap-2">
            Showing {paginatedEvents.length} of {formatCompactNumber(displayTotalCount)} events
            {isLoadingMore && <Loader2 className="h-3 w-3 animate-spin" />}
          </div>

          <div className="border rounded-md overflow-x-auto">
            <Table className="table-fixed w-full" style={{ minWidth: evtCols.totalWidth }}>
              <TableHeader>
                <TableRow>
                  {EVT_COLS.map((label, ci) => (
                    <TableHead
                      key={label}
                      className="text-xs relative"
                      style={ci < EVT_COLS.length - 1 ? { width: evtCols.widths[ci] } : undefined}
                    >
                      {label}
                      <ResizeHandle onMouseDown={(e) => evtCols.onResizeStart(ci, e)} />
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedEvents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-xs text-muted-foreground py-8">
                      {isLoadingMore ? 'Loading cloud events...' : 'No cloud events returned for the current scope'}
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedEvents.map((evt, i) => (
                    <TableRow key={i} className="hover:bg-accent/30">
                      <TableCell className="text-xs font-mono truncate" title={formatUTCShort(new Date(evt.timestamp))}>
                        {formatUTCShort(new Date(evt.timestamp))}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.cloud_provider}>
                        {evt.cloud_provider}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.cloud_service}>
                        {evt.cloud_service}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.cloud_region}>
                        {evt.cloud_region}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.resource_name || evt.resource_id}>
                        {(evt.resource_name || evt.resource_id) ? (
                          <CopyableValue
                            value={evt.resource_name || evt.resource_id}
                            className="text-primary hover:underline"
                            onClick={() => handleEntityClick('resource', evt.resource_name || evt.resource_id)}
                            truncate
                          />
                        ) : '-'}
                      </TableCell>
                      <TableCell className="text-xs truncate">
                        {evt.change_type ? <ChangeTypeBadge type={evt.change_type} /> : '-'}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.user}>
                        {evt.user ? (
                          <CopyableValue
                            value={evt.user}
                            className="text-primary hover:underline"
                            onClick={() => handleUserClick(evt.user)}
                            truncate
                          />
                        ) : '-'}
                      </TableCell>
                      <TableCell className="text-xs font-mono truncate" title={evt.src_ip}>
                        {evt.src_ip ? (
                          <CopyableValue
                            value={evt.src_ip}
                            className="text-primary hover:underline"
                            onClick={() => handleEntityClick('ip', evt.src_ip)}
                            truncate
                          />
                        ) : '-'}
                      </TableCell>
                      <TableCell className="text-xs truncate" title={evt.http_user_agent}>
                        {evt.http_user_agent || '-'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>

            {/* Infinite scroll sentinel */}
            <div ref={sentinelRef} className="h-1" />

            {/* Loading / status footer */}
            {isLoadingMore ? (
              <div className="p-3 text-center text-xs text-muted-foreground flex items-center justify-center gap-2 border-t">
                <Loader2 className="w-3 h-3 animate-spin" />
                Loading more events...
              </div>
            ) : paginatedPagination.has_more ? (
              <div className="text-xs text-muted-foreground text-center py-2 border-t">
                Scroll for more — {formatCompactNumber(displayTotalCount - paginatedEvents.length)} remaining
              </div>
            ) : paginatedEvents.length > 0 ? (
              <div className="text-xs text-muted-foreground text-center py-2 border-t">
                All {formatCompactNumber(displayTotalCount)} events loaded
              </div>
            ) : null}
          </div>
        </>
      )}

      {/* Resources List */}
      {activeTab === 'resources' && (
        <Card>
          <CardContent className="p-0 divide-y">
            {resources.length === 0 ? (
              <div className="text-xs text-muted-foreground text-center py-8">
                No resource identifiers were returned
              </div>
            ) : (
              resources.map((r) => <ResourceCard key={r.resource_id} resource={r} />)
            )}
          </CardContent>
        </Card>
      )}

      {/* Users Tab */}
      {activeTab === 'users' && (
        <div className="border rounded-md overflow-x-auto">
          <Table className="table-fixed w-full" style={{ minWidth: userCols.totalWidth }}>
            <TableHeader>
              <TableRow>
                {USR_COLS.map((col, ci) => (
                  <TableHead
                    key={col.label}
                    className={`relative text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/80 ${col.align}`}
                    style={ci < USR_COLS.length - 1 ? { width: userCols.widths[ci] } : undefined}
                  >
                    {col.label}
                    <ResizeHandle onMouseDown={(e) => userCols.onResizeStart(ci, e)} />
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {userActivity.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} className="text-center text-xs text-muted-foreground py-8">
                    No cloud user activity returned
                  </TableCell>
                </TableRow>
              ) : (
                userActivity.map((u) => {
                  const mfaTotal = u.mfa_count + u.no_mfa_count;
                  const mfaPct = mfaTotal > 0 ? Math.round((u.mfa_count / mfaTotal) * 100) : 0;
                  return (
                    <TableRow key={u.user} className="hover:bg-accent/30">
                      <TableCell className="text-xs font-medium truncate" title={u.user}>
                        <CopyableValue value={u.user} className="text-primary hover:underline" onClick={() => handleUserClick(u.user)} truncate />
                      </TableCell>
                      <TableCell className="text-xs text-right">{formatCompactNumber(u.event_count)}</TableCell>
                      <TableCell className="text-xs text-right">{u.distinct_services}</TableCell>
                      <TableCell className="text-xs text-right">{u.distinct_regions}</TableCell>
                      <TableCell className="text-xs text-right">{u.distinct_ips}</TableCell>
                      <TableCell className={`text-xs text-right ${u.fail_count > 0 && (u.fail_count / u.event_count) > 0.3 ? 'text-destructive font-medium' : ''}`}>
                        {u.fail_count}
                      </TableCell>
                      <TableCell className="text-xs text-right">
                        {u.permission_change_count}
                      </TableCell>
                      <TableCell className={`text-xs text-right ${u.delete_count > 10 ? 'text-destructive font-medium' : ''}`}>
                        {u.delete_count}
                      </TableCell>
                      <TableCell className="text-xs text-right">
                        <div className="flex items-center gap-1.5 justify-end">
                          <Progress value={mfaPct} className="h-1.5 w-12" />
                          <span className={mfaPct < 30 ? 'text-destructive' : 'text-muted-foreground'}>{mfaPct}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="flex flex-wrap gap-1">
                          {u.risk_indicators.map((ri) => (
                            <Badge key={ri} variant="outline" className="text-[10px] text-muted-foreground">
                              <AlertTriangle className="h-2.5 w-2.5 mr-0.5" />
                              {ri.replace(/_/g, ' ')}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Investigation Sheets */}
      {timeRange && (
        <>
          <CloudUserTimelineSheet
            user={timelineUser}
            onClose={handleCloseTimeline}
            query={cloudQuery}
            timeRange={timeRange}
            onEntityClick={handleEntityClick}
            onBack={navStack.length > 0 ? handleBack : undefined}
          />
          <CloudEntityPivotSheet
            entity={pivotEntity}
            onClose={handleClosePivot}
            query={cloudQuery}
            timeRange={timeRange}
            onEntityClick={handleEntityClick}
            onUserClick={handleUserClick}
            onBack={navStack.length > 0 ? handleBack : undefined}
          />
        </>
      )}
    </div>
  );
}
