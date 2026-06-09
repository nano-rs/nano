// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect } from 'react';
import { Globe, User, Server, Loader2, ArrowRight, ArrowLeft, ShieldAlert } from 'lucide-react';
import { api } from '@/lib/api';
import type { CloudEntityPivotResponse, EntityCrossReference } from '@/lib/api/types';
import { Badge } from '@/components/ui/badge';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { formatUTCShort, formatCompactNumber } from '@/lib/date-utils';
import { CopyableValue } from './CopyableValue';
import { useIsMobile } from '@/hooks/use-mobile';

// ============================================================================
// Types
// ============================================================================

interface CloudEntityPivotSheetProps {
  /** Entity to pivot on (null = closed) */
  entity: { type: 'user' | 'ip' | 'resource'; value: string } | null;
  /** Close handler */
  onClose: () => void;
  /** The nPL query context */
  query: string;
  /** Time range */
  timeRange: { start: string; end: string };
  /** Callback when an entity is clicked (chains pivots) */
  onEntityClick?: (entityType: 'user' | 'ip' | 'resource', entityValue: string) => void;
  /** Callback to open user timeline instead of entity pivot */
  onUserClick?: (user: string) => void;
  /** Back navigation handler (shown when there's history) */
  onBack?: () => void;
}

// Schema-agnostic cloud timeline event (NAN-1241): the backend normalizes its
// cloud SELECT back to these canonical UDM keys under both UDM and OCSF, so the
// named fields stay strongly typed; the index signature admits extra
// schema-specific keys without breaking the contract.
interface TimelineEvent {
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
  status: string;
  http_status_code: number;
  enriched_src_country_code: string;
  enriched_src_asn: string;
  enriched_src_as_name: string;
  ioc_src_ip_threat_type: string;
  ioc_src_ip_malware: string;
  ioc_src_ip_confidence: number;
  [key: string]: unknown;
}

// ============================================================================
// Helpers
// ============================================================================

function IocBadge({ threatType, malware, confidence }: { threatType: string; malware: string; confidence: number }) {
  if (!threatType) return null;
  const label = malware ? `${threatType}: ${malware}` : threatType;
  return (
    <Badge variant="outline" className="text-[10px] bg-red-500/20 text-red-700 dark:text-red-400 border-red-500/40">
      <ShieldAlert className="h-2.5 w-2.5 mr-1" />
      IOC {label}{confidence ? ` (${confidence}%)` : ''}
    </Badge>
  );
}

const ENTITY_TYPE_ICONS: Record<string, React.ReactNode> = {
  user: <User className="h-4 w-4" />,
  ip: <Globe className="h-4 w-4" />,
  resource: <Server className="h-4 w-4" />,
};

const ENTITY_TYPE_LABELS: Record<string, string> = {
  user: 'User',
  ip: 'IP Address',
  resource: 'Resource',
};

const CHANGE_TYPE_DOT_COLORS: Record<string, string> = {
  create: 'bg-green-500',
  update: 'bg-blue-500',
  delete: 'bg-red-500',
  permission_change: 'bg-amber-500',
  access: 'bg-zinc-400',
};

function StatusBadge({ code }: { code: number }) {
  if (!code) return null;
  if (code >= 400) {
    return <Badge variant="outline" className="text-[10px] bg-destructive/10 text-destructive border-destructive/30">{code}</Badge>;
  }
  return <Badge variant="outline" className="text-[10px]">{code}</Badge>;
}

// ============================================================================
// Cross-Reference Card
// ============================================================================

function CrossRefCard({
  xref,
  onEntityClick,
  onUserClick,
}: {
  xref: EntityCrossReference;
  onEntityClick?: (type: 'user' | 'ip' | 'resource', value: string) => void;
  onUserClick?: (user: string) => void;
}) {
  const icon = ENTITY_TYPE_ICONS[xref.entity_type] || <Globe className="h-3.5 w-3.5" />;
  const handleClick = () => {
    if (xref.entity_type === 'user' && onUserClick) {
      onUserClick(xref.entity_value);
    } else {
      onEntityClick?.(xref.entity_type as 'user' | 'ip' | 'resource', xref.entity_value);
    }
  };

  return (
    <div
      className="flex items-center gap-2 rounded-md border p-2 hover:bg-accent/50 transition-colors text-left w-full cursor-pointer"
      onClick={handleClick}
    >
      <div className="text-muted-foreground">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium truncate">
          <CopyableValue value={xref.entity_value} />
        </div>
        <div className="text-[10px] text-muted-foreground">
          {ENTITY_TYPE_LABELS[xref.entity_type] || xref.entity_type}
        </div>
      </div>
      <div className="text-xs text-muted-foreground shrink-0">
        {formatCompactNumber(xref.event_count)}
      </div>
      <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
    </div>
  );
}

// ============================================================================
// Component
// ============================================================================

export function CloudEntityPivotSheet({
  entity,
  onClose,
  query,
  timeRange,
  onEntityClick,
  onUserClick,
  onBack,
}: CloudEntityPivotSheetProps) {
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CloudEntityPivotResponse | null>(null);

  useEffect(() => {
    if (!entity) {
      setData(null);
      return;
    }

    setLoading(true);
    api.getCloudEntityPivot({
      query,
      time_range: { start: timeRange.start, end: timeRange.end },
      entity_type: entity.type,
      entity_value: entity.value,
    }).then((response) => {
      setData(response);
    }).catch((err) => {
      console.error('Failed to load entity pivot:', err);
    }).finally(() => {
      setLoading(false);
    });
  }, [entity?.type, entity?.value, query, timeRange.start, timeRange.end]);

  const events = (data?.events || []) as unknown as TimelineEvent[];
  const crossRefs = data?.cross_references || [];
  const summary = data?.entity_summary || {};

  // Build IP enrichment map from events
  const ipEnrichment = React.useMemo(() => {
    const map = new Map<string, { country: string; asn: string; asName: string; iocThreat: string; iocMalware: string; iocConf: number }>();
    for (const evt of events) {
      if (evt.src_ip && !map.has(evt.src_ip)) {
        map.set(evt.src_ip, {
          country: evt.enriched_src_country_code || '',
          asn: evt.enriched_src_asn || '',
          asName: evt.enriched_src_as_name || '',
          iocThreat: evt.ioc_src_ip_threat_type || '',
          iocMalware: evt.ioc_src_ip_malware || '',
          iocConf: evt.ioc_src_ip_confidence || 0,
        });
      }
    }
    return map;
  }, [events]);

  // Pull enrichment from first event with data (for IP header context)
  const firstEnriched = entity?.type === 'ip'
    ? events.find((e) => e.enriched_src_country_code)
    : null;

  // Check if any event for this entity has an IOC hit
  const iocEvent = events.find((e) => e.ioc_src_ip_threat_type);

  const iocIps = React.useMemo(
    () => [...ipEnrichment.entries()].filter(([, v]) => v.iocThreat),
    [ipEnrichment],
  );

  // Group cross-refs by type
  const userRefs = crossRefs.filter((x) => x.entity_type === 'user');
  const ipRefs = crossRefs.filter((x) => x.entity_type === 'ip');
  const resourceRefs = crossRefs.filter((x) => x.entity_type === 'resource');

  return (
    <Sheet open={!!entity} onOpenChange={(open) => { if (!open) onClose(); }}>
      <SheetContent
        side={isMobile ? 'bottom' : 'right'}
        className={isMobile
          ? 'h-[72vh] max-h-[72vh] p-0 border-t rounded-t-xl'
          : 'w-[760px] max-w-[min(760px,calc(100vw-32px))] p-0 border-l'}
      >
        <SheetHeader className="p-4 border-b border-border">
          <SheetTitle className="flex items-center gap-2 flex-wrap pr-8">
            {onBack && (
              <button onClick={onBack} className="rounded-md p-1 hover:bg-accent transition-colors -ml-1 mr-0.5">
                <ArrowLeft className="h-4 w-4" />
              </button>
            )}
            <span className="search-console-section-header"><Globe />Cloud Pivot</span>
            <span className="text-xs text-muted-foreground">
              {entity && ENTITY_TYPE_LABELS[entity.type]}
            </span>
            <span className="font-mono text-sm text-foreground">
              {entity && <CopyableValue value={entity.value} />}
            </span>
            {firstEnriched && (
              <span className="text-xs text-muted-foreground">
                {firstEnriched.enriched_src_country_code}
                {firstEnriched.enriched_src_asn ? ` / ${firstEnriched.enriched_src_asn}` : ''}
                {firstEnriched.enriched_src_as_name ? ` (${firstEnriched.enriched_src_as_name})` : ''}
              </span>
            )}
            {iocEvent && (
              <IocBadge threatType={iocEvent.ioc_src_ip_threat_type} malware={iocEvent.ioc_src_ip_malware} confidence={iocEvent.ioc_src_ip_confidence} />
            )}
            {(summary as Record<string, unknown>).event_count != null && (
              <Badge variant="outline" className="text-[10px]">
                {formatCompactNumber((summary as Record<string, unknown>).event_count as number)} events
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription className="search-console-section-meta">
            Related entities, chronology, and cloud activity around the selected pivot
          </SheetDescription>
        </SheetHeader>

        <div className="overflow-y-auto px-6 pt-4 pb-6" style={{ maxHeight: isMobile ? 'calc(72vh - 5rem)' : 'calc(100vh - 5rem)' }}>
        {loading ? (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading pivot context...
          </div>
        ) : data ? (
          <>
            {/* Entity summary */}
            {Object.keys(summary).length > 0 && (
              <div className="grid grid-cols-4 gap-2 mb-4">
                <div className="text-center">
                  <div className="text-xs text-muted-foreground">Events</div>
                  <div className="text-sm font-semibold">
                    {formatCompactNumber((summary as Record<string, unknown>).event_count as number || 0)}
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-muted-foreground">Fails</div>
                  <div className="text-sm font-semibold">
                    {(summary as Record<string, unknown>).fail_count as number || 0}
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-muted-foreground">First Seen</div>
                  <div className="text-[10px] font-mono">
                    {(summary as Record<string, unknown>).event_count && (summary as Record<string, unknown>).first_seen
                      ? formatUTCShort(new Date((summary as Record<string, unknown>).first_seen as string))
                      : '-'}
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-muted-foreground">Last Seen</div>
                  <div className="text-[10px] font-mono">
                    {(summary as Record<string, unknown>).event_count && (summary as Record<string, unknown>).last_seen
                      ? formatUTCShort(new Date((summary as Record<string, unknown>).last_seen as string))
                      : '-'}
                  </div>
                </div>
              </div>
            )}

            {/* Services and change types */}
            {((summary as Record<string, unknown>).services as string[] || []).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {((summary as Record<string, unknown>).services as string[]).map((s) => (
                  <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
                ))}
              </div>
            )}
            {((summary as Record<string, unknown>).change_types as string[] || []).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-4">
                {((summary as Record<string, unknown>).change_types as string[]).map((ct) => (
                  <Badge key={ct} variant="outline" className="text-[10px]">
                    {ct}
                  </Badge>
                ))}
              </div>
            )}

            {/* IOC alert banner */}
            {iocIps.length > 0 && (
              <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-3 mb-4">
                <ShieldAlert className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                <div>
                  <div className="text-xs font-medium text-red-700 dark:text-red-400">
                    Threat Intel Match — {iocIps.length} IP{iocIps.length > 1 ? 's' : ''}
                  </div>
                  <div className="text-[10px] text-red-600 dark:text-red-400/80 mt-0.5 space-y-0.5">
                    {iocIps.map(([ip, info]) => (
                      <div key={ip} className="font-mono">
                        {ip} — {info.iocThreat}{info.iocMalware ? `: ${info.iocMalware}` : ''}{info.iocConf ? ` (${info.iocConf}%)` : ''}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Cross-references */}
            {crossRefs.length > 0 && (
              <div className="mb-6">
                <h3 className="text-xs font-medium text-muted-foreground mb-2">
                  Related Entities ({crossRefs.length})
                </h3>
                <div className="space-y-3">
                  {userRefs.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                        <User className="h-3 w-3" /> Users ({userRefs.length})
                      </div>
                      <div className="grid grid-cols-3 gap-1.5">
                        {userRefs.slice(0, 10).map((xref) => (
                          <CrossRefCard key={xref.entity_value} xref={xref} onEntityClick={onEntityClick} onUserClick={onUserClick} />
                        ))}
                      </div>
                    </div>
                  )}
                  {ipRefs.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                        <Globe className="h-3 w-3" /> IPs ({ipRefs.length})
                      </div>
                      <div className="grid grid-cols-3 gap-1.5">
                        {ipRefs.slice(0, 10).map((xref) => (
                          <CrossRefCard key={xref.entity_value} xref={xref} onEntityClick={onEntityClick} onUserClick={onUserClick} />
                        ))}
                      </div>
                    </div>
                  )}
                  {resourceRefs.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                        <Server className="h-3 w-3" /> Resources ({resourceRefs.length})
                      </div>
                      <div className="grid grid-cols-1 gap-1.5">
                        {resourceRefs.slice(0, 10).map((xref) => (
                          <CrossRefCard key={xref.entity_value} xref={xref} onEntityClick={onEntityClick} onUserClick={onUserClick} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Events timeline */}
            <div className="text-xs text-muted-foreground mb-2">
              {events.length} events (chronological)
            </div>
            <div className="relative pl-6">
              <div className="absolute left-1 top-0 bottom-0 w-[2px] bg-border" />

              {events.map((evt, i) => {
                const dotColor = CHANGE_TYPE_DOT_COLORS[evt.change_type] || CHANGE_TYPE_DOT_COLORS.access;

                return (
                  <div key={i} className="relative pb-4 last:pb-0">
                    <div className={`absolute -left-6 top-1.5 h-2.5 w-2.5 rounded-full ring-2 ring-background/50 ${dotColor}`} />

                    <div className="rounded-md border p-2.5 hover:bg-accent/30 transition-colors">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <span className="text-[11px] font-mono text-muted-foreground">
                          {formatUTCShort(new Date(evt.timestamp))}
                        </span>
                        <Badge variant="outline" className="text-[10px]">{evt.cloud_service}</Badge>
                        <Badge variant="outline" className="text-[10px]">
                          {evt.change_type || 'access'}
                        </Badge>
                        <StatusBadge code={evt.http_status_code} />
                        <IocBadge threatType={evt.ioc_src_ip_threat_type} malware={evt.ioc_src_ip_malware} confidence={evt.ioc_src_ip_confidence} />
                      </div>
                      <div className="text-xs">
                        <span className="font-medium">{evt.event_type || '-'}</span>
                        {evt.resource_name || evt.resource_id ? (
                          <span className="text-muted-foreground ml-1.5">
                            {' → '}
                            <CopyableValue
                              value={evt.resource_name || evt.resource_id}
                              className="text-primary hover:underline"
                              onClick={() => onEntityClick?.('resource', evt.resource_name || evt.resource_id)}
                            />
                          </span>
                        ) : null}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                        {evt.user && entity?.type !== 'user' && (
                          <CopyableValue
                            value={evt.user}
                            className="text-primary hover:underline"
                            onClick={() => onUserClick?.(evt.user)}
                          />
                        )}
                        {evt.cloud_region && <span>{evt.cloud_region}</span>}
                        {evt.src_ip && entity?.type !== 'ip' && (
                          <span className="inline-flex items-center gap-1">
                            <CopyableValue
                              value={evt.src_ip}
                              className="font-mono text-primary hover:underline"
                              onClick={() => onEntityClick?.('ip', evt.src_ip)}
                            />
                            {evt.enriched_src_country_code && (
                              <span className="text-muted-foreground">
                                {evt.enriched_src_country_code}
                                {evt.enriched_src_asn ? ` ${evt.enriched_src_asn}` : ''}
                                {evt.enriched_src_as_name ? ` (${evt.enriched_src_as_name})` : ''}
                              </span>
                            )}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}

              {events.length === 0 && (
                <div className="text-xs text-muted-foreground py-8 text-center">
                  No cloud events found for this entity
                </div>
              )}
            </div>
          </>
        ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}
