// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect } from 'react';
import { MapPin, Globe, Server, AlertTriangle, Loader2, ShieldAlert, ArrowLeft } from 'lucide-react';
import { api } from '@/lib/api';
import type { CloudUserTimelineResponse } from '@/lib/api/types';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { formatUTCShort } from '@/lib/date-utils';
import { CopyableValue } from './CopyableValue';
import { useIsMobile } from '@/hooks/use-mobile';

// ============================================================================
// Types
// ============================================================================

interface CloudUserTimelineSheetProps {
  /** User to display timeline for (null = closed) */
  user: string | null;
  /** Close handler */
  onClose: () => void;
  /** The nPL query context */
  query: string;
  /** Time range */
  timeRange: { start: string; end: string };
  /** Callback when an entity (IP/resource) is clicked for pivot */
  onEntityClick?: (entityType: 'user' | 'ip' | 'resource', entityValue: string) => void;
  /** Back navigation handler (shown when there's history) */
  onBack?: () => void;
}

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

const CHANGE_TYPE_DOT_COLORS: Record<string, string> = {
  create: 'bg-green-500',
  update: 'bg-blue-500',
  delete: 'bg-red-500',
  permission_change: 'bg-amber-500',
  access: 'bg-zinc-400',
};

const RISK_LABELS: Record<string, string> = {
  high_fail_rate: 'High Fail Rate',
  privilege_escalation: 'Privilege Escalation',
  multi_region: 'Multi-Region',
  no_mfa: 'No MFA',
  high_delete: 'High Delete',
};

function StatusBadge({ code }: { code: number }) {
  if (!code) return null;
  if (code >= 400) {
    return <Badge variant="outline" className="text-[10px] bg-destructive/10 text-destructive border-destructive/30">{code}</Badge>;
  }
  return <Badge variant="outline" className="text-[10px]">{code}</Badge>;
}

// ============================================================================
// Component
// ============================================================================

export function CloudUserTimelineSheet({
  user,
  onClose,
  query,
  timeRange,
  onEntityClick,
  onBack,
}: CloudUserTimelineSheetProps) {
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CloudUserTimelineResponse | null>(null);

  useEffect(() => {
    if (!user) {
      setData(null);
      return;
    }

    setLoading(true);
    api.getCloudUserTimeline({
      query,
      time_range: { start: timeRange.start, end: timeRange.end },
      user,
    }).then((response) => {
      setData(response);
    }).catch((err) => {
      console.error('Failed to load user timeline:', err);
    }).finally(() => {
      setLoading(false);
    });
  }, [user, query, timeRange.start, timeRange.end]);

  const events = (data?.events || []) as unknown as TimelineEvent[];
  const summary = data?.summary;

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

  const iocIps = React.useMemo(
    () => [...ipEnrichment.entries()].filter(([, v]) => v.iocThreat),
    [ipEnrichment],
  );

  return (
    <Sheet open={!!user} onOpenChange={(open) => { if (!open) onClose(); }}>
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
            <span className="search-console-section-header"><Globe />Cloud User Trace</span>
            <span className="font-mono text-sm text-foreground">
              {user && <CopyableValue value={user} />}
            </span>
            {summary?.risk_indicators.map((ri) => (
              <Badge
                key={ri}
                variant="outline"
                className="text-[10px] text-muted-foreground"
              >
                <AlertTriangle className="h-2.5 w-2.5 mr-1" />
                {RISK_LABELS[ri] || ri}
              </Badge>
            ))}
          </SheetTitle>
          <SheetDescription className="search-console-section-meta">
            User activity across cloud services, regions, and source IPs
          </SheetDescription>
        </SheetHeader>

        <div className="overflow-y-auto px-6 pt-4 pb-6" style={{ maxHeight: isMobile ? 'calc(72vh - 5rem)' : 'calc(100vh - 5rem)' }}>
        {loading ? (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading user trace...
          </div>
        ) : summary ? (
          <>
            {/* Summary cards */}
            <div className="grid grid-cols-3 gap-2 mb-4">
              <Card>
                <CardContent className="p-3">
                  <div className="text-xs text-muted-foreground flex items-center gap-1">
                    <Server className="h-3 w-3" /> Services
                  </div>
                  <div className="text-lg font-semibold">{summary.services.length}</div>
                  <div className="text-[10px] text-muted-foreground truncate">
                    {summary.services.slice(0, 3).join(', ')}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-3">
                  <div className="text-xs text-muted-foreground flex items-center gap-1">
                    <MapPin className="h-3 w-3" /> Regions
                  </div>
                  <div className="text-lg font-semibold">{summary.regions.length}</div>
                  <div className="text-[10px] text-muted-foreground truncate">
                    {summary.regions.slice(0, 3).join(', ')}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-3">
                  <div className="text-xs text-muted-foreground flex items-center gap-1">
                    <Globe className="h-3 w-3" /> IPs
                  </div>
                  <div className="text-lg font-semibold">{summary.ips.length}</div>
                  <div className="text-[10px] text-muted-foreground space-y-0.5">
                    {summary.ips.slice(0, 3).map((ip) => {
                      const info = ipEnrichment.get(ip);
                      return (
                        <div key={ip} className="flex items-center gap-1 truncate">
                          <CopyableValue value={ip} className="font-mono" />
                          {info?.country && <span>{info.country}</span>}
                          {info?.asName && <span className="truncate">({info.asName})</span>}
                          {info?.iocThreat && <ShieldAlert className="h-2.5 w-2.5 text-red-500 shrink-0" />}
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </div>

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
            <div className="grid grid-cols-4 gap-2 mb-6">
              <div className="text-center">
                <div className="text-xs text-muted-foreground">Events</div>
                <div className="text-sm font-semibold">{summary.event_count}</div>
              </div>
              <div className="text-center">
                <div className="text-xs text-muted-foreground">Fails</div>
                <div className={`text-sm font-semibold ${summary.event_count > 0 && (summary.fail_count / summary.event_count) > 0.3 ? 'text-destructive' : ''}`}>
                  {summary.fail_count}
                </div>
              </div>
              <div className="text-center">
                <div className="text-xs text-muted-foreground">Deletes</div>
                <div className={`text-sm font-semibold ${summary.delete_count > 10 ? 'text-destructive' : ''}`}>
                  {summary.delete_count}
                </div>
              </div>
              <div className="text-center">
                <div className="text-xs text-muted-foreground">MFA</div>
                <div className={`text-sm font-semibold ${summary.has_no_mfa ? 'text-destructive' : 'text-muted-foreground'}`}>
                  {summary.has_no_mfa ? 'Missing' : 'OK'}
                </div>
              </div>
            </div>

            {/* Timeline */}
            <div className="text-xs text-muted-foreground mb-2">
              {events.length} events (chronological)
            </div>
            <div className="relative pl-6">
              {/* Vertical line */}
              <div className="absolute left-1 top-0 bottom-0 w-[2px] bg-border" />

              {events.map((evt, i) => {
                const dotColor = CHANGE_TYPE_DOT_COLORS[evt.change_type] || CHANGE_TYPE_DOT_COLORS.access;

                return (
                  <div key={i} className="relative pb-4 last:pb-0">
                    {/* Dot on the timeline line */}
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
                        {evt.cloud_region && <span>{evt.cloud_region}</span>}
                        {evt.src_ip && (
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
                  No cloud events found for this user
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
