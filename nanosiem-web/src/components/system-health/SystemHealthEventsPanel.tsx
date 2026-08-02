// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BellRing, Check, ChevronDown, ChevronRight, ExternalLink, RotateCcw } from 'lucide-react';
import { Link } from 'react-router-dom';

import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { SystemHealthEvent, SystemHealthStatus } from '@/lib/api/system-health';
import { cn } from '@/lib/utils';

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/10 text-red-400',
  high: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/25 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/25 bg-blue-500/10 text-blue-400',
  informational: 'border-border bg-muted/40 text-muted-foreground',
};

function relativeTime(value: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function EventRow({ event, canManage }: { event: SystemHealthEvent; canManage: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const acknowledge = useMutation({
    mutationFn: () => api.systemHealth.acknowledge(event.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-health'] });
      toast({ title: 'Health event acknowledged' });
    },
    onError: (error) => toast({
      title: 'Could not acknowledge health event',
      description: error instanceof Error ? error.message : 'Please try again.',
      variant: 'destructive',
    }),
  });
  const resolve = useMutation({
    mutationFn: () => api.systemHealth.resolve(event.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-health'] });
      toast({ title: 'Health event resolved', description: 'A recovery notification was queued.' });
    },
    onError: (error) => toast({
      title: 'Could not resolve health event',
      description: error instanceof Error ? error.message : 'Please try again.',
      variant: 'destructive',
    }),
  });
  const deliveries = useQuery({
    queryKey: ['system-health', 'deliveries', event.id],
    queryFn: () => api.systemHealth.listDeliveries(event.id, 20),
    enabled: expanded,
  });

  return (
    <div className="border-t border-border first:border-t-0">
      <button
        type="button"
        onClick={() => setExpanded(v => !v)}
        className="grid w-full grid-cols-[18px_90px_minmax(0,1fr)_110px_90px] items-center gap-2 px-3 py-2 text-left hover:bg-foreground/[0.025]"
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        <span className={cn('w-fit rounded border px-1.5 py-0.5 font-mono text-[9.5px] uppercase', SEVERITY_CLASS[event.severity])}>
          {event.severity}
        </span>
        <span className="min-w-0">
          <span className="block truncate text-[12px] font-medium text-foreground">{event.title}</span>
          <span className="block truncate text-[10.5px] text-muted-foreground">{event.summary}</span>
        </span>
        <span className="truncate font-mono text-[10.5px] text-muted-foreground" title={event.resource_name ?? event.resource_id ?? undefined}>
          {event.resource_name ?? event.resource_id ?? event.resource_type}
        </span>
        <span className="text-right font-mono text-[10px] text-muted-foreground">
          {relativeTime(event.last_seen_at)}
          {event.occurrence_count > 1 && <span className="ml-1 text-foreground">×{event.occurrence_count}</span>}
        </span>
      </button>
      {expanded && (
        <div className="border-t border-border/70 bg-card/40 px-9 py-3">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
            <div className="space-y-2">
              <div>
                <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground">Remediation</div>
                <p className="mt-1 text-[11.5px] text-foreground">{event.remediation ?? 'Review the affected subsystem and recent configuration changes.'}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-muted-foreground">
                <span>{event.category}</span><span>·</span><span>{event.resource_type}</span><span>·</span><span>{event.source}</span>
                {event.acknowledged_at && <><span>·</span><span className="text-emerald-400">acknowledged</span></>}
              </div>
              {canManage && event.status === 'active' && (
                <div className="flex gap-2 pt-1">
                  {!event.acknowledged_at && (
                    <button type="button" onClick={() => acknowledge.mutate()} disabled={acknowledge.isPending} className="inline-flex h-7 items-center gap-1 rounded-md border border-border px-2 text-[10.5px] hover:bg-muted/50 disabled:opacity-50">
                      <Check className="h-3 w-3" /> Acknowledge
                    </button>
                  )}
                  <button type="button" onClick={() => resolve.mutate()} disabled={resolve.isPending} className="inline-flex h-7 items-center gap-1 rounded-md border border-border px-2 text-[10.5px] hover:bg-muted/50 disabled:opacity-50">
                    <RotateCcw className="h-3 w-3" /> Resolve and notify recovery
                  </button>
                </div>
              )}
            </div>
            <div>
              <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground">External delivery</div>
              <div className="mt-1 space-y-1">
                {deliveries.isLoading && <p className="text-[10.5px] text-muted-foreground">Loading delivery history…</p>}
                {deliveries.data?.length === 0 && <p className="text-[10.5px] text-muted-foreground">No subscribed channel for this lifecycle.</p>}
                {deliveries.data?.map(delivery => (
                  <div key={delivery.id} className="flex items-center justify-between gap-2 font-mono text-[10px]">
                    <span className="truncate text-muted-foreground">{delivery.webhook_name} · {delivery.event_action}</span>
                    <span title={delivery.last_error ?? undefined} className={delivery.status === 'delivered' ? 'text-emerald-400' : delivery.status === 'dead' ? 'text-red-400' : 'text-yellow-400'}>
                      {delivery.status}{delivery.attempt_count > 0 ? ` · ${delivery.attempt_count}` : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function SystemHealthEventsPanel() {
  const { hasPermission } = useAuth();
  const canView = hasPermission('system_health:view');
  const canManage = hasPermission('system_health:manage');
  const canConfigureRouting = hasPermission('settings:webhooks');
  const [status, setStatus] = useState<SystemHealthStatus>('active');
  const events = useQuery({
    queryKey: ['system-health', 'events', status],
    queryFn: () => api.systemHealth.listEvents({ status, limit: 100 }),
    enabled: canView,
    refetchInterval: 30_000,
  });
  const summary = useQuery({
    queryKey: ['system-health', 'summary'],
    queryFn: () => api.systemHealth.getSummary(),
    enabled: canView,
    refetchInterval: 30_000,
  });

  if (!canView) return null;
  const items = events.data?.events ?? [];
  return (
    <section className="mt-4 overflow-hidden rounded-md border border-border bg-card">
      <div className="flex items-center justify-between gap-3 border-b border-border bg-card/60 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <BellRing className="h-3.5 w-3.5 text-muted-foreground" />
          <div>
            <h2 className="text-[12px] font-semibold text-foreground">System health events</h2>
            <p className="text-[10.5px] text-muted-foreground">Operational degradation from collectors, enrichments, log sources, and platform services</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {summary.data && (
            <span className="font-mono text-[10px] text-muted-foreground">
              {summary.data.active} active · {summary.data.unacknowledged} unacknowledged
              {summary.data.delivery_dead > 0 ? ` · ${summary.data.delivery_dead} dead-letter` : ''}
            </span>
          )}
          {canConfigureRouting && (
            <Link to="/settings/notifications" className="inline-flex h-7 items-center gap-1 rounded-md border border-border px-2 text-[10.5px] text-muted-foreground hover:bg-muted/50 hover:text-foreground">
              Routing <ExternalLink className="h-3 w-3" />
            </Link>
          )}
        </div>
      </div>
      <div className="flex gap-1 border-b border-border px-3 py-1.5">
        {(['active', 'resolved'] as const).map(value => (
          <button key={value} type="button" onClick={() => setStatus(value)} className={cn('rounded px-2 py-1 font-mono text-[10px] capitalize', status === value ? 'bg-foreground/10 text-foreground' : 'text-muted-foreground hover:text-foreground')}>
            {value}
          </button>
        ))}
      </div>
      {events.isLoading ? (
        <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">Loading health events…</div>
      ) : items.length === 0 ? (
        <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">
          {status === 'active' ? 'No active system degradation.' : 'No resolved health events yet.'}
        </div>
      ) : (
        <div>{items.map(event => <EventRow key={event.id} event={event} canManage={canManage} />)}</div>
      )}
    </section>
  );
}
