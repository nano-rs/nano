// SPDX-License-Identifier: AGPL-3.0-or-later

// ServiceSecuritySignals (NAN-1542) — the observability ↔ security convergence
// cross-link. A small dense strip on Service detail surfacing security
// DETECTIONS that fired on the hosts/IPs this service runs on, over the same
// window the RED panels use.
//
// Data is REAL: api.observability.getServiceSecuritySignals(service, { start,
// end }) → { host_count, signal_total, signal_count, signals: [{ ts, rule_name,
// src_host, src_ip, severity }] }. signal_total is the true range count;
// signal_count is the bounded sample size (signals.length). The strip is
// best-effort decoration — it never blocks
// or errors the parent detail, and the common case is zero (rendered as a clean
// "no detections" line, NOT a heavy empty panel).
//
// Each signal links into the SIEM search scoped to its matched entity so an
// analyst lands on the underlying logs (mirrors InfraTab's /search?q= pattern).

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ChevronRight } from 'lucide-react';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { parseUTCTimestamp } from '@/lib/date-utils';
import type { ServiceSecuritySignalsResponse, ServiceSecuritySignal } from '@/lib/api/observability';
import type { TimeRange } from '@/lib/api/types';

// How many of the sampled signals to render inline. The backend already caps
// the sample; this keeps the strip from growing tall on a noisy host.
const SHOWN = 5;

interface SevTone {
  text: string;
  dot: string;
}

const SEV_TONE: Record<string, SevTone> = {
  critical: { text: 'text-danger', dot: 'bg-danger' },
  high: { text: 'text-danger', dot: 'bg-danger' },
  medium: { text: 'text-warn', dot: 'bg-warn' },
  low: { text: 'text-fg-3', dot: 'bg-foreground/30' },
  info: { text: 'text-fg-3', dot: 'bg-foreground/30' },
};

const SEV_FALLBACK: SevTone = { text: 'text-fg-3', dot: 'bg-foreground/30' };

function sevTone(sev: string | null): SevTone {
  return (sev != null && SEV_TONE[sev.toLowerCase()]) || SEV_FALLBACK;
}

/** Build a SIEM search query scoped to the signal's matched entity. */
function searchHref(s: ServiceSecuritySignal): string {
  let q: string | null = null;
  if (s.src_ip) {
    const ip = s.src_ip.replace(/"/g, '\\"');
    q = `src_ip="${ip}" OR dest_ip="${ip}" OR src_endpoint.ip="${ip}" OR dst_endpoint.ip="${ip}"`;
  } else if (s.src_host) {
    const h = s.src_host.replace(/"/g, '\\"');
    q = `src_host="${h}" OR dest_host="${h}" OR hostname="${h}" OR device.hostname="${h}"`;
  }
  return q ? `/search?q=${encodeURIComponent(q)}` : '/alerts';
}

function fmtTs(ts: string): string {
  // O12: signal timestamps can arrive CH-format ("YYYY-MM-DD HH:MM:SS", no
  // zone); parseUTCTimestamp reads them as UTC (a bare new Date() would treat
  // them as the browser's local zone and shift the displayed time).
  const d = parseUTCTimestamp(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export interface ServiceSecuritySignalsProps {
  service: string;
  apiTimeRange: TimeRange;
}

export function ServiceSecuritySignals({ service, apiTimeRange }: ServiceSecuritySignalsProps) {
  const [data, setData] = useState<ServiceSecuritySignalsResponse | null>(null);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setErrored(false);
    setData(null);
    api.observability
      .getServiceSecuritySignals(service, { start: apiTimeRange.start, end: apiTimeRange.end })
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch(() => {
        // Convergence is decoration — swallow and hide on failure.
        if (!cancelled) setErrored(true);
      });
    return () => {
      cancelled = true;
    };
  }, [service, apiTimeRange]);

  // While loading, or on failure, render nothing — never disturb the detail.
  if (errored || !data) return null;

  // O54: signal_total is the true range total (count query); signal_count only
  // reflects the bounded sample (signals.length), so the header + overflow must
  // key off signal_total or they undercount (e.g. "100 · +0 more" for 500 hits).
  const { signal_total, host_count, signals } = data;

  // Zero state: a single quiet line, not a panel.
  if (signal_total === 0) {
    return (
      <div className="flex items-center gap-2 px-1 text-[11px] text-fg-4">
        <ShieldAlert className="w-[13px] h-[13px] text-fg-4 shrink-0" />
        <span>
          No security detections on this service's{' '}
          <span className="font-mono text-fg-3 tabular-nums">{host_count}</span>{' '}
          {host_count === 1 ? 'host' : 'hosts'} in range.
        </span>
      </div>
    );
  }

  const shown = signals.slice(0, SHOWN);
  const overflow = signal_total - shown.length;

  return (
    <div className="rounded-lg border border-danger/30 bg-danger/5 overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-danger/20 flex items-center gap-2">
        <ShieldAlert className="w-[13px] h-[13px] text-danger shrink-0" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-danger font-semibold">
          Related security signals
        </span>
        <span className="font-mono text-[10.5px] text-fg-3 tabular-nums">
          {signal_total} on {host_count} {host_count === 1 ? 'host' : 'hosts'}
        </span>
        <div className="flex-1" />
        <Link
          to="/alerts"
          className="inline-flex items-center gap-1 text-[10.5px] text-fg-3 hover:text-fg"
        >
          Alerts <ChevronRight className="w-3 h-3" />
        </Link>
      </div>
      {shown.map((s, i) => (
        <Link
          key={`${s.ts}-${s.rule_name}-${i}`}
          to={searchHref(s)}
          className="group flex items-center gap-2.5 px-3.5 py-2 border-b border-danger/10 last:border-b-0 hover:bg-danger/10"
        >
          <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', sevTone(s.severity).dot)} />
          <span className="font-mono text-[11.5px] text-fg truncate flex-1" title={s.rule_name}>
            {s.rule_name}
          </span>
          {(s.src_host || s.src_ip) && (
            <span className="font-mono text-[10.5px] text-fg-3 truncate max-w-[160px] shrink-0">
              {s.src_host || s.src_ip}
            </span>
          )}
          {s.severity && (
            <span className={cn('font-mono text-[10px] uppercase tracking-wider shrink-0', sevTone(s.severity).text)}>
              {s.severity}
            </span>
          )}
          <span className="font-mono text-[10.5px] text-fg-4 tabular-nums shrink-0 w-[96px] text-right">
            {fmtTs(s.ts)}
          </span>
          <ChevronRight className="w-3 h-3 text-fg-4 group-hover:text-fg-2 shrink-0" />
        </Link>
      ))}
      {overflow > 0 && (
        <div className="px-3.5 py-1.5 text-[10.5px] text-fg-4 font-mono tabular-nums">
          +{overflow} more in range
        </div>
      )}
    </div>
  );
}

export default ServiceSecuritySignals;
