// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Infrastructure host-inventory waffle (NAN-1537)
 *
 * Ported from the design handoff's obs-infra.jsx (host waffle) + obs-charts.jsx
 * (`heatColor`). One cell per host, shaded by a selectable metric (CPU / mem /
 * load / net), grouped by `host.group`, with a legend + summary line and a
 * hover title carrying the host id + metric values.
 *
 * Lives outside charts.tsx (which the surface slice doesn't own) so the heat
 * ramp + tile primitives stay self-contained to the Infra surface.
 *
 * Data is REAL: api.observability.getInfraHosts returns the latest-snapshot
 * CPU/mem/load/net per host over the shared window. A metric a host never
 * reported is `null` and renders as an "unreported" tile rather than a hot 0.
 */

import { cn } from '@/lib/utils';
import { fmtNum } from '@/components/observability/format';
import type { InfraHost } from '@/lib/api/observability';

// ---------------------------------------------------------------------------
// heat color ramp (good→warn→danger) — ported 1:1 from obs-charts.jsx
// ---------------------------------------------------------------------------

/** t in [0,1]; cool (teal/green) → amber → red, matching the design ramp. */
export function heatColor(t: number): string {
  const c = Math.min(1, Math.max(0, t));
  if (c < 0.5) {
    const k = c / 0.5; // green → amber
    return `oklch(${(72 - k * 4).toFixed(0)}% ${(0.14 + k * 0.02).toFixed(3)} ${(150 - k * 70).toFixed(0)})`;
  }
  const k = (c - 0.5) / 0.5; // amber → red
  return `oklch(${(70 - k * 8).toFixed(0)}% ${(0.16 + k * 0.05).toFixed(3)} ${(80 - k * 55).toFixed(0)})`;
}

// ---------------------------------------------------------------------------
// metric registry — which host field each selectable metric reads, how it's
// labelled / formatted, and how its [0,1] heat intensity is derived.
// ---------------------------------------------------------------------------

export type InfraMetricKey = 'cpu' | 'mem' | 'load' | 'net';

export interface InfraMetric {
  key: InfraMetricKey;
  /** Button label. */
  label: string;
  /** Pull the host's value for this metric (null = unreported). */
  value: (h: InfraHost) => number | null;
  /** Human value + unit for tile titles / hottest list. */
  fmt: (v: number) => string;
  /** Percent metrics ride a fixed 0..100 scale; load/net scale to observed max. */
  fixedMax: number | null;
}

const fmtBytesPerSec = (v: number): string => {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + ' GB/s';
  if (v >= 1e6) return (v / 1e6).toFixed(1) + ' MB/s';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + ' KB/s';
  return Math.round(v) + ' B/s';
};

export const INFRA_METRICS: InfraMetric[] = [
  { key: 'cpu', label: 'CPU', value: (h) => h.cpu_pct, fmt: (v) => Math.round(v) + '%', fixedMax: 100 },
  { key: 'mem', label: 'Mem', value: (h) => h.mem_pct, fmt: (v) => Math.round(v) + '%', fixedMax: 100 },
  { key: 'load', label: 'Load', value: (h) => h.load, fmt: (v) => fmtNum(v), fixedMax: null },
  { key: 'net', label: 'Net', value: (h) => h.net_bytes_per_sec, fmt: fmtBytesPerSec, fixedMax: null },
];

/**
 * The scale maximum for a metric: fixed (100% for CPU/mem) or the largest
 * observed value across hosts (load/net), floored to 1 so a flat/empty fleet
 * doesn't divide by zero or blow the ramp.
 */
export function metricScaleMax(metric: InfraMetric, hosts: InfraHost[]): number {
  if (metric.fixedMax != null) return metric.fixedMax;
  let max = 0;
  for (const h of hosts) {
    const v = metric.value(h);
    if (v != null && v > max) max = v;
  }
  return Math.max(1, max);
}

// ---------------------------------------------------------------------------
// host tile
// ---------------------------------------------------------------------------

function HostTile({
  host,
  metric,
  scaleMax,
  selected,
  onSelect,
}: {
  host: InfraHost;
  metric: InfraMetric;
  scaleMax: number;
  selected: boolean;
  onSelect: (h: InfraHost) => void;
}) {
  const raw = metric.value(host);
  const reported = raw != null;
  const t = reported ? Math.min(1, raw / scaleMax) : 0;
  const hot = reported && t >= 0.8;

  // Build a hover title with every reported metric so the cell is self-describing.
  const titleParts: string[] = [host.host];
  for (const m of INFRA_METRICS) {
    const v = m.value(host);
    if (v != null) titleParts.push(`${m.label} ${m.fmt(v)}`);
  }

  return (
    <button
      type="button"
      onClick={() => onSelect(host)}
      title={titleParts.join(' · ')}
      aria-label={`${host.host} ${metric.label} ${reported ? metric.fmt(raw) : 'unreported'}`}
      className={cn(
        'relative rounded-[3px] transition-all',
        selected
          ? 'ring-2 ring-fg ring-offset-1 ring-offset-card z-10'
          : 'hover:ring-1 hover:ring-fg/40'
      )}
      style={{
        width: 30,
        height: 30,
        background: reported ? heatColor(t) : 'var(--color-foreground)',
        opacity: reported ? 1 : 0.06,
      }}
    >
      {hot && (
        <span
          className="absolute inset-0 rounded-[3px] animate-pulse"
          style={{ boxShadow: 'inset 0 0 0 1.5px rgba(255,255,255,0.25)' }}
        />
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// waffle — grouped tiles + legend, with selection lifted to the parent
// ---------------------------------------------------------------------------

export interface InfraWaffleProps {
  hosts: InfraHost[];
  metric: InfraMetric;
  /** Currently-selected host id, or null. */
  selectedHost: string | null;
  onSelect: (h: InfraHost) => void;
}

export function InfraWaffle({ hosts, metric, selectedHost, onSelect }: InfraWaffleProps) {
  const scaleMax = metricScaleMax(metric, hosts);

  // Group by host.group (falling back to an "ungrouped" bucket), largest first.
  const groups = new Map<string, InfraHost[]>();
  for (const h of hosts) {
    const key = h.group ?? 'ungrouped';
    const arr = groups.get(key);
    if (arr) arr.push(h);
    else groups.set(key, [h]);
  }
  const ordered = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="rounded-lg border border-border bg-card p-3.5 flex flex-col gap-4">
      {ordered.map(([name, groupHosts]) => (
        <div key={name}>
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[10.5px] text-fg-2 font-semibold truncate">{name}</span>
            <span className="font-mono text-[10px] text-fg-4 tabular-nums">{groupHosts.length}</span>
            <div className="flex-1 h-px bg-border/60" />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {groupHosts.map((h) => (
              <HostTile
                key={h.host}
                host={h}
                metric={metric}
                scaleMax={scaleMax}
                selected={selectedHost === h.host}
                onSelect={onSelect}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// legend — the metric heat ramp
// ---------------------------------------------------------------------------

export function InfraLegend({ metric, scaleMax }: { metric: InfraMetric; scaleMax: number }) {
  const isPct = metric.fixedMax != null;
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] text-fg-4 font-mono">{isPct ? '0' : 'low'}</span>
      <div
        className="h-2.5 w-24 rounded-full"
        style={{
          background: `linear-gradient(90deg, ${heatColor(0)}, ${heatColor(0.5)}, ${heatColor(1)})`,
        }}
      />
      <span className="text-[10px] text-fg-4 font-mono">
        {isPct ? `${scaleMax}` : metric.fmt(scaleMax)}
      </span>
    </div>
  );
}
