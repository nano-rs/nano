// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * UptimeBar (NAN-1538)
 *
 * Ported from the design handoff (obs-charts2.jsx · UptimeBar) — a 90-cell
 * run-history strip for a synthetic check. Each cell is one recorded run:
 * green = success, red = failure. Older runs are padded with neutral "no data"
 * cells on the left so the strip is always full width and right-anchored on the
 * most recent run.
 *
 * Input is the backend's `SyntheticResult[]` (oldest→newest); we map each
 * `success` boolean to a tone and hover-title it with the latency + timestamp.
 */

import type { SyntheticResult } from '@/lib/api/observability';

const CELLS = 90;

const TONE = {
  up: 'var(--color-good)',
  down: 'var(--color-danger)',
  nodata: 'var(--color-border-2)',
} as const;

type Tone = keyof typeof TONE;

function titleFor(r: SyntheticResult): string {
  const when = new Date(r.ts);
  const stamp = Number.isNaN(when.getTime()) ? r.ts : when.toLocaleString();
  return `${r.success ? 'up' : 'down'} · ${Math.round(r.latency_ms)}ms · ${stamp}`;
}

export interface UptimeBarProps {
  /** Recorded runs, oldest→newest. Trimmed/padded to the last 90. */
  history: SyntheticResult[];
  /** Bar height in px. */
  h?: number;
}

export function UptimeBar({ history, h = 22 }: UptimeBarProps) {
  // Keep the most recent 90 runs, right-anchored.
  const recent = history.slice(-CELLS);
  const padding = CELLS - recent.length;

  const cells: Array<{ tone: Tone; title?: string }> = [];
  for (let i = 0; i < padding; i++) cells.push({ tone: 'nodata' });
  for (const r of recent) {
    cells.push({ tone: r.success ? 'up' : 'down', title: titleFor(r) });
  }

  return (
    <div className="flex items-stretch gap-[1.5px] w-full" style={{ height: h }}>
      {cells.map((c, i) => (
        <div
          key={i}
          className="flex-1 rounded-[1px] min-w-[2px]"
          title={c.title}
          style={{ background: TONE[c.tone], opacity: c.tone === 'up' ? 0.7 : 1 }}
        />
      ))}
    </div>
  );
}

export default UptimeBar;
