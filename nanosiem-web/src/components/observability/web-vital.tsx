// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * WebVital — Core Web Vitals gauge (NAN-1538)
 *
 * Ported from the design handoff's obs-charts2.jsx (WebVital). A single metric
 * card: label + rating, the p75 value, and a good/needs-work/poor gradient bar
 * with a marker at the current position. Lives outside charts.tsx because the
 * shared charts module is owned by the foundation slice — this is RUM-specific.
 *
 * `value == null` (metric unreported over the window) renders a muted "no data"
 * state rather than faking a zero reading.
 */

interface WebVitalProps {
  /** Short metric label, e.g. `LCP`. */
  label: string;
  /** The p75 value over the window, in the gauge's native unit, or null. */
  value: number | null;
  /** Unit suffix shown beside the value (`s`, `ms`, or `''`). */
  unit: string;
  /** Upper bound of the "good" zone (≤ good ⇒ good). */
  good: number;
  /** Upper bound of the "needs improvement" zone (≤ poor ⇒ needs-work). */
  poor: number;
  /** Value → display string (defaults to identity). */
  fmt?: (v: number) => string;
}

export function WebVital({ label, value, unit, good, poor, fmt = (v) => String(v) }: WebVitalProps) {
  const max = poor * 1.6;

  if (value == null) {
    return (
      <div className="rounded-lg border border-border bg-card px-3.5 py-3 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">{label}</span>
          <span className="text-[10px] font-medium text-fg-4">No data</span>
        </div>
        <div className="flex items-baseline gap-1">
          <span className="text-[22px] font-mono font-semibold tabular-nums text-fg-4 leading-none">–</span>
          {unit && <span className="text-[10.5px] text-fg-4">{unit}</span>}
        </div>
        <div className="relative h-1.5 rounded-full overflow-hidden mt-0.5 bg-foreground/8" />
        <div className="relative h-0" />
      </div>
    );
  }

  const rating = value <= good ? 'good' : value <= poor ? 'ni' : 'poor';
  const tone = { good: 'var(--color-good)', ni: 'var(--color-warn)', poor: 'var(--color-danger)' }[rating];
  const ratingLabel = { good: 'Good', ni: 'Needs work', poor: 'Poor' }[rating];
  const pos = Math.min(100, (value / max) * 100);

  return (
    <div className="rounded-lg border border-border bg-card px-3.5 py-3 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">{label}</span>
        <span className="text-[10px] font-medium" style={{ color: tone }}>
          {ratingLabel}
        </span>
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-[22px] font-mono font-semibold tabular-nums text-fg leading-none">{fmt(value)}</span>
        {unit && <span className="text-[10.5px] text-fg-3">{unit}</span>}
      </div>
      <div
        className="relative h-1.5 rounded-full overflow-hidden mt-0.5"
        style={{
          background: `linear-gradient(90deg, var(--color-good) 0%, var(--color-good) ${
            (good / max) * 100
          }%, var(--color-warn) ${(good / max) * 100}%, var(--color-warn) ${
            (poor / max) * 100
          }%, var(--color-danger) ${(poor / max) * 100}%)`,
        }}
      />
      <div className="relative h-0">
        <span
          className="absolute -top-[7px] w-[2px] h-2.5 bg-fg rounded-full -translate-x-1/2"
          style={{ left: `${pos}%` }}
        />
      </div>
    </div>
  );
}

export default WebVital;
