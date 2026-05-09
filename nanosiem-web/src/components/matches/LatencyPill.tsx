// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — latency pill for per-event detection latency.
// Styling derived from the redesign tone tokens; parity with the old
// LatencyIndicator in DetectionMatches.tsx minus the rounded-xl/badge shell.

import { CheckCircle2, AlertCircle, XCircle, Timer } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Latency } from './helpers';

const LEVEL_STYLES = {
  fast:     { icon: CheckCircle2, tone: 'var(--success)' },
  moderate: { icon: AlertCircle,  tone: 'var(--warning)' },
  slow:     { icon: XCircle,      tone: 'var(--destructive)' },
} as const;

interface LatencyPillProps {
  latency: Latency | null;
  label?: boolean;
  className?: string;
}

export function LatencyPill({ latency, label, className }: LatencyPillProps) {
  if (!latency) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1 h-[16px] px-1.5 rounded-sm font-mono text-[10px]',
          className,
        )}
        style={{ color: 'var(--muted-foreground)' }}
      >
        <Timer className="w-3 h-3" strokeWidth={2} />
        —
      </span>
    );
  }
  const style = LEVEL_STYLES[latency.level];
  const Icon = style.icon;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 h-[16px] px-1.5 rounded-sm font-mono text-[10px] font-medium tabular-nums',
        className,
      )}
      style={{
        background: `color-mix(in srgb, ${style.tone} 14%, transparent)`,
        color: style.tone,
      }}
      title={`Detection latency: ${latency.formatted}`}
    >
      <Icon className="w-3 h-3" strokeWidth={2} />
      {label && <span className="text-muted-foreground mr-0.5">lat</span>}
      {latency.formatted}
    </span>
  );
}
