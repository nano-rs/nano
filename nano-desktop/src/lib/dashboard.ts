import { useEffect, useState } from 'react';

import { api, errorMessage } from './ipc';
import type { Dashboard } from './types';

/**
 * The SOC Overview's data, on a refresh loop.
 *
 * Shared by the dashboard tab and every pinned widget, so a widget can never
 * disagree with the page it was pinned from.
 *
 * IT GOES QUIET WHEN THE SESSION IS LOCKED. A pinned, always-on-top widget still
 * showing live detections on a locked machine is a leak — the whole point of Lock
 * is that the screen stops telling people things. The tray watcher already works
 * this way; widgets must too, and they are far more visible.
 */
export function useDashboard(intervalMs = 30_000) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function refresh() {
      try {
        const authenticated = await api.isAuthenticated();
        if (cancelled) return;

        if (!authenticated) {
          setLocked(true);
          // Drop what's on screen — not just stop updating it. A frozen last
          // reading left visible on a locked machine is the same leak, slightly
          // staler.
          setData(null);
          return;
        }

        setLocked(false);
        const next = await api.dashboard();
        if (cancelled) return;
        setData(next);
        setError(null);
      } catch (caught) {
        if (!cancelled) setError(errorMessage(caught));
      }
    }

    void refresh();
    const handle = window.setInterval(refresh, intervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [intervalMs]);

  return { data, error, locked };
}

/** Severity order, worst first — the only order a SOC list is read in. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;

export const SEVERITY_STYLE: Record<string, string> = {
  critical: 'border-danger/40 bg-danger-soft text-danger',
  high: 'border-danger/30 bg-danger-soft text-danger',
  medium: 'border-warn/40 bg-warn-soft text-warn',
  low: 'border-info/40 bg-info/10 text-info',
  informational: 'border-line-strong bg-raised text-t3',
};

/** "4.2k", "1.3M" — a KPI numeral has to fit the card. */
export function compact(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return value.toLocaleString();
}

export function ago(timestamp: string): string {
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return '';
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86_400)}d ago`;
}
