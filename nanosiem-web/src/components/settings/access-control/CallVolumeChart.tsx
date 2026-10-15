// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Per-key call-volume sparkline for the API key detail panel.
 *
 * Backed by `GET /api/api-keys/{id}/usage`, which counts *audited* actions
 * (mutations + authorization denials) attributed to the key — not raw request
 * volume. Read-only GET traffic is not audited and does not appear here; the
 * caption says so rather than implying a complete request count.
 *
 * Hosted-shared tenants (NAN-2361) answer the same shape from the tenant
 * key-authority ledger, where every authenticated request is one event, so
 * there the series IS request volume and the caption says that instead. If
 * the tenant API does not serve the route (503 / 404) the panel says so
 * honestly rather than pretending the key was never used.
 *
 * Rendered as a hand-rolled div bar chart to stay within the dense, mono-meta
 * visual language without pulling Recharts into this panel.
 */

import { useEffect, useState } from 'react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import { api, ApiClientError, type ApiKeyUsageResponse } from '@/lib/api';

const WINDOW_DAYS = 14;

type UsageError = 'failed' | 'unavailable';

export function CallVolumeChart({ apiKeyId, sharedTenant = false }: { apiKeyId: string; sharedTenant?: boolean }) {
  const [data, setData] = useState<ApiKeyUsageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<UsageError | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getApiKeyUsage(apiKeyId, WINDOW_DAYS)
      .then(res => {
        if (!cancelled) setData(Array.isArray(res?.series) ? res : { days: WINDOW_DAYS, total: 0, series: [] });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const status = err instanceof ApiClientError ? err.status : undefined;
        setError(status === 503 || status === 404 || status === 405 ? 'unavailable' : 'failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [apiKeyId]);

  const max = data ? Math.max(1, ...data.series.map(p => p.count)) : 1;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Call volume</div>
        {data && (
          <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
            {data.total.toLocaleString()} in {WINDOW_DAYS}d
          </div>
        )}
      </div>

      <div className="rounded-md border border-border bg-card/40 px-4 py-3">
        {loading ? (
          <div className="h-[64px] flex items-center justify-center">
            <LoadingIcon className="w-3.5 h-3.5 text-muted-foreground" />
          </div>
        ) : error ? (
          <div className="h-[64px] flex items-center justify-center text-[11px] text-muted-foreground">
            {error === 'unavailable'
              ? 'Call volume is not recorded for this tenant.'
              : "Couldn't load call volume."}
          </div>
        ) : !data || data.total === 0 ? (
          <div className="h-[64px] flex items-center justify-center text-[11px] text-muted-foreground">
            {sharedTenant ? `No requests in the last ${WINDOW_DAYS} days.` : `No audited activity in the last ${WINDOW_DAYS} days.`}
          </div>
        ) : (
          <div className="h-[64px] flex items-end gap-[3px]">
            {data.series.map(p => {
              const pct = p.count === 0 ? 0 : Math.max(6, (p.count / max) * 100);
              return (
                <div
                  key={p.date}
                  className="flex-1 min-w-0 flex items-end h-full"
                  title={`${p.date} · ${p.count} action${p.count === 1 ? '' : 's'}`}
                >
                  <div
                    className={cn(
                      'w-full rounded-[1px] transition-[height]',
                      p.count === 0 ? 'bg-foreground/[0.06]' : 'bg-primary/55',
                    )}
                    style={{ height: p.count === 0 ? '2px' : `${pct}%` }}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="text-[10.5px] text-muted-foreground/70 mt-1.5">
        {sharedTenant ? (
          <>
            Authenticated requests per day (UTC) from the tenant key ledger, read-only calls included —
            see <span className="font-mono">Last used</span> above for the most recent activity.
          </>
        ) : (
          <>
            Audited actions per day (mutations + denied requests). Read-only traffic isn't audited and isn't counted —
            see <span className="font-mono">Last used</span> above for the most recent activity.
          </>
        )}
      </div>
    </div>
  );
}
