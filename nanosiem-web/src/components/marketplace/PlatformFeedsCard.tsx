// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4759 — Platform feeds (self-hosted lean: sovereign and open core).
 *
 * The cell stamps IPinfo Lite geo/ASN, ThreatFox and Tor at ingest from one
 * signed feed bundle installed on this host. This card shows which feeds are
 * installed, their revision and age, and when each hard-expires. Past the
 * hard expiry a feed stops stamping NEW events; values already stamped stay
 * searchable as written. Updating is an operator command on the host
 * (`scripts/nano feeds update`, or `--file` for an offline drop), so the card
 * only reports and says how.
 *
 * Renders nothing where the deployment keeps no local bundle (hosted,
 * ClickHouse) or the status call fails: the marketplace works without it.
 */

import { formatRelativeCompact, formatUTCCompact } from '@/lib/date-utils';
import type { PlatformFeedState, PlatformFeedsStatus } from '@/lib/api/enrichment';
import { cn } from '@/lib/utils';

const STATE_TONE: Record<PlatformFeedState, { color: string; label: string }> = {
  fresh:   { color: 'oklch(70% 0.16 160)', label: 'fresh' },
  stale:   { color: 'oklch(80% 0.14 78)',  label: 'stale' },
  expired: { color: 'oklch(64% 0.20 28)',  label: 'expired' },
};

const UPDATE_COMMAND = 'scripts/nano feeds update';

interface PlatformFeedsCardProps {
  status: PlatformFeedsStatus | null | undefined;
}

export function PlatformFeedsCard({ status }: PlatformFeedsCardProps) {
  if (!status?.available) return null;
  const worst = status.feeds.some(f => f.state === 'expired')
    ? 'expired'
    : status.feeds.some(f => f.state === 'stale') ? 'stale' : 'fresh';
  return (
    <section
      aria-label="Platform feeds"
      className="rounded-md border border-border bg-card"
      data-testid="platform-feeds-card"
    >
      <header className="flex items-center gap-3 px-4 py-2.5 border-b border-border/60">
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: status.installed ? STATE_TONE[worst].color : STATE_TONE.expired.color }}
        />
        <div className="min-w-0">
          <div className="text-[12.5px] font-medium text-foreground">Platform feeds</div>
          <div className="text-[11px] text-muted-foreground">
            {status.installed ? (
              <>
                Stamped at ingest from the signed bundle installed{' '}
                {status.installed_at && (
                  <span className="font-mono text-foreground">{formatUTCCompact(status.installed_at)}</span>
                )}
                {status.bundle_sha256 && (
                  <> · <span className="font-mono" title={status.bundle_sha256}>{status.bundle_sha256.slice(0, 12)}</span></>
                )}
              </>
            ) : (
              <>No feed bundle installed: geo/ASN, ThreatFox and Tor are not stamped on new events.</>
            )}
          </div>
        </div>
        <div className="ml-auto text-[10.5px] font-mono text-muted-foreground whitespace-nowrap">
          update: <span className="text-foreground">{UPDATE_COMMAND}</span>
        </div>
      </header>
      {status.feeds.length > 0 && (
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-[10.5px] text-muted-foreground text-left">
              <th className="font-normal px-4 py-1.5">Feed</th>
              <th className="font-normal px-2 py-1.5">State</th>
              <th className="font-normal px-2 py-1.5">Revision</th>
              <th className="font-normal px-2 py-1.5">Produced</th>
              <th className="font-normal px-2 py-1.5">Hard expiry</th>
              <th className="font-normal px-4 py-1.5 text-right">Records</th>
            </tr>
          </thead>
          <tbody>
            {status.feeds.map(feed => (
              <tr key={feed.feed_id} className="h-7 border-t border-border/60" data-testid={`platform-feed-${feed.feed_id}`}>
                <td className="px-4">
                  <span className="text-foreground">{feed.name}</span>{' '}
                  <span className="font-mono text-[10.5px] text-muted-foreground">{feed.feed_id}</span>
                </td>
                <td className="px-2">
                  <span className="inline-flex items-center gap-1 font-mono text-[10.5px]">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: STATE_TONE[feed.state].color }} />
                    <span className={cn(feed.state === 'fresh' ? 'text-muted-foreground' : 'text-foreground')}>
                      {STATE_TONE[feed.state].label}
                    </span>
                  </span>
                </td>
                <td className="px-2 font-mono text-[11px] tabular-nums">{feed.revision}</td>
                <td className="px-2 font-mono text-[11px]" title={feed.produced_at ?? undefined}>
                  {feed.produced_at ? formatRelativeCompact(feed.produced_at) : '—'}
                </td>
                <td className="px-2 font-mono text-[11px]" title={feed.hard_expiry}>
                  {formatUTCCompact(feed.hard_expiry)}
                </td>
                <td className="px-4 font-mono text-[11px] tabular-nums text-right">
                  {feed.records ?? '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <footer className="px-4 py-2 border-t border-border/60 text-[10.5px] text-muted-foreground">
        A feed past its hard expiry stops stamping new events; values already stamped stay searchable.
        {' '}Stale after {status.stale_after_days} days.
        {status.notice && (
          <div className="mt-1 whitespace-pre-line" data-testid="platform-feeds-notice">{status.notice}</div>
        )}
      </footer>
    </section>
  );
}
