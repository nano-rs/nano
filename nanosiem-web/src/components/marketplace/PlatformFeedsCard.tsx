// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4759 / NAN-4948 — Platform feeds.
 *
 * IPinfo Lite geo/ASN, ThreatFox and the Tor exit list are stamped at ingest
 * from ONE signed feed bundle nano publishes. This card shows which feeds are
 * installed, their revision and age, when each hard-expires and whether it
 * stamps new events, plus the latest check. Past the hard expiry a feed stops
 * stamping NEW events; values already stamped stay searchable as written.
 *
 * On the ClickHouse product the jobs leader checks for a new bundle on a
 * schedule; `onCheck` runs a check now, `onImport` installs a `.nanfeed` file
 * for air-gapped installs. Both are optional (omit for a read-only card).
 *
 * Renders nothing where the status is unavailable: the page works without it.
 */

import { useRef } from 'react';
import { formatRelativeCompact, formatUntil, formatUTCCompact } from '@/lib/date-utils';
import type { PlatformFeedState, PlatformFeedsStatus } from '@/lib/api/enrichment';
import { cn } from '@/lib/utils';

const STATE_TONE: Record<PlatformFeedState, { color: string; label: string }> = {
  fresh:   { color: 'oklch(70% 0.16 160)', label: 'fresh' },
  stale:   { color: 'oklch(80% 0.14 78)',  label: 'stale' },
  expired: { color: 'oklch(64% 0.20 28)',  label: 'expired' },
};

const CHANNEL_LABEL: Record<string, string> = {
  open: 'nano open feed',
  sovereign: 'nano licensed feed',
  mirror: 'mirror',
  file: 'file import',
};

interface PlatformFeedsCardProps {
  status: PlatformFeedsStatus | null | undefined;
  /** Run an online check now (omit to hide the action). */
  onCheck?: () => void;
  /** Install a bundle file (omit to hide the action). */
  onImport?: (file: File) => void;
  /** A check or import is in flight. */
  busy?: boolean;
}

export function PlatformFeedsCard({ status, onCheck, onImport, busy }: PlatformFeedsCardProps) {
  const fileInput = useRef<HTMLInputElement>(null);
  if (!status?.available) return null;
  const worst = status.feeds.some(f => f.state === 'expired' || f.active === false)
    ? 'expired'
    : status.feeds.some(f => f.state === 'stale') ? 'stale' : 'fresh';
  const checking = busy || status.last_check_status === 'checking';
  const canCheck = Boolean(onCheck) && status.auto_update !== false;
  const failed = status.last_check_status === 'refused' || status.last_check_status === 'failed';
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
                {status.channel && <> · {CHANNEL_LABEL[status.channel] ?? status.channel}</>}
                {status.sequence != null && (
                  <> · seq <span className="font-mono">{status.sequence}</span></>
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
        <div className="ml-auto flex items-center gap-2 shrink-0">
          {status.last_check_at && (
            <span className="text-[10.5px] font-mono text-muted-foreground whitespace-nowrap" title={status.last_check_at}>
              {checking ? 'checking…' : `checked ${formatRelativeCompact(status.last_check_at)}`}
              {status.last_check_status && !checking && <> · {status.last_check_status}</>}
              {status.next_check_at && !checking && (
                <span data-testid="platform-feeds-next-check" title={status.next_check_at}> · next {formatUntil(status.next_check_at)}</span>
              )}
            </span>
          )}
          {canCheck && (
            <button
              type="button"
              onClick={onCheck}
              disabled={checking}
              className="h-6 px-2 rounded border border-border text-[11px] text-foreground hover:bg-accent/50 disabled:opacity-50"
              data-testid="platform-feeds-check"
            >
              Check now
            </button>
          )}
          {onImport && (
            <>
              <button
                type="button"
                onClick={() => fileInput.current?.click()}
                disabled={checking}
                className="h-6 px-2 rounded border border-border text-[11px] text-foreground hover:bg-accent/50 disabled:opacity-50"
                data-testid="platform-feeds-import"
              >
                Import file
              </button>
              <input
                ref={fileInput}
                type="file"
                accept=".nanfeed"
                className="hidden"
                data-testid="platform-feeds-file"
                onChange={e => {
                  const file = e.target.files?.[0];
                  if (file) onImport(file);
                  e.target.value = '';
                }}
              />
            </>
          )}
        </div>
      </header>
      {failed && status.last_error && (
        <div
          className="px-4 py-1.5 border-b border-border/60 text-[11px] text-foreground"
          data-testid="platform-feeds-error"
        >
          <span className="font-mono text-[10.5px]" style={{ color: STATE_TONE.expired.color }}>
            {status.last_check_status}
          </span>{' '}
          {status.last_error}
          {status.installed && <span className="text-muted-foreground"> The installed bundle is still in use.</span>}
        </div>
      )}
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
            {status.feeds.map(feed => {
              const inactive = feed.active === false;
              return (
                <tr
                  key={feed.feed_id}
                  className="h-7 border-t border-border/60"
                  data-testid={`platform-feed-${feed.feed_id}`}
                  title={feed.detail ?? undefined}
                >
                  <td className="px-4">
                    <span className="text-foreground">{feed.name}</span>{' '}
                    <span className="font-mono text-[10.5px] text-muted-foreground">{feed.feed_id}</span>
                    {inactive && feed.detail && (
                      <div className="text-[10.5px] text-muted-foreground leading-tight pb-1">{feed.detail}</div>
                    )}
                  </td>
                  <td className="px-2">
                    <span className="inline-flex items-center gap-1 font-mono text-[10.5px]">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: STATE_TONE[feed.state].color }} />
                      <span className={cn(feed.state === 'fresh' && !inactive ? 'text-muted-foreground' : 'text-foreground')}>
                        {STATE_TONE[feed.state].label}
                        {inactive && feed.state !== 'expired' && ' · not stamping'}
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
                    {feed.loaded ?? feed.records ?? '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <footer className="px-4 py-2 border-t border-border/60 text-[10.5px] text-muted-foreground">
        A feed past its hard expiry stops stamping new events; values already stamped stay searchable.
        {' '}Stale after {status.stale_after_days} days.
        {status.auto_update === false && <> Online updates are off on this deployment: import a bundle file.</>}
        {status.notice && (
          <div className="mt-1 whitespace-pre-line" data-testid="platform-feeds-notice">{status.notice}</div>
        )}
      </footer>
    </section>
  );
}
