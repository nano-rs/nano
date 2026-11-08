// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4959 — how nano's signed platform feed bundle provides one feed:
 * revision, state, last update and next refresh. Used by the inventory drawer
 * for every bundle-covered card (IPinfo Lite, ThreatFox, Tor) and by the
 * IPinfo Lite connection drawer, which has no credentials or sync of its own:
 * IPinfo Lite comes only from the bundle (no download URL or token).
 */

import { formatRelativeCompact, formatUntil, formatUTCCompact } from '@/lib/date-utils';
import type { BundleProvision } from '@/lib/api/marketplace-inventory';

const STATE_LABEL: Record<string, string> = {
  fresh: 'fresh',
  stale: 'stale',
  expired: 'expired',
  not_installed: 'not installed',
};

function nextRefresh(p: BundleProvision): string {
  if (p.auto_update === false) return 'manual: import a bundle file (online updates off)';
  if (!p.next_check_at) return 'after the first scheduled check';
  return `${formatUTCCompact(p.next_check_at)} · ${formatUntil(p.next_check_at)}`;
}

export function BundleFeedStatus({ provision, className }: { provision: BundleProvision; className?: string }) {
  const p = provision;
  const notStamping = !p.active && p.state !== 'not_installed';
  return (
    <section className={className} data-testid="bundle-feed-status" aria-label="Platform feed bundle status">
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
        <dt className="text-muted-foreground">Provided by</dt>
        <dd className="font-mono" data-testid="inventory-bundle">
          nano · signed bundle · {p.feed_id}
        </dd>
        <dt className="text-muted-foreground">Revision</dt>
        <dd className="font-mono tabular-nums" data-testid="bundle-feed-revision">{p.revision ?? '—'}</dd>
        <dt className="text-muted-foreground">State</dt>
        <dd className="font-mono" data-testid="bundle-feed-state">
          {STATE_LABEL[p.state] ?? p.state}
          {notStamping && ' · not stamping'}
        </dd>
        <dt className="text-muted-foreground">Last update</dt>
        <dd className="font-mono" data-testid="bundle-feed-last-update" title={p.produced_at ?? undefined}>
          {p.produced_at ? `${formatUTCCompact(p.produced_at)} · ${formatRelativeCompact(p.produced_at)}` : '—'}
        </dd>
        {p.installed_at && (
          <>
            <dt className="text-muted-foreground">Installed</dt>
            <dd className="font-mono" title={p.installed_at}>{formatUTCCompact(p.installed_at)}</dd>
          </>
        )}
        <dt className="text-muted-foreground">Next refresh</dt>
        <dd className="font-mono" data-testid="bundle-feed-next-refresh" title={p.next_check_at ?? undefined}>
          {nextRefresh(p)}
        </dd>
      </dl>
      {p.detail && !p.active && (
        <p className="mt-2 text-[11px] text-muted-foreground" data-testid="bundle-feed-detail">{p.detail}</p>
      )}
      <p className="mt-3 text-[11px] leading-[1.45] text-muted-foreground" data-testid="inventory-bundle-note">
        Provided by nano's signed feed bundle from app.nano.rs and stamped at ingest. There is no download URL or
        token to configure. Check now and Import file are under Platform feeds on this page.
      </p>
    </section>
  );
}
