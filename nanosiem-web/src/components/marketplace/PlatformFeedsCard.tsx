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
 * NAN-5087 — dense layout: provenance in a mono meta row, explanations behind
 * `?` tooltips, and each feed's third-party attribution behind a licence chip
 * (popover with the exact NOTICE text and links). The full bundle NOTICE stays
 * one click away from the header: it is a redistribution requirement.
 *
 * Renders nothing where the status is unavailable: the page works without it.
 */

import { Fragment, useRef, useState, type ReactNode } from 'react';
import { HelpCircle, RefreshCw, TriangleAlert, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { CopyButton } from '@/components/add-data/CopyButton';
import { copyText } from '@/lib/clipboard';
import { formatNumber, formatRelativeCompact, formatUntil, formatUTCCompact } from '@/lib/date-utils';
import type { PlatformFeedState, PlatformFeedStatus, PlatformFeedsStatus } from '@/lib/api/enrichment';
import { parseFeedNotice, type FeedNotice } from '@/lib/platform-feed-notice';
import { cn } from '@/lib/utils';

/** Same pill palette as the Marketplace StateBadge (IntegrationCard). */
const PILL = 'inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[9.5px] uppercase tracking-[0.1em] border whitespace-nowrap';
const STATE_PILL: Record<PlatformFeedState | 'not_installed', { label: string; cls: string }> = {
  fresh:         { label: 'fresh',         cls: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500' },
  stale:         { label: 'stale',         cls: 'bg-amber-500/10 border-amber-500/30 text-amber-500' },
  expired:       { label: 'expired',       cls: 'bg-red-500/10 border-red-500/30 text-red-500' },
  not_installed: { label: 'not installed', cls: 'bg-muted/40 border-border text-muted-foreground' },
};

const CHANNEL_LABEL: Record<string, string> = {
  open: 'nano open feed',
  sovereign: 'nano licensed feed',
  mirror: 'mirror',
  file: 'file import',
};

const HEAD = 'h-7 px-2 font-mono text-[10px] font-medium uppercase tracking-wider text-muted-foreground whitespace-nowrap';
const CELL = 'px-2 py-1 font-mono text-[11px] whitespace-nowrap';

/** Attribution text with its URLs as links (the text itself is unchanged). */
function Linkified({ text }: { text: string }) {
  const parts = text.split(/(https?:\/\/[^\s),]+[^\s),.])/g);
  return <>{parts.map((part, i) => i % 2 === 1
    ? <a key={i} href={part} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 break-all">{part}</a>
    : <Fragment key={i}>{part}</Fragment>)}</>;
}

function HelpTip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" aria-label={label} className="inline-flex align-[-2px] text-muted-foreground/70 hover:text-foreground">
          <HelpCircle className="w-3 h-3" strokeWidth={1.5} />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-[300px] px-2.5 py-1.5 text-[11px] leading-relaxed font-sans normal-case tracking-normal">
        {children}
      </TooltipContent>
    </Tooltip>
  );
}

function Pill({ state, children, testId }: { state: keyof typeof STATE_PILL; children?: ReactNode; testId?: string }) {
  return <span className={cn(PILL, STATE_PILL[state].cls)} data-testid={testId}>{STATE_PILL[state].label}{children}</span>;
}

/** Truncated hash; the full value is in the tooltip and a click copies it. */
function Hash({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          data-testid="platform-feeds-hash"
          aria-label={`Bundle SHA-256 ${value}`}
          className="font-mono text-foreground/80 hover:text-foreground"
          onClick={async () => { setCopied(await copyText(value)); }}
          onMouseLeave={() => setCopied(false)}
        >
          {value.slice(0, 12)}
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-[340px] px-2.5 py-1.5">
        <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">bundle sha-256{copied ? ' · copied' : ' · click to copy'}</div>
        <div className="mt-0.5 font-mono text-[10.5px] break-all text-popover-foreground">{value}</div>
      </TooltipContent>
    </Tooltip>
  );
}

function LicenceChip({ feed, notice }: { feed: PlatformFeedStatus; notice: FeedNotice | undefined }) {
  const licenseId = feed.license_id ?? notice?.licenseId ?? null;
  if (!licenseId && !notice) return <span className="text-muted-foreground">—</span>;
  const label = (licenseId ?? 'notice').replace(/^LicenseRef-/, '');
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          data-testid={`platform-feed-licence-${feed.feed_id}`}
          aria-label={`Licence and attribution for ${feed.name}`}
          title={licenseId ?? undefined}
          className="inline-flex items-center h-[17px] max-w-[150px] px-1.5 rounded border border-border font-mono text-[10px] text-muted-foreground hover:text-foreground hover:bg-foreground/5"
        >
          <span className="truncate">{label}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[360px] p-0" data-testid={`platform-feed-notice-${feed.feed_id}`}>
        <div className="px-3 py-2 border-b border-border font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          {feed.name} · licence
        </div>
        <div className="px-3 py-2.5 space-y-1.5">
          <div className="font-mono text-[11px] text-foreground break-all">{licenseId ?? '—'}</div>
          {notice
            ? <p className="text-[11.5px] leading-relaxed text-popover-foreground"><Linkified text={notice.text} /></p>
            : <p className="text-[11px] text-muted-foreground">No attribution in the bundle NOTICE for this feed.</p>}
          {feed.terms_revision && <div className="font-mono text-[10.5px] text-muted-foreground">terms rev {feed.terms_revision}</div>}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function NoticeButton({ notice }: { notice: string }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button size="sm" variant="ghost" className="h-7 px-2 text-[11.5px] text-muted-foreground" data-testid="platform-feeds-notice-open">
          NOTICE
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[440px] p-0">
        <div className="flex items-center px-3 py-2 border-b border-border">
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Bundle NOTICE</span>
          <CopyButton text={notice} className="ml-auto" />
        </div>
        <div className="max-h-[320px] overflow-auto px-3 py-2.5 text-[11.5px] leading-relaxed whitespace-pre-line text-popover-foreground" data-testid="platform-feeds-notice">
          <Linkified text={notice} />
        </div>
      </PopoverContent>
    </Popover>
  );
}

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
  const worst: PlatformFeedState = status.feeds.some(f => f.state === 'expired' || f.active === false)
    ? 'expired'
    : status.feeds.some(f => f.state === 'stale') ? 'stale' : 'fresh';
  const checking = busy || status.last_check_status === 'checking';
  const canCheck = Boolean(onCheck) && status.auto_update !== false;
  const failed = status.last_check_status === 'refused' || status.last_check_status === 'failed';
  const notices = parseFeedNotice(status.notice).feeds;
  const sep = <span className="text-muted-foreground/40">·</span>;
  return (
    <TooltipProvider delayDuration={250}>
      <section
        aria-label="Platform feeds"
        className="rounded-lg border border-border/60 bg-card"
        data-testid="platform-feeds-card"
      >
        <header className="flex items-center gap-3 px-4 py-2.5 border-b border-border/60">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="text-[12.5px] font-medium text-foreground">Platform feeds</span>
              <Pill state={status.installed ? worst : 'not_installed'} testId="platform-feeds-state" />
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 font-mono text-[10.5px] text-muted-foreground" data-testid="platform-feeds-meta">
              {status.installed ? (
                <>
                  {status.channel && <span className="text-foreground/80">{CHANNEL_LABEL[status.channel] ?? status.channel}</span>}
                  {status.installed_at && <>{status.channel && sep}<span title={status.installed_at}>installed {formatUTCCompact(status.installed_at)}</span></>}
                  {status.sequence != null && <>{sep}<span>seq <span className="text-foreground/80 tabular-nums">{status.sequence}</span></span></>}
                  {status.bundle_sha256 && <>{sep}<Hash value={status.bundle_sha256} /></>}
                </>
              ) : (
                <span className="inline-flex items-center gap-1">
                  No feed bundle installed
                  <HelpTip label="What happens without a bundle">Geo/ASN, ThreatFox and Tor are not stamped on new events until a feed bundle is installed.</HelpTip>
                </span>
              )}
              {status.last_check_at && (
                <>
                  {sep}
                  <span title={status.last_check_at}>
                    {checking ? 'checking…' : `checked ${formatRelativeCompact(status.last_check_at)}`}
                    {status.last_check_status && !checking && <> · {status.last_check_status}</>}
                  </span>
                  {status.next_check_at && !checking && (
                    <>{sep}<span data-testid="platform-feeds-next-check" title={status.next_check_at}>next {formatUntil(status.next_check_at)}</span></>
                  )}
                </>
              )}
              {status.auto_update === false && (
                <>
                  {sep}
                  <span className="inline-flex items-center gap-1" data-testid="platform-feeds-manual">
                    online updates off
                    <HelpTip label="Online updates are off">Online updates are off on this deployment: import a bundle file.</HelpTip>
                  </span>
                </>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            {status.notice && <NoticeButton notice={status.notice} />}
            {canCheck && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px]" onClick={onCheck} disabled={checking} data-testid="platform-feeds-check">
                <RefreshCw className={cn('w-3 h-3', checking && 'animate-spin')} strokeWidth={1.5} /> Check now
              </Button>
            )}
            {onImport && (
              <>
                <Button size="sm" variant="outline" className="h-7 text-[11.5px]" onClick={() => fileInput.current?.click()} disabled={checking} data-testid="platform-feeds-import">
                  <Upload className="w-3 h-3" strokeWidth={1.5} /> Import file
                </Button>
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
          <div className="flex items-center gap-2 px-4 py-1.5 border-b border-border/60 text-[11px] text-foreground" data-testid="platform-feeds-error">
            <TriangleAlert className="w-3 h-3 shrink-0 text-red-500" strokeWidth={1.5} />
            <span className={cn(PILL, STATE_PILL.expired.cls)}>{status.last_check_status}</span>
            <span className="min-w-0">
              {status.last_error}
              {status.installed && <span className="text-muted-foreground"> The installed bundle is still in use.</span>}
            </span>
          </div>
        )}
        {status.feeds.length > 0 && (
          <Table className="text-[12px]">
            <TableHeader>
              <TableRow className="border-border/60 hover:bg-transparent">
                <TableHead className={cn(HEAD, 'pl-4')}>Feed</TableHead>
                <TableHead className={HEAD}>Licence</TableHead>
                <TableHead className={HEAD}>
                  <span className="inline-flex items-center gap-1">
                    State
                    <HelpTip label="About feed state">
                      A feed is stale after {status.stale_after_days} days. A feed past its hard expiry stops stamping new events; values already stamped stay searchable.
                    </HelpTip>
                  </span>
                </TableHead>
                <TableHead className={HEAD}>Revision</TableHead>
                <TableHead className={HEAD}>Produced</TableHead>
                <TableHead className={HEAD}>
                  <span className="inline-flex items-center gap-1">
                    Hard expiry
                    <HelpTip label="About hard expiry">
                      Past its hard expiry a feed stops stamping new events; values already stamped stay searchable.
                    </HelpTip>
                  </span>
                </TableHead>
                <TableHead className={cn(HEAD, 'pr-4 text-right')}>Records</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {status.feeds.map(feed => {
                const inactive = feed.active === false;
                const rows = feed.loaded ?? feed.records;
                const pill = (
                  <Pill state={feed.state} testId={`platform-feed-state-${feed.feed_id}`}>
                    {inactive && feed.state !== 'expired' && ' · not stamping'}
                  </Pill>
                );
                return (
                  <TableRow key={feed.feed_id} className="h-7 border-border/60 hover:bg-foreground/[0.02]" data-testid={`platform-feed-${feed.feed_id}`}>
                    <TableCell className="pl-4 pr-2 py-1 whitespace-nowrap">
                      <span className="text-[12px] text-foreground">{feed.name}</span>
                      <span className="ml-1.5 font-mono text-[10.5px] text-muted-foreground">{feed.feed_id}</span>
                    </TableCell>
                    <TableCell className="px-2 py-1">
                      <LicenceChip feed={feed} notice={notices.get(feed.feed_id)} />
                    </TableCell>
                    <TableCell className="px-2 py-1">
                      {inactive && feed.detail ? (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button type="button" className="cursor-help" aria-label={`${feed.name}: ${feed.detail}`} data-testid={`platform-feed-detail-${feed.feed_id}`}>{pill}</button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-[300px] px-2.5 py-1.5 text-[11px] leading-relaxed">{feed.detail}</TooltipContent>
                        </Tooltip>
                      ) : pill}
                    </TableCell>
                    <TableCell className={cn(CELL, 'tabular-nums')}>{feed.revision}</TableCell>
                    <TableCell className={CELL} title={feed.produced_at ?? undefined}>
                      {feed.produced_at ? formatRelativeCompact(feed.produced_at) : '—'}
                    </TableCell>
                    <TableCell className={cn(CELL, feed.state === 'expired' && 'text-red-500')} title={feed.hard_expiry}>
                      {formatUTCCompact(feed.hard_expiry)}
                    </TableCell>
                    <TableCell
                      className={cn(CELL, 'pr-4 tabular-nums text-right')}
                      title={feed.loaded != null && feed.records != null && feed.loaded !== feed.records
                        ? `${formatNumber(feed.loaded)} loaded · ${formatNumber(feed.records)} in the signed descriptor`
                        : undefined}
                    >
                      {rows != null ? formatNumber(rows) : '—'}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </section>
    </TooltipProvider>
  );
}
