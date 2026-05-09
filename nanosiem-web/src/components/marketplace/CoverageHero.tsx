// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-573 — Marketplace coverage hero.
 *
 * Renders the "Enrichment coverage · by artifact type" card on the redesigned
 * /marketplace page. 3-column grid of artifact rows; each row has a 24-cell
 * segmented bar, a tone-coded state dot, "have" pills, and dashed-button
 * "missing" chips that prefill the marketplace search when clicked.
 *
 * NAN-609 — Decoupled from page load. Backed by a *shared* 6h
 * Dragonfly-backed cache server-side so the slow ~10s coverage SQL only
 * runs once per 6h across all replicas/users; caller still gets a
 * permissive React Query staleTime so in-tab navigations don't even
 * re-issue the GET. While the hero is loading or refetching, render a
 * dense skeleton so the rest of the page (catalog grid) is unblocked.
 * The header's RefreshCw button calls the dedicated POST refresh
 * endpoint, which invalidates the shared cache for everyone. The footer
 * meta line stamps "as of HH:MM" so users can see when the data was
 * last computed.
 *
 * Source of truth: design-ref/ui_kits/search/marketplace.html lines 290-349.
 */

import { Check, Plus, RefreshCw } from 'lucide-react';
import type { ArtifactCoverage, CoverageState, MarketplaceCoverage } from '@/lib/api/marketplace';
import { Skeleton } from '@/components/ui/skeleton';
import { formatUTCCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';

interface CoverageHeroProps {
  coverage: MarketplaceCoverage | null;
  /** Initial fetch in flight — render full skeleton. */
  isLoading?: boolean;
  /** Background refetch in flight (cache hit + revalidate, or manual refresh). */
  isFetching?: boolean;
  /** The coverage query failed. Hide the card; the marketplace still works without it. */
  isError?: boolean;
  /** Click on the manual-refresh button — forces a `refetch({ cancelRefetch: true })`. */
  onRefresh?: () => void;
  /** Click on a dashed "missing" chip prefills the marketplace search box. */
  onAddMissing: (name: string) => void;
}

const STATE_TONE: Record<CoverageState, { color: string; label: string }> = {
  good:    { color: 'oklch(70% 0.16 160)', label: 'good' },
  partial: { color: 'oklch(80% 0.14 78)',  label: 'partial' },
  gap:     { color: 'oklch(64% 0.20 28)',  label: 'gap' },
};

export function CoverageHero({
  coverage,
  isLoading = false,
  isFetching = false,
  isError = false,
  onRefresh,
  onAddMissing,
}: CoverageHeroProps) {
  // Skeleton while the very first fetch is in flight.
  if (isLoading && !coverage) {
    return <CoverageHeroSkeleton />;
  }

  // Coverage is best-effort — if the query failed and we have nothing to show,
  // hide the card entirely rather than rendering an error UI. The user's
  // "missing" chips and provider hints come from the rest of the page anyway.
  if (isError && !coverage) return null;

  // No data and not loading (e.g. ClickHouse unavailable, returned an empty
  // artifact list). Hide rather than render an empty card.
  if (!coverage || coverage.artifacts.length === 0) return null;

  const overall = Math.round(
    coverage.artifacts.reduce((s, a) => s + a.pct, 0) / coverage.artifacts.length,
  );
  const totalProviders = coverage.artifacts.reduce((s, a) => s + a.have.length, 0);
  const totalMissing = coverage.artifacts.reduce((s, a) => s + a.missing.length, 0);
  const thinCount = coverage.artifacts.filter(a => a.state !== 'good').length;

  return (
    <div className="bg-card border border-border/60 rounded-xl overflow-hidden shadow-none">
      <div className="px-5 py-4 flex items-end justify-between gap-6 border-b border-border/60 bg-muted/20">
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/80 mb-1.5">
            Enrichment coverage · by artifact type
          </div>
          <div className="flex items-end gap-3">
            <div
              className="font-semibold tabular-nums shrink-0 leading-none"
              style={{ fontSize: '36px', color: 'var(--primary)' }}
            >
              {overall}
              <span className="text-muted-foreground" style={{ fontSize: '18px' }}>%</span>
            </div>
            <div className="pb-0.5 min-w-0">
              <div className="text-[12.5px] text-foreground">
                Of artifacts in your events get enriched.{' '}
                {thinCount > 0 ? (
                  <>
                    <span className="text-foreground">{thinCount}</span>{' '}
                    {thinCount === 1 ? 'type is' : 'types are'} thin.
                  </>
                ) : (
                  <>All types are healthy.</>
                )}
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5 whitespace-nowrap">
                {coverage.artifacts.length} artifact types · {totalProviders} active providers · {totalMissing} recommended
                {coverage.computed_at && (
                  <>
                    {' · '}as of{' '}
                    <span className="font-mono text-foreground">
                      {formatUTCCompact(coverage.computed_at)}
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 text-[10.5px] font-mono text-muted-foreground shrink-0">
          {(['good', 'partial', 'gap'] as const).map(k => (
            <span
              key={k}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-border/60 bg-muted/20"
            >
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: STATE_TONE[k].color }} />
              {STATE_TONE[k].label}
            </span>
          ))}
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={isFetching}
              aria-label="Refresh coverage"
              title="Recompute now — invalidates the shared 6h cache"
              className={cn(
                'inline-flex items-center justify-center w-6 h-6 rounded border border-border/60 bg-muted/20 ml-0.5',
                'text-muted-foreground hover:text-foreground hover:bg-muted/40',
                'disabled:opacity-60 disabled:cursor-not-allowed',
              )}
            >
              <RefreshCw className={cn('w-[11px] h-[11px]', isFetching && 'animate-spin')} />
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 divide-x divide-border/60">
        {coverage.artifacts.map((row, i) => (
          <CoverageRow
            key={row.id}
            row={row}
            isAfterFirstColumn={i % 3 !== 0}
            isAfterFirstRow={i >= 3}
            onAddMissing={onAddMissing}
          />
        ))}
      </div>
    </div>
  );
}

interface CoverageRowProps {
  row: ArtifactCoverage;
  isAfterFirstColumn: boolean;
  isAfterFirstRow: boolean;
  onAddMissing: (name: string) => void;
}

function CoverageRow({ row, isAfterFirstRow, onAddMissing }: CoverageRowProps) {
  const tone = STATE_TONE[row.state].color;
  return (
    <div className={cn('p-4', isAfterFirstRow && 'border-t border-border/60')}>
      <div className="flex items-center gap-2 mb-2">
        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: tone }} />
        <span className="text-[12.5px] font-medium text-foreground whitespace-nowrap truncate">
          {row.label}
        </span>
        <span className="font-mono text-[11px] tabular-nums text-foreground ml-auto shrink-0">
          {row.pct}
          <span className="text-muted-foreground/60">%</span>
        </span>
      </div>
      <SegmentedBar pct={row.pct} tone={tone} />
      {row.have.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1">
          {row.have.slice(0, 3).map(h => (
            <span
              key={h}
              className="inline-flex items-center gap-1 text-[10.5px] font-mono text-muted-foreground px-1.5 py-0.5 rounded bg-muted/40 border border-border/60 whitespace-nowrap"
            >
              <Check className="w-[9px] h-[9px] text-emerald-500 shrink-0" />
              {h}
            </span>
          ))}
          {row.have.length > 3 && (
            <span className="text-[10.5px] font-mono text-muted-foreground/70">
              +{row.have.length - 3}
            </span>
          )}
        </div>
      )}
      {row.missing.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1">
          {row.missing.map(m => (
            <button
              key={m}
              type="button"
              onClick={() => onAddMissing(m)}
              className="inline-flex items-center gap-1 text-[10.5px] font-mono px-1.5 py-0.5 rounded border border-dashed border-border text-muted-foreground hover:text-primary hover:border-primary/50 hover:bg-primary/5 whitespace-nowrap"
            >
              <Plus className="w-[9px] h-[9px] shrink-0" />
              {m}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function SegmentedBar({ pct, tone }: { pct: number; tone: string }) {
  const cells = 24;
  const filled = Math.round((pct / 100) * cells);
  return (
    <div className="flex gap-[2px] flex-1 min-w-0">
      {Array.from({ length: cells }).map((_, i) => (
        <div
          key={i}
          className="h-[8px] flex-1 rounded-[1px]"
          style={{
            background: i < filled ? tone : 'color-mix(in srgb, var(--foreground) 6%, transparent)',
          }}
        />
      ))}
    </div>
  );
}

/**
 * Dense, on-brand skeleton that mirrors the real card's layout (header strip
 * with eyebrow + big number + meta line, then 6 artifact rows arranged
 * 3-up × 2-down). Uses the existing `Skeleton` primitive so the pulse
 * timing/color matches the rest of the app.
 */
function CoverageHeroSkeleton() {
  return (
    <div
      className="bg-card border border-border/60 rounded-xl overflow-hidden shadow-none"
      role="status"
      aria-label="Loading enrichment coverage"
      aria-busy="true"
    >
      <div className="px-5 py-4 flex items-end justify-between gap-6 border-b border-border/60 bg-muted/20">
        <div className="min-w-0 flex-1">
          <Skeleton className="h-[10px] w-[200px] mb-2" />
          <div className="flex items-end gap-3">
            <Skeleton className="h-[36px] w-[88px]" />
            <div className="pb-0.5 min-w-0 flex-1 max-w-[420px]">
              <Skeleton className="h-[12px] w-full mb-1.5" />
              <Skeleton className="h-[10px] w-[70%]" />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <Skeleton className="h-[18px] w-[52px]" />
          <Skeleton className="h-[18px] w-[58px]" />
          <Skeleton className="h-[18px] w-[44px]" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 divide-x divide-border/60">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className={cn('p-4', i >= 3 && 'border-t border-border/60')}
          >
            <div className="flex items-center gap-2 mb-2">
              <Skeleton className="h-1.5 w-1.5 rounded-full" />
              <Skeleton className="h-[12px] w-[120px]" />
              <Skeleton className="h-[11px] w-[28px] ml-auto" />
            </div>
            <Skeleton className="h-[8px] w-full" />
            <div className="mt-3 flex flex-wrap items-center gap-1">
              <Skeleton className="h-[16px] w-[64px] rounded" />
              <Skeleton className="h-[16px] w-[80px] rounded" />
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-1">
              <Skeleton className="h-[16px] w-[72px] rounded" />
              <Skeleton className="h-[16px] w-[60px] rounded" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
