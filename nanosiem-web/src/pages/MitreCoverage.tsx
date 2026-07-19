// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 — MITRE ATT&CK Coverage page redesigned for the redesign branch.
// Port of design-ref/mitre-coverage.html + design-ref/shadcn/mitre-*.jsx.
// AppLayout owns the breadcrumb (`AppBreadcrumbs` has /rules/coverage wired);
// this page renders only the body: summary strip → filter row → matrix → drawer.

import { useMemo, useState } from 'react';
import { AlertTriangle, Loader2, Search as SearchIcon, Shield } from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  useMitreCoverage,
  useMitreData,
  useMitreQuarantine,
  type MitreQuarantinedMapping,
  type MitreSyncState,
} from '@/hooks/useMitreData';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

import { CoverageMatrix } from '@/components/mitre/CoverageMatrix';
import { TechniqueDetailSheet } from '@/components/mitre/TechniqueDetailSheet';
import {
  type CoverageTier,
  type Density,
  type RedesignFilters,
  type StatusKey,
  type TechniqueCoverage,
  summarizeTechniqueCoverage,
} from '@/components/mitre/types';

// ----------------------------------------------------------------------------
// Summary strip — donut + tier breakdown + top hot-gap chips.
// ----------------------------------------------------------------------------

interface TierTotals {
  full: number;
  partial: number;
  'hot-gap': number;
  gap: number;
}

function CoverageDonut({ pct }: { pct: number }) {
  const r = 22;
  const c = 2 * Math.PI * r;
  const covered = c * (pct / 100);
  return (
    <svg viewBox="0 0 56 56" className="w-[56px] h-[56px] -rotate-90">
      <circle cx="28" cy="28" r={r} stroke="currentColor" className="text-border" strokeWidth="6" fill="none" />
      <circle
        cx="28"
        cy="28"
        r={r}
        stroke="currentColor"
        className="text-primary"
        strokeWidth="6"
        fill="none"
        strokeDasharray={`${covered} ${c}`}
        strokeLinecap="round"
      />
    </svg>
  );
}

const TIER_CHIP: Record<CoverageTier, { label: string; cls: string }> = {
  full:      { label: 'Full',     cls: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30' },
  partial:   { label: 'Partial',  cls: 'text-amber-500 bg-amber-500/10 border-amber-500/30' },
  'hot-gap': { label: 'Hot gaps', cls: 'text-rose-500 bg-rose-500/10 border-rose-500/30' },
  gap:       { label: 'No data',  cls: 'text-muted-foreground bg-foreground/5 border-border' },
};

function TierPill({ tier, count }: { tier: CoverageTier; count: number }) {
  const cfg = TIER_CHIP[tier];
  return (
    <span className={cn('inline-flex items-center gap-1.5 h-[22px] pl-1.5 pr-2 rounded-md border text-[10.5px] font-mono', cfg.cls)}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      <span>{cfg.label}</span>
      <span className="opacity-70">·</span>
      <span className="font-semibold tabular-nums">{count}</span>
    </span>
  );
}

// ----------------------------------------------------------------------------
// Unmapped-rules banner (NAN-1918).
//
// Coverage counts only live mappings, so a rule whose mapping a catalog sync
// dropped stops contributing — and the percentage rises. Without this the
// number on this page looks better precisely because detection got worse.
// ----------------------------------------------------------------------------

function DroppedMappingsBanner({ mappings }: { mappings: MitreQuarantinedMapping[] }) {
  const [expanded, setExpanded] = useState(false);
  if (mappings.length === 0) return null;

  return (
    <div className="mx-3 mt-3 border border-amber-500/30 bg-amber-500/10 rounded-md">
      <div className="flex items-start gap-2 px-3 py-2">
        <AlertTriangle className="w-4 h-4 mt-[1px] shrink-0 text-amber-500" strokeWidth={1.5} />
        <div className="min-w-0 flex-1">
          <p className="text-[12px] leading-snug">
            <span className="font-medium">
              {mappings.length} {mappings.length === 1 ? 'rule has' : 'rules have'} no ATT&amp;CK
              mapping
            </span>
            <span className="text-muted-foreground">
              {' '}— an ATT&amp;CK catalog update dropped {mappings.length === 1 ? 'it' : 'them'}.
              The coverage figure below excludes {mappings.length === 1 ? 'this rule' : 'these rules'}.
            </span>
          </p>
          <button
            type="button"
            onClick={() => setExpanded((open) => !open)}
            className="mt-1 text-[11px] text-muted-foreground hover:text-foreground underline underline-offset-2"
          >
            {expanded ? 'Hide' : 'Show'} affected rules
          </button>
          {expanded && (
            <ul className="mt-2 space-y-1 border-t border-amber-500/20 pt-2">
              {mappings.map((mapping) => (
                <li key={mapping.id} className="flex flex-wrap items-baseline gap-x-2 text-[11px]">
                  <span className="font-mono text-[10.5px]">
                    {mapping.rule_name ?? mapping.rule_id}
                  </span>
                  <span className="text-muted-foreground">was</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground">
                    {[...mapping.original_tactics, ...mapping.original_techniques].join(' ') || '—'}
                  </span>
                  <span className="text-muted-foreground">· {mapping.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

interface SummaryStripProps {
  pct: number;
  covered: number;
  total: number;
  tiers: TierTotals;
  coverageGaps: TechniqueCoverage[];
  totalGapCount: number;
  onOpenTechnique: (tacticId: string, techniqueId: string) => void;
}

function SummaryStrip({ pct, covered, total, tiers, coverageGaps, totalGapCount, onOpenTechnique }: SummaryStripProps) {
  return (
    <div className="shrink-0 border-b border-border bg-card/40">
      {/* Title row */}
      <div className="px-5 pt-3.5 pb-3 flex items-start gap-4">
        <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0">
          <Shield className="w-[18px] h-[18px] text-foreground/80" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground whitespace-nowrap">
              MITRE ATT&amp;CK coverage
            </div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px">
              Enterprise
            </span>
          </div>
          <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[780px]">
            Coverage is computed from live detection rules mapped to each technique. Disabled and
            draft rules don&apos;t count. Techniques with no rules but active telemetry are surfaced
            as <span className="text-rose-500">hot gaps</span> — you have the signal, just no detection.
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="px-5 pb-4 grid grid-cols-12 gap-3">
        {/* Donut + % */}
        <div className="col-span-12 md:col-span-3 rounded-lg border border-border bg-card p-3 flex items-center gap-3">
          <div className="relative">
            <CoverageDonut pct={pct} />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="font-mono text-[12.5px] font-semibold text-foreground tabular-nums">{pct}%</span>
            </div>
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Overall coverage</div>
            <div className="text-[13px] text-foreground mt-0.5">
              <span className="font-mono tabular-nums">{covered}</span>
              <span className="text-muted-foreground"> / {total} techniques</span>
            </div>
            <div className="text-[10.5px] text-muted-foreground mt-0.5">Enterprise ATT&amp;CK</div>
          </div>
        </div>

        {/* Tier breakdown */}
        <div className="col-span-12 md:col-span-4 rounded-lg border border-border bg-card p-3 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Tier breakdown</div>
            <div className="text-[10px] font-mono text-muted-foreground">live rules only</div>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <TierPill tier="full" count={tiers.full} />
            <TierPill tier="partial" count={tiers.partial} />
            <TierPill tier="hot-gap" count={tiers['hot-gap']} />
            <TierPill tier="gap" count={tiers.gap} />
          </div>
          <div className="h-1.5 flex rounded-full overflow-hidden bg-border mt-0.5">
            <div className="bg-emerald-500" style={{ width: `${(tiers.full / Math.max(total, 1)) * 100}%` }} />
            <div className="bg-amber-500" style={{ width: `${(tiers.partial / Math.max(total, 1)) * 100}%` }} />
            <div className="bg-rose-500" style={{ width: `${(tiers['hot-gap'] / Math.max(total, 1)) * 100}%` }} />
            <div className="bg-foreground/20" style={{ width: `${(tiers.gap / Math.max(total, 1)) * 100}%` }} />
          </div>
        </div>

        {/* Coverage gaps — every parent and sub-technique is an independent
            coverage unit, matching the API and matrix headers.
            Replaces the older "Top hot gaps" panel which gated chips on
            data_source.connected — that flag isn't reliably populated, so
            the panel always read "0 with connected sources · 0 live rules"
            even when the matrix had real gaps. The matrix is authoritative;
            this panel is the click-shortcut to its worst entries. */}
        <div className="col-span-12 md:col-span-5 rounded-lg border border-border bg-card p-3 flex flex-col min-w-0">
          <div className="flex items-center justify-between mb-1.5">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <AlertTriangle className="w-[11px] h-[11px] text-rose-500" />
              Top coverage gaps
            </div>
            <div className="text-[10px] font-mono text-muted-foreground">
              {totalGapCount === 0
                ? 'no gaps'
                : `${totalGapCount} ${totalGapCount === 1 ? 'technique' : 'techniques'} uncovered`}
            </div>
          </div>
          <div className="flex-1 flex flex-wrap gap-1 content-start">
            {coverageGaps.length === 0 ? (
              <div className="text-[11px] text-muted-foreground italic">
                Every technique has at least one live rule. Coverage matrix below confirms.
              </div>
            ) : (
              coverageGaps.map((t) => (
                <button
                  key={`${t.tactic_ids[0] ?? 'unknown'}-${t.technique_id}`}
                  type="button"
                  onClick={() => onOpenTechnique(t.tactic_ids[0] ?? '', t.technique_id)}
                  className="group inline-flex items-center gap-1.5 h-[22px] pl-1.5 pr-2 rounded-md border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 text-[10.5px] font-mono transition"
                >
                  <span className="w-1 h-1 rounded-full bg-rose-500" />
                  <span className="opacity-90">{t.technique_id}</span>
                  <span className="text-rose-500/80 truncate max-w-[170px] group-hover:text-rose-500">
                    {t.technique_name}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Filter row.
// ----------------------------------------------------------------------------

const STATUS_CHOICES: { id: StatusKey; label: string }[] = [
  { id: 'live', label: 'Live' },
  { id: 'review', label: 'In review' },
  { id: 'disabled', label: 'Disabled' },
];

interface FilterRowProps {
  filters: RedesignFilters;
  onChange: (next: RedesignFilters) => void;
  density: Density;
  onDensity: (d: Density) => void;
  showIds: boolean;
  onShowIds: (v: boolean) => void;
  platforms: { id: string; label: string }[];
}

function FilterRow({ filters, onChange, density, onDensity, showIds, onShowIds, platforms }: FilterRowProps) {
  const toggleStatus = (id: StatusKey) => {
    const next = new Set(filters.status);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange({ ...filters, status: next });
  };

  return (
    <div className="shrink-0 h-[42px] border-b border-border bg-card/40 flex items-center gap-2 px-3.5 overflow-x-auto">
      {/* Search */}
      <div className="relative w-[260px] shrink-0">
        <SearchIcon className="w-[13px] h-[13px] absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <input
          value={filters.q}
          onChange={(e) => onChange({ ...filters, q: e.target.value })}
          placeholder="Search T-id, technique…"
          className="w-full h-[26px] pl-7 pr-2 rounded-md border border-border bg-card text-[11.5px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/50"
        />
      </div>

      {/* Status chips */}
      <div className="flex items-center gap-1 shrink-0">
        {STATUS_CHOICES.map((s) => {
          const on = filters.status.has(s.id);
          return (
            <button
              key={s.id}
              type="button"
              onClick={() => toggleStatus(s.id)}
              className={cn(
                'h-[26px] px-2.5 rounded-md text-[11px] border font-mono transition-colors',
                on
                  ? 'border-primary text-primary bg-primary/10'
                  : 'border-border bg-card text-foreground/80 hover:bg-secondary',
              )}
            >
              {s.label}
            </button>
          );
        })}
      </div>

      {/* Gaps-only */}
      <button
        type="button"
        onClick={() => onChange({ ...filters, gapOnly: !filters.gapOnly })}
        className={cn(
          'h-[26px] px-2.5 rounded-md text-[11px] border flex items-center gap-1.5 font-mono shrink-0 transition-colors',
          filters.gapOnly
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-500'
            : 'border-border bg-card text-foreground/80 hover:bg-secondary',
        )}
      >
        <span
          className={cn(
            'w-2.5 h-2.5 rounded-sm border flex items-center justify-center',
            filters.gapOnly ? 'border-rose-500 bg-rose-500' : 'border-border bg-card',
          )}
        />
        Gaps only
      </button>

      {/* Platforms — only render when backend ships per-rule source. */}
      {platforms.length > 0 && (
        <div className="text-[10.5px] font-mono text-muted-foreground shrink-0 px-2">
          {filters.platforms.size === 0 ? `${platforms.length} sources` : `${filters.platforms.size} selected`}
        </div>
      )}

      <div className="flex-1 min-w-[8px]" />

      {/* Density */}
      <div className="flex items-center gap-1 shrink-0">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-1">density</span>
        {(['compact', 'default', 'roomy'] as Density[]).map((d) => (
          <button
            key={d}
            type="button"
            onClick={() => onDensity(d)}
            className={cn(
              'h-[22px] px-2 rounded-md text-[10.5px] font-mono border transition-colors',
              density === d
                ? 'border-primary text-primary bg-primary/10'
                : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary',
            )}
          >
            {d[0]}
          </button>
        ))}
      </div>

      <div className="h-4 w-px bg-border mx-1" />

      <button
        type="button"
        onClick={() => onShowIds(!showIds)}
        className={cn(
          'h-[22px] px-2 rounded-md text-[10.5px] font-mono border transition-colors shrink-0',
          showIds
            ? 'border-primary text-primary bg-primary/10'
            : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary',
        )}
      >
        IDs
      </button>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Boot / seed window — the pinned ATT&CK catalog hasn't populated yet, so the
// coverage matrix would render a phantom 0-of-0 grid. Surface the real sync
// state instead of implying "zero coverage" (NAN-1766 / D5).
// ----------------------------------------------------------------------------

function CatalogEmptyState({ syncState }: { syncState: MitreSyncState | null }) {
  const neverSynced = syncState == null || syncState.last_success_at == null;
  const failed = syncState?.status === 'failed';
  // Treat unknown/never-synced as "syncing" — an empty catalog on first boot is
  // overwhelmingly the seed window, not a terminal failure.
  const syncing = !failed && (syncState == null || syncState.status === 'syncing' || neverSynced);

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="max-w-[460px] text-center flex flex-col items-center gap-3">
        {syncing ? (
          <>
            <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            <div className="text-[14px] font-semibold text-foreground">ATT&amp;CK catalog syncing…</div>
            <div className="text-[11.5px] text-muted-foreground leading-relaxed">
              The MITRE ATT&amp;CK catalog is being fetched and validated. Coverage will appear as soon
              as techniques are available — this usually takes under a minute on first boot.
            </div>
          </>
        ) : (
          <>
            <AlertTriangle className="w-8 h-8 text-amber-500" />
            <div className="text-[14px] font-semibold text-foreground">ATT&amp;CK catalog unavailable</div>
            <div className="text-[11.5px] text-muted-foreground leading-relaxed">
              The catalog hasn&apos;t been populated yet. On air-gapped or egress-restricted
              deployments it must be seeded before coverage can be computed.
            </div>
            {syncState?.last_error ? (
              <div className="text-[10.5px] font-mono text-rose-500/90 break-words max-w-full">
                {syncState.last_error}
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Page.
// ----------------------------------------------------------------------------

export function MitreCoverage() {
  useDocumentTitle('MITRE ATT&CK Coverage');

  // The redesign filters are independent of the API's severity/mode filters —
  // search, status chips, and gaps-only are all applied client-side against
  // the already-fetched response.
  const [filters, setFilters] = useState<RedesignFilters>({
    q: '',
    status: new Set<StatusKey>(),
    platforms: new Set<string>(),
    gapOnly: false,
  });
  const [density, setDensity] = useState<Density>('default');
  const [showIds, setShowIds] = useState(true);
  const [drawer, setDrawer] = useState<{ tacticId: string; techniqueId: string } | null>(null);

  const { data, loading, error } = useMitreCoverage({ severity: [], mode: [] });
  // Only used to distinguish an empty catalog that is still syncing from a
  // genuine no-data state; the coverage endpoint itself carries no sync state.
  const { data: catalogData } = useMitreData();
  // Only rules still missing a mapping — anything a later sync repaired is
  // already back in the coverage figure and would be noise here.
  const { mappings: quarantined } = useMitreQuarantine();
  const droppedMappings = useMemo(
    () => quarantined.filter((mapping) => mapping.repaired_at === null),
    [quarantined],
  );

  const techniques = useMemo(() => data?.techniques ?? [], [data?.techniques]);
  const tactics = useMemo(() => data?.tactics ?? [], [data?.tactics]);

  const techniqueById = useMemo(() => new Map(techniques.map((t) => [t.technique_id, t])), [techniques]);

  const subsByParent = useMemo(() => {
    const map = new Map<string, TechniqueCoverage[]>();
    techniques
      .filter((t) => t.is_subtechnique && t.parent_id)
      .forEach((t) => {
        const list = map.get(t.parent_id!) ?? [];
        list.push(t);
        map.set(t.parent_id!, list);
      });
    return map;
  }, [techniques]);

  const tactsById = useMemo(() => new Map(tactics.map((t) => [t.tactic_id, t])), [tactics]);

  // Parents and sub-techniques are independent coverage units everywhere.
  // The backend summary carries the same explicit `technique` unit contract.
  const coverageStats = useMemo(() => summarizeTechniqueCoverage(techniques), [techniques]);
  const tiers: TierTotals = coverageStats.tiers;
  const total = data?.summary.total_techniques ?? coverageStats.total;
  const covered = coverageStats.covered;
  const pct = coverageStats.percentage;
  const allCoverageGaps = coverageStats.gaps;
  const coverageGaps = useMemo(() => allCoverageGaps.slice(0, 8), [allCoverageGaps]);

  // Surface the union of rule sources actually present in the response — empty
  // until the backend ships per-rule source. The filter row hides the chip
  // when this list is empty.
  const platforms = useMemo(() => {
    const set = new Set<string>();
    techniques.forEach((t) => (t.rules || []).forEach((r) => r.source && set.add(r.source)));
    return [...set].sort().map((id) => ({ id, label: id }));
  }, [techniques]);

  const openTechnique = (tacticId: string, techniqueId: string) =>
    setDrawer({ tacticId, techniqueId });
  const closeDrawer = () => setDrawer(null);

  // Resolve drawer payload — handle both parent and sub-technique selection.
  const drawerPayload = (() => {
    if (!drawer) return null;
    const t = techniqueById.get(drawer.techniqueId);
    if (!t) return null;
    const parent = t.is_subtechnique && t.parent_id ? techniqueById.get(t.parent_id) ?? null : null;
    const parentForSubs = parent ?? t;
    return {
      technique: t,
      parent,
      subs: subsByParent.get(parentForSubs.technique_id) ?? [],
      tactic: tactsById.get(drawer.tacticId) ?? null,
    };
  })();

  if (error) {
    return (
      <Card className="border-rose-500/20 bg-rose-500/10">
        <CardContent className="p-6">
          <p className="text-rose-500">Failed to load MITRE coverage data: {error}</p>
          <Button onClick={() => window.location.reload()} className="mt-4">
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  // Boot/seed window: an empty catalog would otherwise render as a phantom
  // 0-of-0 matrix. Show the real catalog sync state instead (NAN-1766 / D5).
  if (!loading && techniques.length === 0) {
    return (
      <div className="flex flex-col h-full min-h-0 -m-3">
        <CatalogEmptyState syncState={catalogData?.sync_state ?? null} />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0 -m-3">
      <DroppedMappingsBanner mappings={droppedMappings} />
      <SummaryStrip
        pct={pct}
        covered={covered}
        total={total}
        tiers={tiers}
        coverageGaps={coverageGaps}
        totalGapCount={allCoverageGaps.length}
        onOpenTechnique={openTechnique}
      />
      <FilterRow
        filters={filters}
        onChange={setFilters}
        density={density}
        onDensity={setDensity}
        showIds={showIds}
        onShowIds={setShowIds}
        platforms={platforms}
      />

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        </div>
      ) : data ? (
        <CoverageMatrix
          tactics={tactics}
          techniques={techniques}
          filters={filters}
          density={density}
          showIds={showIds}
          onOpenTechnique={openTechnique}
        />
      ) : (
        <div className="flex-1 flex items-center justify-center text-muted-foreground text-[12px]">
          No coverage data available
        </div>
      )}

      <TechniqueDetailSheet
        open={drawer !== null}
        onOpenChange={(o) => (o ? null : closeDrawer())}
        technique={drawerPayload?.technique ?? null}
        parentTechnique={drawerPayload?.parent ?? null}
        subs={drawerPayload?.subs ?? []}
        tactic={drawerPayload?.tactic ?? null}
      />
    </div>
  );
}

export default MitreCoverage;
