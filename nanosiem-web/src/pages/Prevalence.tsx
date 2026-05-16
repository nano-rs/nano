// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-563 — Runtime Prevalence (analytical) page. Ported to Wave 18+ dense aesthetic.
 *
 * Source of truth: design-ref/prevalence.html.
 * Eyebrow + 20px H1 + meta line; flat KPI tiles; flat filter bar; flat heatmap card
 * (wraps the existing PrevalenceExplorerHeatmap unchanged); flat artifacts table with
 * mono uppercase header strip and a 4-card facet grid in the expanded row.
 *
 * NOT to be confused with PrevalenceSettings.tsx (the rarity-thresholds admin page
 * shipped in Wave 20 as NAN-554 / #833).
 */

import { useState, useEffect, useCallback, useMemo, Fragment } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  AlertOctagon,
  Hash,
  Globe,
  Server,
  RefreshCw,
  Search,
  Clock,
  Sparkles,
  ShieldAlert,
  Download,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  User,
  Cpu,
  Tag,
  Wifi,
  MapPin,
  Filter,
  Grid as GridIcon,
} from 'lucide-react';
import { useArtifactExplorer, useArtifactDetail } from '@/hooks/use-api';
import { formatUTCCompact, formatRelativeCompact, buildHeatmapDays, expandPackedDaily } from '@/lib/date-utils';
import { PrevalenceExplorerHeatmap } from '@/components/prevalence';
import { RuleActivityHeatmap } from '@/components/detection/RuleActivityHeatmap';
import type { ArtifactExplorerItem } from '@/lib/api/types';
import { cn } from '@/lib/utils';

type TimeWindow = '1h' | '24h' | '7d' | '30d';
type ArtifactTypeFilter = 'all' | 'hash' | 'domain' | 'ip';
type RiskFilter = 'all' | 'rare' | 'new';

const PAGE_SIZE = 50;
const NEW_ARTIFACT_WINDOW_MS = 24 * 60 * 60 * 1000;

const TIME_LABELS: Record<TimeWindow, string> = {
  '1h': 'Last 1 hour',
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

const TYPE_LABELS: Record<ArtifactTypeFilter, string> = {
  all: 'All types',
  hash: 'Hashes',
  domain: 'Domains',
  ip: 'IP addresses',
};

const RISK_LABELS: Record<RiskFilter, string> = {
  all: 'All risk',
  rare: 'Rare',
  new: 'New',
};

function getArtifactTypeDisplay(type: string): { label: string; icon: typeof Hash } {
  switch (type) {
    case 'hash_md5': return { label: 'md5', icon: Hash };
    case 'hash_sha256': return { label: 'sha256', icon: Hash };
    case 'hash_unknown': return { label: 'hash', icon: Hash };
    case 'domain': return { label: 'domain', icon: Globe };
    case 'subdomain': return { label: 'subdomain', icon: Globe };
    case 'ip_address': return { label: 'ip', icon: Globe };
    case 'ip_address_private': return { label: 'private ip', icon: Globe };
    default: return { label: 'host', icon: Server };
  }
}

function Eyebrow({ icon: Icon, children }: { icon: typeof GridIcon; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80">
      <Icon className="h-[11px] w-[11px]" />
      {children}
    </div>
  );
}

type KpiTone = 'danger' | 'warn' | 'brand';

function KpiTile({
  label,
  value,
  sub,
  icon: Icon,
  tone,
  loading,
}: {
  label: string;
  value: number;
  sub: string;
  icon: typeof AlertOctagon;
  tone: KpiTone;
  loading: boolean;
}) {
  const toneClasses =
    tone === 'danger'
      ? { fg: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' }
      : tone === 'warn'
        ? { fg: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' }
        : { fg: 'text-primary', bg: 'bg-primary/10', border: 'border-primary/30' };

  return (
    <div className="flex items-start gap-3 rounded-md border border-border bg-card px-4 py-3.5 transition-colors hover:border-border/80">
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80">
          {label}
        </div>
        <div
          className={cn('mt-1.5 font-semibold tabular-nums tracking-tight', toneClasses.fg)}
          style={{ fontSize: '32px', lineHeight: '1.05' }}
        >
          {loading ? <span className="text-muted-foreground/40">—</span> : value.toLocaleString()}
        </div>
        <div className="mt-1 text-[11.5px] text-muted-foreground">{sub}</div>
      </div>
      <div
        className={cn(
          'flex h-9 w-9 shrink-0 items-center justify-center rounded-md border',
          toneClasses.border,
          toneClasses.bg,
        )}
      >
        <Icon className={cn('h-4 w-4', toneClasses.fg)} />
      </div>
    </div>
  );
}

function FilterPill({
  icon: Icon,
  value,
  options,
  onChange,
  ariaLabel,
}: {
  icon: typeof Clock;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  ariaLabel: string;
}) {
  const current = options.find((o) => o.value === value)?.label ?? value;
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger
        aria-label={ariaLabel}
        className="h-9 w-auto gap-1.5 rounded-md border border-border bg-card px-3 text-[12px] font-medium text-muted-foreground hover:bg-card/70 hover:text-foreground focus:ring-0 focus:ring-offset-0 [&>span]:flex [&>span]:items-center [&>span]:gap-1.5"
      >
        <SelectValue>
          <Icon className="h-3 w-3 text-muted-foreground" />
          <span className="whitespace-nowrap">{current}</span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {options.map((opt) => (
          <SelectItem key={opt.value} value={opt.value} className="text-[12px]">
            {opt.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function TagChip({ kind }: { kind: 'rare' | 'new' }) {
  const tone =
    kind === 'rare'
      ? 'border-red-500/30 bg-red-500/10 text-red-400'
      : 'border-primary/30 bg-primary/10 text-primary';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[0.08em]',
        tone,
      )}
    >
      {kind}
    </span>
  );
}

function TypePill({ artifactType }: { artifactType: string }) {
  const info = getArtifactTypeDisplay(artifactType);
  const Icon = info.icon;
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
      <Icon className="h-3 w-3 text-muted-foreground/70" />
      {info.label}
    </span>
  );
}

export function Prevalence() {
  useDocumentTitle('Prevalence');
  useBreadcrumbTitle('Prevalence');

  const navigate = useNavigate();
  // Default to 1h — narrows the per-load aggregate scan to the most useful
  // triage window. 24h / 7d / 30d are still selectable from the dropdown.
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('1h');
  const [artifactTypeFilter, setArtifactTypeFilter] = useState<ArtifactTypeFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [page, setPage] = useState(0);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  useEffect(() => {
    setPage(0);
  }, [timeWindow, artifactTypeFilter, riskFilter, debouncedSearch]);

  const { data, loading, error, refetch } = useArtifactExplorer({
    window: timeWindow,
    type: artifactTypeFilter === 'all' ? undefined : artifactTypeFilter,
    risk_level: riskFilter === 'all' ? undefined : riskFilter,
    search: debouncedSearch || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  useEffect(() => {
    const interval = setInterval(() => refetch(), 60_000);
    return () => clearInterval(interval);
  }, [refetch]);

  const handleDrilldown = useCallback(
    (artifact: ArtifactExplorerItem) => {
      let field: string;
      if (artifact.artifact_type.startsWith('hash')) field = 'file_hash';
      else if (artifact.artifact_type.startsWith('ip_address')) field = 'dest_ip';
      else field = 'dest_host';
      navigate(`/search?q=${encodeURIComponent(`${field}="${artifact.artifact}"`)}`);
    },
    [navigate],
  );

  const toggleRow = useCallback((key: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const rareCount = data?.rare_count ?? 0;
  const newCount = data?.new_count ?? 0;
  const highRiskCount = data?.high_risk_asset_count ?? 0;
  const artifacts = data?.artifacts ?? [];
  const total = data?.total ?? 0;
  const totalPages = total > 0 ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : 1;
  const heatmapArtifacts = artifacts.slice(0, 20);

  const onExport = useCallback(() => {
    const params = new URLSearchParams();
    params.set('window', timeWindow);
    if (artifactTypeFilter !== 'all') params.set('type', artifactTypeFilter);
    window.open(`/api/prevalence/export?${params.toString()}`, '_blank');
  }, [timeWindow, artifactTypeFilter]);

  return (
    <TooltipProvider delayDuration={300}>
    <div className="flex flex-col px-6 pt-5 pb-6">
      {/* Header */}
      <div className="flex items-end gap-3">
        <div className="min-w-0">
          <Eyebrow icon={GridIcon}>Prevalence index</Eyebrow>
          <h1 className="mt-1 text-[20px] font-semibold tracking-[-0.015em] text-foreground">
            What's running across your fleet
          </h1>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            Indicators ranked by how rare they are. Pivot any row into Search.
          </p>
        </div>
        <span className="flex-1" />
        <div className="flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground">
          <span className={cn('h-1.5 w-1.5 rounded-full', loading ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400 animate-pulse')} />
          <span>{loading ? 'refreshing' : 'indexing live'}</span>
          {data && (
            <>
              <span className="text-muted-foreground/40">·</span>
              <span>
                <span className="tabular-nums text-foreground">{total.toLocaleString()}</span> indicators
              </span>
            </>
          )}
        </div>
      </div>

      {/* KPI strip */}
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
        <KpiTile
          label="Rare artifacts"
          value={rareCount}
          sub="Below rarity threshold"
          icon={AlertOctagon}
          tone="danger"
          loading={loading && !data}
        />
        <KpiTile
          label="New artifacts (24h)"
          value={newCount}
          sub="First seen in last 24 hours"
          icon={Sparkles}
          tone="brand"
          loading={loading && !data}
        />
        <KpiTile
          label="High-risk assets"
          value={highRiskCount}
          sub="Rare + active in last 24h"
          icon={ShieldAlert}
          tone="warn"
          loading={loading && !data}
        />
      </div>

      {/* Filter bar */}
      <div className="mt-4 flex items-center gap-2.5">
        <div className="relative flex h-9 min-w-0 flex-1 items-center gap-2 rounded-md border border-border bg-card/40 px-3 transition-colors focus-within:bg-card/80 hover:bg-card/70">
          <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search artifacts…"
            className="flex-1 bg-transparent text-[13px] text-foreground outline-none placeholder:text-muted-foreground"
          />
        </div>
        <FilterPill
          icon={Clock}
          value={timeWindow}
          options={(Object.entries(TIME_LABELS) as [TimeWindow, string][]).map(([value, label]) => ({ value, label }))}
          onChange={(v) => setTimeWindow(v as TimeWindow)}
          ariaLabel="Time window"
        />
        <FilterPill
          icon={Filter}
          value={artifactTypeFilter}
          options={(Object.entries(TYPE_LABELS) as [ArtifactTypeFilter, string][]).map(([value, label]) => ({ value, label }))}
          onChange={(v) => setArtifactTypeFilter(v as ArtifactTypeFilter)}
          ariaLabel="Artifact type"
        />
        <FilterPill
          icon={ShieldAlert}
          value={riskFilter}
          options={(Object.entries(RISK_LABELS) as [RiskFilter, string][]).map(([value, label]) => ({ value, label }))}
          onChange={(v) => setRiskFilter(v as RiskFilter)}
          ariaLabel="Risk filter"
        />
        <button
          type="button"
          onClick={() => refetch()}
          disabled={loading}
          aria-label="Refresh"
          className="flex h-9 w-9 items-center justify-center rounded-md border border-border bg-card text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </button>
        <button
          type="button"
          onClick={onExport}
          className="flex h-9 items-center gap-1.5 rounded-md border border-border bg-card px-3 text-[12px] font-medium text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground"
        >
          <Download className="h-3.5 w-3.5" />
          Export
        </button>
      </div>

      {/* Heatmap card */}
      {heatmapArtifacts.length > 0 && (
        <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
          <div className="flex items-center gap-3 border-b border-border px-4 py-3">
            <Eyebrow icon={GridIcon}>Artifact prevalence · per host</Eyebrow>
            <span className="flex-1" />
            <div className="font-mono text-[10.5px] text-muted-foreground">
              <span className="tabular-nums text-foreground">{heatmapArtifacts.length}</span> artifacts ·{' '}
              <span className="tabular-nums text-foreground">30</span> days · bucket{' '}
              <span className="text-foreground">1d</span>
            </div>
            <div className="ml-2 flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
              <span>Less</span>
              {[0.05, 0.25, 0.5, 0.75, 1].map((v, i) => (
                <span
                  key={i}
                  className="h-3 w-3 rounded-sm"
                  style={{
                    background:
                      v < 0.06
                        ? 'oklch(0.25 0 0)'
                        : `oklch(0.6 ${0.06 + v * 0.12} 250 / ${0.2 + v * 0.8})`,
                  }}
                />
              ))}
              <span>More</span>
            </div>
          </div>
          <div className="px-4 py-3">
            <PrevalenceExplorerHeatmap
              artifacts={heatmapArtifacts}
              timeWindow={timeWindow}
              onArtifactClick={handleDrilldown}
            />
          </div>
          <div className="flex items-center gap-4 border-t border-border bg-card/40 px-4 py-2 font-mono text-[10.5px] text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-red-400" />
              Rare
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-primary" />
              Common
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-sm border border-border"
                style={{ background: 'oklch(0.25 0 0)' }}
              />
              No activity
            </span>
            <span className="flex-1" />
            <span>scale · log · per-host normalized</span>
          </div>
        </div>
      )}

      {/* Artifacts table */}
      <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Eyebrow icon={Hash}>Artifacts · <span className="text-foreground tabular-nums">{total.toLocaleString()}</span></Eyebrow>
          <span className="flex-1" />
          <div className="flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
            <span>Page</span>
            <span className="tabular-nums text-foreground">{page + 1}</span>
            <span>/</span>
            <span className="tabular-nums">{totalPages}</span>
            <button
              type="button"
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0 || loading}
              aria-label="Previous page"
              className="ml-2 flex h-6 w-6 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-foreground/5 hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
            >
              <ChevronLeft className="h-3 w-3" />
            </button>
            <button
              type="button"
              onClick={() => setPage(page + 1)}
              disabled={!data?.has_more || loading}
              aria-label="Next page"
              className="flex h-6 w-6 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-foreground/5 hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
            >
              <ChevronRight className="h-3 w-3" />
            </button>
          </div>
        </div>

        {/* Column header strip */}
        <div
          className="grid items-center border-b border-border bg-card/40 font-mono text-[9.5px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/80"
          style={{ gridTemplateColumns: '20px minmax(0,1fr) 90px 80px 80px 130px 130px 200px' }}
        >
          <div className="px-2 py-2" />
          <div className="px-2 py-2">Artifact</div>
          <div className="px-2 py-2">Type</div>
          <div className="px-2 py-2 text-right">Hosts</div>
          <div className="px-2 py-2 text-right">Count</div>
          <div className="px-2 py-2">First seen</div>
          <div className="px-2 py-2">Last seen</div>
          <div className="px-2 py-2">Activity (28d)</div>
        </div>

        {/* Body */}
        {error ? (
          <div className="px-4 py-12 text-center text-[12px] text-red-400">
            <AlertOctagon className="mx-auto mb-2 h-5 w-5" />
            <p>{error.message}</p>
          </div>
        ) : loading && !data ? (
          <div className="px-4 py-12 text-center text-[12px] text-muted-foreground">
            <Loader2 className="mx-auto mb-2 h-5 w-5 animate-spin" />
            <p>Loading artifacts…</p>
          </div>
        ) : artifacts.length === 0 ? (
          <div className="px-4 py-12 text-center text-[12px] text-muted-foreground">
            <Search className="mx-auto mb-2 h-5 w-5 opacity-50" />
            <p>No artifacts found</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {artifacts.map((artifact, idx) => {
              const key = `${artifact.artifact}|${artifact.artifact_type}`;
              const isExpanded = expandedRows.has(key);
              return (
                <Fragment key={`${artifact.artifact}-${idx}`}>
                  <ArtifactRow
                    artifact={artifact}
                    isExpanded={isExpanded}
                    onToggle={() => toggleRow(key)}
                    onDrilldown={handleDrilldown}
                  />
                  {isExpanded && (
                    <div className="border-t border-border bg-card/40 px-3 pt-3 pb-4">
                      <ExpandedArtifactDetail
                        artifact={artifact}
                        timeWindow={timeWindow}
                        onDrilldown={handleDrilldown}
                      />
                    </div>
                  )}
                </Fragment>
              );
            })}
          </div>
        )}
      </div>
    </div>
    </TooltipProvider>
  );
}

function ArtifactRow({
  artifact,
  isExpanded,
  onToggle,
  onDrilldown,
}: {
  artifact: ArtifactExplorerItem;
  isExpanded: boolean;
  onToggle: () => void;
  onDrilldown: (artifact: ArtifactExplorerItem) => void;
}) {
  const heatmapDays = useMemo(
    () => buildHeatmapDays(expandPackedDaily(artifact.daily_counts, artifact.daily_start)),
    [artifact.daily_counts, artifact.daily_start],
  );
  const isNew = useMemo(() => {
    const ageMs = Date.now() - new Date(artifact.first_seen).getTime();
    return ageMs < NEW_ARTIFACT_WINDOW_MS;
  }, [artifact.first_seen]);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onToggle();
        }
      }}
      className="group grid cursor-pointer items-center text-[12px] transition-colors hover:bg-foreground/[0.025]"
      style={{ gridTemplateColumns: '20px minmax(0,1fr) 90px 80px 80px 130px 130px 200px' }}
    >
      <div className="px-2 py-2 text-muted-foreground">
        <ChevronDown className={cn('h-3 w-3 transition-transform', isExpanded ? '' : '-rotate-90')} />
      </div>
      <div className="flex min-w-0 items-center gap-2 px-2 py-2">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="truncate font-mono text-[12px] text-foreground">{artifact.artifact}</span>
          </TooltipTrigger>
          <TooltipContent side="top" align="start">
            <p className="max-w-[500px] break-all font-mono text-[11px]">{artifact.artifact}</p>
          </TooltipContent>
        </Tooltip>
        {artifact.is_rare && <TagChip kind="rare" />}
        {isNew && <TagChip kind="new" />}
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onDrilldown(artifact);
          }}
          aria-label="Search events"
          className="rounded-sm opacity-0 transition-opacity focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary group-hover:opacity-100"
        >
          <Search className="h-3 w-3 text-muted-foreground hover:text-foreground" />
        </button>
      </div>
      <div className="px-2 py-2">
        <TypePill artifactType={artifact.artifact_type} />
      </div>
      <div className="px-2 py-2 text-right font-mono tabular-nums text-foreground">
        {artifact.host_count.toLocaleString()}
      </div>
      <div className="px-2 py-2 text-right font-mono tabular-nums text-foreground">
        {artifact.total_occurrences.toLocaleString()}
      </div>
      <div className="min-w-0 truncate px-2 py-2 font-mono text-[11px] text-muted-foreground">
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{formatRelativeCompact(artifact.first_seen)}</span>
          </TooltipTrigger>
          <TooltipContent>
            <p>{formatUTCCompact(artifact.first_seen)}</p>
          </TooltipContent>
        </Tooltip>
      </div>
      <div className="min-w-0 truncate px-2 py-2 font-mono text-[11px] text-muted-foreground">
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{formatRelativeCompact(artifact.last_seen)}</span>
          </TooltipTrigger>
          <TooltipContent>
            <p>{formatUTCCompact(artifact.last_seen)}</p>
          </TooltipContent>
        </Tooltip>
      </div>
      <div className="px-2 py-2">
        <RuleActivityHeatmap data={heatmapDays} />
      </div>
    </div>
  );
}

function FacetCard({
  icon: Icon,
  title,
  rows,
  mono,
}: {
  icon: typeof Server;
  title: string;
  rows: { name: string; meta?: string; value: number }[];
  mono?: boolean;
}) {
  return (
    <div className="rounded-md border border-border bg-card">
      <div className="flex items-center gap-1.5 border-b border-border px-2.5 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/80">
        <Icon className="h-[11px] w-[11px]" />
        {title}
      </div>
      <div className="max-h-[200px] overflow-y-auto px-2 py-1.5">
        {rows.length === 0 ? (
          <div className="px-1 py-1 text-[11px] text-muted-foreground/60">none</div>
        ) : (
          rows.map((row, i) => (
            <div key={i} className="flex items-center gap-2 py-0.5">
              <div className="min-w-0 flex-1">
                <div
                  className={cn(
                    'truncate text-[11.5px] text-foreground',
                    mono && 'font-mono',
                  )}
                >
                  {row.name}
                </div>
                {row.meta && (
                  <div className="truncate font-mono text-[10px] text-muted-foreground/70">{row.meta}</div>
                )}
              </div>
              <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground">
                {row.value.toLocaleString()}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function ExpandedArtifactDetail({
  artifact,
  timeWindow,
  onDrilldown,
}: {
  artifact: ArtifactExplorerItem;
  timeWindow: string;
  onDrilldown: (artifact: ArtifactExplorerItem) => void;
}) {
  const { data: detail, loading } = useArtifactDetail(artifact.artifact, timeWindow);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-6">
        <Loader2 className="h-4 w-4 animate-spin text-primary" />
        <span className="ml-2 font-mono text-[11px] text-muted-foreground">Loading context…</span>
      </div>
    );
  }

  if (!detail) {
    return <div className="px-2 py-4 text-[11.5px] text-muted-foreground">No detail data available</div>;
  }

  const isHash = artifact.artifact_type.startsWith('hash');
  const isIp = artifact.artifact_type.startsWith('ip_address');
  const isDomain = artifact.artifact_type === 'domain' || artifact.artifact_type === 'subdomain';

  const cards: React.ReactNode[] = [];

  if (detail.top_hosts.length > 0) {
    cards.push(
      <FacetCard
        key="hosts"
        icon={Server}
        title={`Top hosts (${detail.top_hosts.length})`}
        rows={detail.top_hosts.map((h) => ({ name: h.host, value: h.count }))}
        mono
      />,
    );
  }

  if (detail.top_users.length > 0) {
    cards.push(
      <FacetCard
        key="users"
        icon={User}
        title={`Top users (${detail.top_users.length})`}
        rows={detail.top_users.map((u) => ({ name: u.user, value: u.count }))}
        mono
      />,
    );
  }

  if (detail.source_types.length > 0) {
    cards.push(
      <FacetCard
        key="sources"
        icon={Tag}
        title="Source types"
        rows={detail.source_types.map((s) => ({ name: s.source_type, value: s.count }))}
        mono
      />,
    );
  }

  if (isHash && detail.processes && detail.processes.length > 0) {
    cards.push(
      <FacetCard
        key="processes"
        icon={Cpu}
        title={`Process context (${detail.processes.length})`}
        rows={detail.processes.map((p) => ({
          name: p.process_name,
          meta: p.command_line,
          value: p.count,
        }))}
        mono
      />,
    );
  }

  if ((isIp || isDomain) && detail.network && detail.network.length > 0) {
    cards.push(
      <FacetCard
        key="network"
        icon={Wifi}
        title={`Network context (${detail.network.length})`}
        rows={detail.network.map((n) => ({
          name: `${n.protocol}/${n.dest_port}`,
          value: n.count,
        }))}
        mono
      />,
    );
  }

  if (isIp && detail.geo && detail.geo.length > 0) {
    cards.push(
      <FacetCard
        key="geo"
        icon={MapPin}
        title={`Geo · ASN (${detail.geo.length})`}
        rows={detail.geo.map((g) => ({
          name: g.country,
          meta: g.asn || 'Unknown ASN',
          value: g.count,
        }))}
      />,
    );
  }

  return (
    <div className="space-y-3">
      {cards.length === 0 ? (
        <p className="px-1 py-2 text-[11.5px] text-muted-foreground">No detail data found for this artifact</p>
      ) : (
        <div
          className="grid gap-3"
          style={{ gridTemplateColumns: `repeat(${Math.min(cards.length, 4)}, minmax(0, 1fr))` }}
        >
          {cards}
        </div>
      )}
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onDrilldown(artifact);
        }}
        className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-card px-2.5 text-[11.5px] text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground"
      >
        <Search className="h-3 w-3" />
        Search events
      </button>
    </div>
  );
}
