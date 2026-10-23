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

import { useState, useEffect, useCallback, useMemo, useRef, Fragment } from 'react';
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
  FileText,
  ShieldCheck,
  Store,
  ScanSearch,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useArtifactExplorer, useArtifactDetail, useArtifactLookup } from '@/hooks/use-api';
import { explorerStatusLabel } from '@/lib/prevalence/explorerStatus';
import { DETAIL_WARMING_MAX_POLLS, detailWarmingDelay } from '@/lib/prevalence/detailWarming';
import { detailCoverageLabel, detailCoverageTitle, isPartialCoverage } from '@/lib/prevalence/detailCoverage';
import { formatUTCCompact, formatRelativeCompact, buildHeatmapDays, expandPackedDaily } from '@/lib/date-utils';
import { trailingWindowTitle } from '@/lib/time-range';
import { PrevalenceExplorerHeatmap } from '@/components/prevalence';
import {
  detectArtifact,
  detectBulkArtifacts,
  artifactKindLabel,
  type DetectedArtifact,
} from '@/lib/prevalence-detect';
import type { PrevalenceData, PrevalenceArtifactType } from '@/lib/api/types';
import { X } from 'lucide-react';
import { RuleActivityHeatmap } from '@/components/detection/RuleActivityHeatmap';
import type {
  ArtifactExplorerItem,
  ArtifactInlineContext,
  ArtifactProcessEntry,
  PrevalenceExplorerCursor,
} from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { enrichTypeFor, openEnrich } from '@/components/threat-intel/enrich-event';
import { useEnrichEnabled } from '@/components/threat-intel/use-threat-intel';
import { api } from '@/lib/api';
import {
  DurableJobNotice,
  type DurableProductJobState,
} from '@/components/search/DurableJobNotice';

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

// NAN-3884: the pill stays relative; the resolved window is its hover text.
const TIME_WINDOW_MS: Record<TimeWindow, number> = {
  '1h': 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
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

function saveExport(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

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
  approximate = false,
}: {
  label: string;
  value: number;
  sub: string;
  icon: typeof AlertOctagon;
  tone: KpiTone;
  loading: boolean;
  /** Count is a floor over a capped fetch buffer — render as `N+`. */
  approximate?: boolean;
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
          title={
            approximate && !loading
              ? 'At least this many — the fleet exceeds the scan buffer, so this is a floor, not an exact total'
              : undefined
          }
        >
          {loading ? (
            <span className="text-muted-foreground/40">—</span>
          ) : (
            <>
              {value.toLocaleString()}
              {approximate && <span className="text-muted-foreground/70">+</span>}
            </>
          )}
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
  title,
}: {
  icon: typeof Clock;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  ariaLabel: string;
  title?: string;
}) {
  const current = options.find((o) => o.value === value)?.label ?? value;
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger
        aria-label={ariaLabel}
        title={title}
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

// ============================================================================
// NAN-849 — inline subtitle rendering
//
// Every prevalence row now carries an optional `context` payload populated by
// the backend in a single bulk pass (see PrevalenceService::enrich_explorer_items).
// We render a single muted line beneath the artifact value so the row is
// scannable without expanding. Format varies by artifact_type — see the
// per-type helpers below. Missing fields degrade gracefully.
// ============================================================================

function truncate(s: string, max = 80): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

function formatHostsUsersSummary(
  hosts: number,
  users: number | undefined,
  hostsSaturated = false,
): string {
  const hostStr = `${hosts.toLocaleString()}${hostsSaturated ? '+' : ''} ${hosts === 1 && !hostsSaturated ? 'host' : 'hosts'}`;
  if (users == null || users === 0) return hostStr;
  return `${hostStr} · ${users.toLocaleString()} ${users === 1 ? 'user' : 'users'}`;
}

/** Build the inline subtitle for a prevalence row. Returns null when there
 *  is no meaningful context to surface — the row renders without a subtitle
 *  rather than reserving empty vertical space. */
function buildSubtitle(artifact: ArtifactExplorerItem): string | null {
  const ctx: ArtifactInlineContext | undefined = artifact.context;
  const hostCount = artifact.host_count;

  // Hash artifacts: top file_name is the truer identity than process_name.
  // When the top process is a wrapper (svchost et al.), promote the
  // process+command-line summary because the file_name will repeat the
  // wrapper's DLL host name many times.
  if (artifact.artifact_type.startsWith('hash')) {
    if (ctx?.top_process_is_wrapper && ctx.top_process_name) {
      const cmd = ctx.top_command_line ? ` (${truncate(ctx.top_command_line, 48)})` : '';
      return `${ctx.top_process_name}${cmd} · ${formatHostsUsersSummary(hostCount, ctx.user_count, artifact.host_count_saturated)}`;
    }
    if (ctx?.top_file_name) {
      return `${ctx.top_file_name} · ${formatHostsUsersSummary(hostCount, ctx.user_count, artifact.host_count_saturated)}`;
    }
    return null;
  }

  // IP artifacts: country + ASN org. Fall back gracefully when partial.
  if (artifact.artifact_type.startsWith('ip_address')) {
    const parts: string[] = [];
    if (ctx?.country) parts.push(ctx.country);
    if (ctx?.asn || ctx?.asn_org) {
      const asnLabel = ctx.asn ? `AS${ctx.asn}` : '';
      const org = ctx.asn_org ?? '';
      parts.push([asnLabel, org].filter(Boolean).join(' ').trim());
    }
    if (parts.length === 0) {
      // Private IPs commonly have no geo — at least surface host/user counts.
      return formatHostsUsersSummary(hostCount, ctx?.user_count, artifact.host_count_saturated);
    }
    return parts.join(' · ');
  }

  // Domain / subdomain.
  if (artifact.artifact_type === 'domain' || artifact.artifact_type === 'subdomain') {
    const left = formatHostsUsersSummary(hostCount, ctx?.user_count, artifact.host_count_saturated);
    return ctx?.top_source_type ? `${left} · ${ctx.top_source_type}` : left;
  }

  // User / host / asset (fallthrough) — count + top source_type.
  return ctx?.top_source_type
    ? `${formatHostsUsersSummary(hostCount, ctx?.user_count, artifact.host_count_saturated)} · ${ctx.top_source_type}`
    : formatHostsUsersSummary(hostCount, ctx?.user_count, artifact.host_count_saturated);
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
  const [pageCursors, setPageCursors] = useState<Array<PrevalenceExplorerCursor | null>>([null]);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [exportJob, setExportJob] = useState<DurableProductJobState | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const exportRunRef = useRef(0);

  useEffect(() => () => {
    exportRunRef.current += 1;
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  useEffect(() => {
    setPage(0);
    setPageCursors([null]);
  }, [timeWindow, artifactTypeFilter, riskFilter, debouncedSearch]);

  // NAN-871: derive page mode from the debounced input so the same bar serves
  // browse / single-artifact lookup / bulk-paste lookup. `bulkDetected` only
  // populates when ≥2 valid artifacts are detected (paste-style); a single
  // valid artifact routes through `singleDetected`. Free-text falls through
  // to browse mode and the existing substring-in-buffer behavior.
  const trimmedSearch = debouncedSearch.trim();
  const bulkDetected = useMemo(
    () => detectBulkArtifacts(debouncedSearch),
    [debouncedSearch],
  );
  const singleDetected = useMemo<DetectedArtifact | null>(
    () => (bulkDetected.length >= 2 ? null : detectArtifact(trimmedSearch)),
    [trimmedSearch, bulkDetected],
  );
  const mode: 'browse' | 'lookup' | 'bulk' =
    bulkDetected.length >= 2 ? 'bulk' : singleDetected ? 'lookup' : 'browse';

  const clearSearch = useCallback(() => {
    setSearchQuery('');
    setDebouncedSearch('');
  }, []);

  const pageCursor = pageCursors[page] ?? null;
  const { data, loading, error, refetch } = useArtifactExplorer({
    window: timeWindow,
    type: artifactTypeFilter === 'all' ? undefined : artifactTypeFilter,
    risk_level: riskFilter === 'all' ? undefined : riskFilter,
    // Only forward the search term in browse mode — in lookup/bulk we drive
    // results from the point-lookup endpoints below.
    search: mode === 'browse' ? (debouncedSearch || undefined) : undefined,
    limit: PAGE_SIZE,
    offset: pageCursor ? 0 : page * PAGE_SIZE,
    cursor_last_seen: pageCursor?.last_seen,
    cursor_kind: pageCursor?.kind,
    cursor_artifact: pageCursor?.artifact,
  });

  const snapshotStatus = explorerStatusLabel(data?.product_state);
  useEffect(() => {
    if (!data?.product_state?.warming && !data?.product_state?.stale) return;
    const timer = window.setTimeout(() => void refetch(), 60_000);
    return () => window.clearTimeout(timer);
  }, [data, refetch]);

  const nextPage = useCallback(() => {
    if (!data?.has_more) return;
    if (data.next_cursor) {
      setPageCursors((current) => {
        const next = current.slice(0, page + 1);
        next[page + 1] = data.next_cursor ?? null;
        return next;
      });
    }
    setPage(page + 1);
  }, [data?.has_more, data?.next_cursor, page]);

  // Header stats for lookup/bulk modes. `useArtifactLookup` resolves to null
  // when artifacts is null/empty so the request short-circuits in browse mode.
  const lookupArtifacts =
    mode === 'lookup' && singleDetected
      ? [singleDetected.value]
      : mode === 'bulk'
        ? bulkDetected.map((d) => d.value)
        : null;
  const { data: lookupData, loading: lookupLoading } = useArtifactLookup(
    lookupArtifacts,
    undefined,
  );

  const handleDrilldown = useCallback(
    (artifact: ArtifactExplorerItem) => {
      let field: string;
      if (artifact.artifact_type.startsWith('hash')) field = 'file_hash';
      else if (artifact.artifact_type.startsWith('ip_address')) field = 'dest_ip';
      else field = 'dest_host';
      navigate(`/search#q=${encodeURIComponent(`${field}="${artifact.artifact}"`)}`);
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
  // P6: headline counts are floors when the fleet exceeds the fetch buffer.
  const countsApproximate = data?.counts_approximate ?? false;
  const artifacts = data?.artifacts ?? [];
  const total = data?.total ?? 0;
  const totalPages = total > 0 ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : 1;
  const heatmapArtifacts = artifacts.slice(0, 20);

  const onExport = useCallback(async () => {
    const run = ++exportRunRef.current;
    setExporting(true);
    setExportError(null);
    setExportJob(null);
    try {
      const started = await api.startPrevalenceExport({
        window: timeWindow,
        type: artifactTypeFilter === 'all' ? undefined : artifactTypeFilter,
        format: 'csv',
      });
      if (run !== exportRunRef.current) return;
      if (started.kind === 'completed') {
        saveExport(started.blob, started.filename);
        return;
      }

      const jobId = started.job.job_id;
      // NAN-2361 hosted-shared tenants: the queued export is a tenant export
      // job polled at `status_url`, not a search job.
      if (started.job.status_url && started.job.download_url) {
        const statusUrl = started.job.status_url;
        const downloadUrl = started.job.download_url;
        const deadline = Date.now() + 40 * 60 * 1000;
        for (;;) {
          if (Date.now() > deadline) throw new Error('Prevalence export did not complete in time');
          const job = await api.getExportJob(statusUrl);
          if (run !== exportRunRef.current) return;
          setExportJob({ jobId, status: job.status === 'expired' ? 'failed' : job.status });
          if (job.status === 'completed') {
            const download = await api.downloadExportJob(downloadUrl, job.filename ?? 'prevalence_export.csv');
            if (run !== exportRunRef.current) return;
            saveExport(download.blob, download.filename);
            setExportJob(null);
            return;
          }
          if (job.status === 'failed' || job.status === 'expired') {
            throw new Error(job.error || `Prevalence export ${job.status}`);
          }
          await new Promise((resolve) => window.setTimeout(resolve, 1500));
        }
      }
      for (;;) {
        const status = await api.getSearchJob(jobId);
        if (run !== exportRunRef.current) return;
        if (status.task_kind && status.task_kind !== 'prevalence_export_v1') {
          throw new Error('Prevalence export job changed type unexpectedly');
        }
        setExportJob({
          jobId,
          status: status.status,
          queuePosition: status.queue_position,
          estimatedWaitSeconds: status.estimated_wait_seconds,
          progress: status.progress,
        });
        if (status.status === 'completed') {
          const download = await api.downloadSearchJob(jobId);
          if (run !== exportRunRef.current) return;
          saveExport(download.blob, download.filename);
          setExportJob(null);
          return;
        }
        if (status.status === 'failed' || status.status === 'cancelled') {
          throw new Error(status.error || `Prevalence export ${status.status}`);
        }
        await new Promise((resolve) => window.setTimeout(resolve, 750));
      }
    } catch (caught) {
      if (run === exportRunRef.current) {
        setExportJob(null);
        setExportError(caught instanceof Error ? caught.message : 'Prevalence export failed');
      }
    } finally {
      if (run === exportRunRef.current) setExporting(false);
    }
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
        {data && (
          <div className="flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground">
            <span
              title={
                countsApproximate
                  ? 'At least this many — the fleet exceeds the scan buffer, so this is a floor, not an exact total'
                  : undefined
              }
            >
              <span className="tabular-nums text-foreground">
                {total.toLocaleString()}
                {countsApproximate && '+'}
              </span>{' '}
              indicators
            </span>
          </div>
        )}
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
          approximate={countsApproximate}
        />
        <KpiTile
          label="New artifacts (24h)"
          value={newCount}
          sub="First seen in last 24 hours"
          icon={Sparkles}
          tone="brand"
          loading={loading && !data}
          approximate={countsApproximate}
        />
        <KpiTile
          label="High-risk assets"
          value={highRiskCount}
          sub="Rare + active in last 24h"
          icon={ShieldAlert}
          tone="warn"
          loading={loading && !data}
          approximate={countsApproximate}
        />
      </div>

      {/* Filter bar */}
      <div className="mt-4 flex items-center gap-2.5">
        <div className="relative flex h-9 min-w-0 flex-1 items-center gap-2 rounded-md border border-border bg-card/40 px-3 transition-colors focus-within:bg-card/80 hover:bg-card/70">
          <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <input
            // NAN-871: in bulk mode the raw paste value contains newlines that
            // a single-line `<input>` can't faithfully render — show the
            // placeholder ("N artifacts pasted") instead so the user gets a
            // truthful indicator. The actual paste lives in `searchQuery`
            // state and drives the bulk results table below.
            value={mode === 'bulk' ? '' : searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onPaste={(e) => {
              // NAN-871: when ≥2 newline-separated artifacts are pasted, swap
              // the search input wholesale instead of letting the browser drop
              // a multi-line blob into a single-line `<input>`. Mode-derivation
              // upstream picks up the bulk shape. Single-line pastes fall
              // through to default behavior (LookupTableView precedent).
              const text = e.clipboardData.getData('text/plain');
              if (!text.includes('\n')) return;
              const detected = detectBulkArtifacts(text);
              if (detected.length >= 2) {
                e.preventDefault();
                setSearchQuery(text);
              }
            }}
            placeholder={
              mode === 'browse'
                ? 'Search artifacts, or paste a hash / IP / domain…'
                : mode === 'lookup'
                  ? 'Looking up artifact…'
                  : `${bulkDetected.length} artifacts pasted — looking up…`
            }
            className="flex-1 bg-transparent text-[13px] text-foreground outline-none placeholder:text-muted-foreground"
          />
          {mode !== 'browse' && (
            <button
              type="button"
              onClick={clearSearch}
              aria-label="Clear search"
              className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-foreground/10 hover:text-foreground"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
        {mode === 'browse' ? (
          <>
            <FilterPill
              icon={Clock}
              value={timeWindow}
              options={(Object.entries(TIME_LABELS) as [TimeWindow, string][]).map(([value, label]) => ({ value, label }))}
              onChange={(v) => setTimeWindow(v as TimeWindow)}
              ariaLabel="Time window"
              title={trailingWindowTitle(TIME_WINDOW_MS[timeWindow])}
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
              {loading ? <LoadingIcon className="h-3.5 w-3.5" /> : <RefreshCw className="h-3.5 w-3.5" />}
            </button>
            <button
              type="button"
              onClick={onExport}
              disabled={exporting}
              className="flex h-9 items-center gap-1.5 rounded-md border border-border bg-card px-3 text-[12px] font-medium text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground disabled:opacity-50"
            >
              {exporting ? <LoadingIcon className="h-3.5 w-3.5" /> : <Download className="h-3.5 w-3.5" />}
              {exporting ? 'Exporting' : 'Export'}
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={clearSearch}
            className="flex h-9 items-center gap-1.5 rounded-md border border-border bg-card px-3 text-[12px] font-medium text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
            Clear search
          </button>
        )}
      </div>

      {exportJob && (
        <DurableJobNotice
          job={exportJob}
          detail="A complete prevalence export runs as a background job bound to your retention window."
        />
      )}
      {exportError && (
        <div className="mx-4 mt-4 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-[12px] text-destructive">
          {exportError}
        </div>
      )}

      {/* NAN-871: lookup / bulk modes replace the browse experience entirely
          (heatmap + KPI table). `Clear search` returns to browse. */}
      {mode === 'lookup' && singleDetected && (
        <ArtifactLookupCard
          detected={singleDetected}
          lookupData={lookupData?.data?.[0]}
          lookupLoading={lookupLoading}
          timeWindow={timeWindow}
          onDrilldown={handleDrilldown}
        />
      )}

      {mode === 'bulk' && (
        <BulkLookupTable
          detected={bulkDetected}
          lookupData={lookupData?.data ?? []}
          lookupLoading={lookupLoading}
          onSelectRow={(artifact) => setSearchQuery(artifact)}
        />
      )}

      {/* Heatmap card */}
      {mode === 'browse' && heatmapArtifacts.length > 0 && (
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
      {mode === 'browse' && (
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
              onClick={nextPage}
              disabled={!data?.has_more || loading}
              aria-label="Next page"
              className="flex h-6 w-6 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-foreground/5 hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
            >
              <ChevronRight className="h-3 w-3" />
            </button>
          </div>
        </div>

        {snapshotStatus && artifacts.length > 0 && (
          <p role="status" className="border-b border-border px-3 py-2 font-mono text-[11px] text-muted-foreground">
            {snapshotStatus}
          </p>
        )}
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
            <LoadingIcon className="mx-auto mb-2 h-5 w-5" />
            <p>Loading artifacts…</p>
          </div>
        ) : artifacts.length === 0 ? (
          <div className="px-4 py-12 text-center text-[12px] text-muted-foreground">
            <Search className="mx-auto mb-2 h-5 w-5 opacity-50" />
            <p>{snapshotStatus ?? (data?.availability?.available === false ? 'Prevalence not computed yet' : 'No artifacts found')}</p>
            {data?.availability?.available === false && data.availability.detail && (
              <p className="mt-1 text-muted-foreground/60">{data.availability.detail}</p>
            )}
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
      )}
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
  // NAN-849: single-line scannable subtitle. Built from the bulk `context`
  // shipped with each list row — no per-row fetch.
  const subtitle = useMemo(() => buildSubtitle(artifact), [artifact]);
  const threatIntel = useEnrichEnabled();
  const enrichType = threatIntel ? enrichTypeFor(artifact.artifact_type, artifact.artifact) : null;

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
      <div className="flex min-w-0 flex-col justify-center gap-0.5 px-2 py-1.5">
        <div className="flex min-w-0 items-center gap-2">
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
          {enrichType && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                openEnrich({ artifact: artifact.artifact, artifactType: enrichType, origin: 'analyst' });
              }}
              aria-label="Enrich"
              title="Enrich with threat intel"
              className="rounded-sm opacity-0 transition-opacity focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary group-hover:opacity-100"
            >
              <ScanSearch className="h-3 w-3 text-muted-foreground hover:text-foreground" />
            </button>
          )}
        </div>
        {subtitle && (
          <div className="truncate text-[10.5px] text-muted-foreground/80" title={subtitle}>
            {subtitle}
          </div>
        )}
      </div>
      <div className="px-2 py-2">
        <TypePill artifactType={artifact.artifact_type} />
      </div>
      <div className="px-2 py-2 text-right font-mono tabular-nums text-foreground">
        {artifact.host_count.toLocaleString()}{artifact.host_count_saturated ? '+' : ''}
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

export function ExpandedArtifactDetail({
  artifact,
  timeWindow,
  onDrilldown,
}: {
  artifact: ArtifactExplorerItem;
  timeWindow: string;
  onDrilldown: (artifact: ArtifactExplorerItem) => void;
}) {
  const { data: detail, loading, error, refetch } = useArtifactDetail(artifact.artifact, timeWindow);
  // On-demand threat-intel lookup (hosted-shared tenants with agent enrichment).
  const threatIntel = useEnrichEnabled();
  const enrichType = threatIntel ? enrichTypeFor(artifact.artifact_type, artifact.artifact) : null;
  // NAN-3210: lean (enterprise-shared) tenants build artifact detail in
  // product state on demand. A miss answers 200 with empty facets and
  // `availability: {available: false, reason: 'warming'}`; rendering that as
  // "no data" made every first expand look empty. Poll while it warms.
  const availability = detail?.availability;
  const warming = availability?.available === false && availability.reason === 'warming';
  // NAN-3766: a common artifact first answers with its newest slice
  // (`coverage.refining`) while the publisher keeps counting; poll for the
  // wider answer on the same bounded schedule, keeping the partial facets.
  const coverage = detail?.coverage;
  const refining = coverage?.refining === true;
  const [polls, setPolls] = useState(0);
  useEffect(() => {
    setPolls(0);
  }, [artifact.artifact, timeWindow]);
  useEffect(() => {
    if (!(warming || refining) || loading || polls >= DETAIL_WARMING_MAX_POLLS) return;
    const timer = setTimeout(() => {
      setPolls((n) => n + 1);
      void refetch();
    }, detailWarmingDelay(polls));
    return () => clearTimeout(timer);
  }, [warming, refining, loading, polls, refetch]);

  if (warming) {
    const gaveUp = polls >= DETAIL_WARMING_MAX_POLLS;
    return (
      <div className="px-2 py-4" role="status">
        <div className="mb-2 font-mono text-[11px] text-muted-foreground">
          {artifact.total_occurrences.toLocaleString()} occurrences · {artifact.host_count_saturated ? '≥' : ''}{artifact.host_count.toLocaleString()} hosts · first {artifact.first_seen} · last {artifact.last_seen}
        </div>
        {!gaveUp && <LoadingIcon className="h-4 w-4 text-primary" />}
        <span className="ml-2 font-mono text-[11px] text-muted-foreground">
          {gaveUp ? 'Context is still being prepared; collapse and expand to retry' : 'Building detail…'}
        </span>
      </div>
    );
  }

  if (loading && !(refining && detail)) {
    return (
      <div className="flex items-center justify-center py-6">
        <LoadingIcon className="h-4 w-4 text-primary" />
        <span className="ml-2 font-mono text-[11px] text-muted-foreground">Loading context…</span>
      </div>
    );
  }

  if (availability?.available === false) {
    return (
      <div className="px-2 py-4 text-[11.5px] text-muted-foreground" role="alert">
        {availability.detail || 'Artifact context could not be read'}
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="px-2 py-4 text-[11.5px] text-muted-foreground">
        {error ? `Artifact context could not be read: ${error.message}` : 'No detail data available'}
      </div>
    );
  }

  const isHash = artifact.artifact_type.startsWith('hash');
  const isIp = artifact.artifact_type.startsWith('ip_address');
  const isDomain = artifact.artifact_type === 'domain' || artifact.artifact_type === 'subdomain';

  const cards: React.ReactNode[] = [];

  // NAN-849: for hashes, top_file_names is rendered FIRST because file_name
  // is the on-disk identity (`tiledatamodelsvc.dll`) — the truer answer for
  // "what is this thing?" than the running image, which is frequently a
  // wrapper like svchost.exe.
  if (isHash && detail.top_file_names && detail.top_file_names.length > 0) {
    cards.push(
      <FacetCard
        key="file-names"
        icon={FileText}
        title={`File names (${detail.top_file_names.length})`}
        rows={detail.top_file_names.map((f) => ({ name: f.file_name, value: f.count }))}
        mono
      />,
    );
  }

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

  // NAN-849: process context with wrapper-grouping. When the top process is
  // a wrapper (svchost et al.) we render the rows under a sub-heading like
  // "svchost.exe — split by command line" so that a hash with 10 svchost
  // entries reads as "one host, many services" rather than 10 identical-
  // looking rows.
  if (isHash && detail.processes && detail.processes.length > 0) {
    cards.push(
      <ProcessContextCard key="processes" processes={detail.processes} />,
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

  // NAN-849: threat-intel from configured IOC enrichments. When nothing is
  // returned we surface a small marketplace promotion below the cards
  // (rendered separately so it doesn't compete with real cards for layout).
  const hasThreatIntel = (detail.threat_intel?.length ?? 0) > 0;
  if (hasThreatIntel) {
    cards.push(
      <FacetCard
        key="threat-intel"
        icon={ShieldCheck}
        title={`Threat intelligence (${detail.threat_intel!.length})`}
        rows={detail.threat_intel!.map((t) => ({
          name: t.verdict,
          meta: t.source + (t.score != null ? ` · confidence ${t.score}` : ''),
          value: 1,
        }))}
        mono
      />,
    );
  }

  // NAN-849: marketplace promotion when no threat-intel verdict is
  // attached. The data-path is wired — empty just means "no feed matched"
  // or "no relevant feed is configured for this artifact_type". The link
  // to /marketplace is the actionable next step.
  const showMarketplacePromo = !hasThreatIntel && !enrichType;
  const coverageLabel = detailCoverageLabel(coverage, timeWindow);

  return (
    <div className="space-y-3">
      {cards.length === 0 ? (
        <p className="px-1 py-2 text-[11.5px] text-muted-foreground">
          {isPartialCoverage(coverage) ? 'No detail data found in the counted range' : 'No detail data found for this artifact'}
        </p>
      ) : (
        <div
          className="grid gap-3"
          style={{ gridTemplateColumns: `repeat(${Math.min(cards.length, 4)}, minmax(0, 1fr))` }}
        >
          {cards}
        </div>
      )}
      {coverageLabel && coverage && (
        <div
          className="px-1.5 font-mono text-[10.5px] text-muted-foreground"
          title={detailCoverageTitle(coverage, timeWindow)}
          data-testid="detail-coverage"
        >
          {coverageLabel}
        </div>
      )}
      {showMarketplacePromo && (
        <a
          href="/marketplace"
          className="flex items-center gap-2 rounded-md border border-dashed border-border bg-card/40 px-3 py-2 text-[11.5px] text-muted-foreground transition-colors hover:border-border hover:bg-card/70 hover:text-foreground"
        >
          <Store className="h-3.5 w-3.5 text-muted-foreground/80" />
          <span className="flex-1 truncate">
            Connect AbuseIPDB / GreyNoise / VirusTotal in the marketplace to see reputation for this artifact
          </span>
          <ChevronRight className="h-3 w-3 text-muted-foreground/70" />
        </a>
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
      {enrichType && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            openEnrich({ artifact: artifact.artifact, artifactType: enrichType, origin: 'analyst' });
          }}
          className="ml-1.5 inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-card px-2.5 text-[11.5px] text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground"
        >
          <ScanSearch className="h-3 w-3" />
          Enrich
        </button>
      )}
    </div>
  );
}

// ============================================================================
// NAN-849 — ProcessContextCard
//
// Renders the per-hash process rows. Wrapper rows (svchost.exe, rundll32.exe,
// powershell.exe, etc.) are grouped under a single sub-heading so that 10
// `svchost.exe` rows read as "one host, many services" rather than 10
// identical-looking entries. Non-wrapper rows render flat the same way they
// always have.
// ============================================================================

function ProcessContextCard({ processes }: { processes: ArtifactProcessEntry[] }) {
  // Group consecutive wrapper-process rows that share the same image name.
  // The CH query orders rows DESC by count, so wrappers cluster naturally
  // when present.
  type Group =
    | { kind: 'flat'; row: ArtifactProcessEntry }
    | { kind: 'wrapper'; processName: string; rows: ArtifactProcessEntry[] };

  const groups: Group[] = [];
  for (const p of processes) {
    if (p.is_wrapper) {
      const last = groups[groups.length - 1];
      if (last && last.kind === 'wrapper' && last.processName.toLowerCase() === p.process_name.toLowerCase()) {
        last.rows.push(p);
        continue;
      }
      groups.push({ kind: 'wrapper', processName: p.process_name, rows: [p] });
    } else {
      groups.push({ kind: 'flat', row: p });
    }
  }

  return (
    <div className="rounded-md border border-border bg-card">
      <div className="flex items-center gap-1.5 border-b border-border px-2.5 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/80">
        <Cpu className="h-[11px] w-[11px]" />
        Process context ({processes.length})
      </div>
      <div className="max-h-[260px] overflow-y-auto px-2 py-1.5">
        {groups.map((g, i) =>
          g.kind === 'flat' ? (
            <ProcessRow key={`flat-${i}`} row={g.row} />
          ) : (
            <div key={`wrap-${i}`} className="my-1 first:mt-0">
              <div className="px-1 pb-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground/60">
                {g.processName} — split by command line ({g.rows.length})
              </div>
              <div className="border-l border-border/60 pl-2">
                {g.rows.map((r, j) => (
                  <ProcessRow key={`wrap-${i}-${j}`} row={r} />
                ))}
              </div>
            </div>
          ),
        )}
      </div>
    </div>
  );
}

function ProcessRow({ row }: { row: ArtifactProcessEntry }) {
  return (
    <div className="flex items-center gap-2 py-0.5">
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-[11.5px] text-foreground">{row.process_name}</div>
        {row.command_line && (
          <div className="truncate font-mono text-[10px] text-muted-foreground/70" title={row.command_line}>
            {row.command_line}
          </div>
        )}
      </div>
      <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground">
        {row.count.toLocaleString()}
      </span>
    </div>
  );
}

// ============================================================================
// NAN-871 — Smart lookup mode (single artifact + bulk)
// ============================================================================

/** Adapt a `PrevalenceData` row from `/api/prevalence/bulk` into the
 * `ArtifactExplorerItem` shape `ExpandedArtifactDetail` / `handleDrilldown`
 * expect. Daily counts aren't fetched by the bulk endpoint — leave empty so
 * the heatmap-driven sparkline gracefully renders as zero activity. */
function explorerItemFromLookup(
  detected: DetectedArtifact,
  data: PrevalenceData | undefined,
): ArtifactExplorerItem {
  return {
    artifact: detected.value,
    artifact_type: data?.artifact_type ?? detected.kind,
    host_count: data?.host_count ?? 0,
    host_count_saturated: data?.host_count_saturated ?? false,
    total_occurrences: data?.total_occurrences ?? 0,
    first_seen: data?.first_seen ?? '',
    last_seen: data?.last_seen ?? '',
    is_rare: data?.is_rare ?? false,
    prevalence_score: data?.prevalence_score ?? 0,
    daily_counts: [],
    daily_start: '',
  };
}

function TypeChip({ kind }: { kind: PrevalenceArtifactType }) {
  return (
    <span className="inline-flex h-5 items-center rounded-sm border border-border bg-card/40 px-1.5 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
      {artifactKindLabel(kind)}
    </span>
  );
}

function ArtifactLookupCard({
  detected,
  lookupData,
  lookupLoading,
  timeWindow,
  onDrilldown,
}: {
  detected: DetectedArtifact;
  lookupData: PrevalenceData | undefined;
  lookupLoading: boolean;
  timeWindow: string;
  onDrilldown: (artifact: ArtifactExplorerItem) => void;
}) {
  const item = useMemo(
    () => explorerItemFromLookup(detected, lookupData),
    [detected, lookupData],
  );
  const seen = (lookupData?.host_count ?? 0) > 0;

  return (
    <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
      {/* Header strip */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <TypeChip kind={lookupData?.artifact_type ?? detected.kind} />
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[13px] text-foreground">{detected.value}</div>
          <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">
            {lookupLoading ? (
              'Looking up…'
            ) : seen ? (
              <>
                <span className="tabular-nums text-foreground">{(lookupData?.host_count ?? 0).toLocaleString()}{lookupData?.host_count_saturated ? '+' : ''}</span>{' '}
                {lookupData?.host_count === 1 ? 'host' : 'hosts'} ·{' '}
                <span className="tabular-nums text-foreground">{(lookupData?.total_occurrences ?? 0).toLocaleString()}</span>{' '}
                {lookupData?.total_occurrences === 1 ? 'event' : 'events'}
                {lookupData?.first_seen && (
                  <>
                    {' · first '}
                    <span className="text-foreground">{formatUTCCompact(lookupData.first_seen)}</span>
                  </>
                )}
                {lookupData?.last_seen && (
                  <>
                    {' · last '}
                    <span className="text-foreground">{formatRelativeCompact(lookupData.last_seen)}</span>
                  </>
                )}
              </>
            ) : (
              <span className="text-muted-foreground/70">Not seen in this environment</span>
            )}
          </div>
        </div>
        {lookupData?.is_rare && (
          <span className="inline-flex h-5 items-center gap-1 rounded-sm border border-red-400/30 bg-red-400/10 px-1.5 font-mono text-[10px] uppercase tracking-[0.08em] text-red-300">
            <AlertOctagon className="h-2.5 w-2.5" />
            Rare
          </span>
        )}
        <button
          type="button"
          onClick={() => onDrilldown(item)}
          disabled={!seen}
          className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-card px-2.5 text-[11.5px] text-muted-foreground transition-colors hover:bg-card/70 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-card disabled:hover:text-muted-foreground"
        >
          <Search className="h-3 w-3" />
          Search events
        </button>
      </div>

      {/* Body: facet grid when seen, empty state when not */}
      <div className="px-3 pt-3 pb-4">
        {lookupLoading ? (
          <div className="flex items-center justify-center py-6">
            <LoadingIcon className="h-4 w-4 text-primary" />
            <span className="ml-2 font-mono text-[11px] text-muted-foreground">Looking up artifact…</span>
          </div>
        ) : seen ? (
          <ExpandedArtifactDetail
            artifact={item}
            timeWindow={timeWindow}
            onDrilldown={onDrilldown}
          />
        ) : (
          <div className="px-4 py-10 text-center text-[12px] text-muted-foreground">
            <Search className="mx-auto mb-2 h-5 w-5 opacity-50" />
            <p>Not seen in this environment</p>
            <p className="mt-1 text-[11px] text-muted-foreground/70">
              No prevalence record exists for this artifact in the configured retention window.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function BulkLookupTable({
  detected,
  lookupData,
  lookupLoading,
  onSelectRow,
}: {
  detected: DetectedArtifact[];
  lookupData: PrevalenceData[];
  lookupLoading: boolean;
  onSelectRow: (artifact: string) => void;
}) {
  // Index the API response by artifact value so we can pair each row in the
  // pasted list with its prevalence stats. The bulk endpoint may return rows
  // in a different order than the input — keying preserves the user's order.
  const byArtifact = useMemo(() => {
    const m = new Map<string, PrevalenceData>();
    for (const row of lookupData) m.set(row.artifact.toLowerCase(), row);
    return m;
  }, [lookupData]);

  return (
    <div className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <Eyebrow icon={Hash}>
          Bulk lookup ·{' '}
          <span className="tabular-nums text-foreground">{detected.length.toLocaleString()}</span>{' '}
          artifacts
        </Eyebrow>
      </div>

      {/* Column header strip — mirrors the rare-artifacts table grid */}
      <div
        className="grid items-center border-b border-border bg-card/40 font-mono text-[9.5px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/80"
        style={{ gridTemplateColumns: 'minmax(0,1fr) 110px 80px 80px 140px 140px 80px' }}
      >
        <div className="px-3 py-2">Artifact</div>
        <div className="px-2 py-2">Type</div>
        <div className="px-2 py-2 text-right">Hosts</div>
        <div className="px-2 py-2 text-right">Events</div>
        <div className="px-2 py-2">First seen</div>
        <div className="px-2 py-2">Last seen</div>
        <div className="px-2 py-2 text-right">Rare</div>
      </div>

      {lookupLoading ? (
        <div className="px-4 py-12 text-center text-[12px] text-muted-foreground">
          <LoadingIcon className="mx-auto mb-2 h-5 w-5" />
          <p>Looking up artifacts…</p>
        </div>
      ) : (
        <div className="divide-y divide-border">
          {detected.map((d, i) => {
            const row = byArtifact.get(d.value.toLowerCase());
            const seen = (row?.host_count ?? 0) > 0;
            return (
              <button
                key={`${d.value}-${i}`}
                type="button"
                onClick={() => onSelectRow(d.value)}
                className="grid w-full items-center text-left transition-colors hover:bg-card/40"
                style={{ gridTemplateColumns: 'minmax(0,1fr) 110px 80px 80px 140px 140px 80px' }}
              >
                <div className="truncate px-3 py-2 font-mono text-[12px] text-foreground" title={d.value}>
                  {d.value}
                </div>
                <div className="px-2 py-2">
                  <TypeChip kind={row?.artifact_type ?? d.kind} />
                </div>
                <div className="px-2 py-2 text-right font-mono text-[11.5px] tabular-nums text-foreground">
                  {seen ? <>{(row?.host_count ?? 0).toLocaleString()}{row?.host_count_saturated ? '+' : ''}</> : <span className="text-muted-foreground/60">—</span>}
                </div>
                <div className="px-2 py-2 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">
                  {seen ? (row?.total_occurrences ?? 0).toLocaleString() : <span className="text-muted-foreground/60">—</span>}
                </div>
                <div className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                  {row?.first_seen ? formatUTCCompact(row.first_seen) : <span className="text-muted-foreground/60">—</span>}
                </div>
                <div className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                  {row?.last_seen ? formatRelativeCompact(row.last_seen) : <span className="text-muted-foreground/60">—</span>}
                </div>
                <div className="px-2 py-2 text-right">
                  {row?.is_rare ? (
                    <span className="inline-flex h-5 items-center gap-1 rounded-sm border border-red-400/30 bg-red-400/10 px-1.5 font-mono text-[10px] uppercase tracking-[0.08em] text-red-300">
                      <AlertOctagon className="h-2.5 w-2.5" />
                      Rare
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] text-muted-foreground/60">—</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
