// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — redesigned /rules dashboard.
//
// Port of design-ref/rules.html + shadcn/rules-*.jsx into the real app against
// the live detection API. The old visuals lived at Detections.tsx (kept in-tree
// under a legacy export until a sunset PR).

import { useCallback, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Download, Plus, RefreshCw, Search as SearchIcon, Database, ShieldAlert, History } from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  useDetections,
  useDetectionStats,
  useTodayCounts,
  useAlertCounts,
  useAlertVelocity,
  useFleetHealth,
} from '@/hooks/use-api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { DailyStat, DetectionRule } from '@/lib/api/types';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';

import { BANDS, bandOf, buildRuleView, primaryTactic, type BandId, type SeverityKey } from '@/components/rules/helpers';
import { RulesOverview } from '@/components/rules/RulesOverview';
import { SegmentedSev, FilterSelect, TacticChips } from '@/components/rules/RulesToolbarChips';
import { RuleRow, Chk } from '@/components/rules/RuleRow';
import { BandHeader } from '@/components/rules/BandHeader';
import { BulkActionBar } from '@/components/rules/BulkActionBar';

// Activity strip — 28 days of match counts from the per-rule stats endpoint.
function buildActivity(stats: DailyStat[] | undefined, todayCount: number, days = 28): number[] {
  const byDate = new Map(stats?.map((s) => [s.date, s.match_count]) || []);
  const today = new Date();
  const todayStr = today.toISOString().split('T')[0];
  const out: number[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const iso = d.toISOString().split('T')[0];
    out.push(iso === todayStr ? todayCount : byDate.get(iso) || 0);
  }
  return out;
}

type SevFilter = 'all' | SeverityKey;
type ModeFilter = 'all' | 'scheduled' | 'real-time';
type StatusFilter = 'all' | 'live' | 'staging' | 'disabled';

export function Rules() {
  useDocumentTitle('Rules');
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();

  const canCreate = hasPermission('detections:create');

  const { data: apiRules, loading, refetch } = useDetections();
  const { data: stats } = useDetectionStats(28);
  const { data: todayCounts, refetch: refetchTodayCounts } = useTodayCounts();
  // NAN-1541: the rules page is a detection surface — scope alert counts/velocity to
  // security detections so observability monitor alerts don't leak into these numbers.
  const { data: alertCounts } = useAlertCounts(['detection']);
  const { data: alertVelocity } = useAlertVelocity(24, ['detection']);
  const { data: fleetHealth } = useFleetHealth();

  const [sev, setSev] = useState<SevFilter>('all');
  const [mode, setMode] = useState<ModeFilter>('all');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [tactic, setTactic] = useState<string>('All tactics');
  const [query, setQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [openBands, setOpenBands] = useState<Record<BandId, boolean>>(() => {
    const m: Record<string, boolean> = {};
    BANDS.forEach((b) => { m[b.id] = b.defaultOpen; });
    return m as Record<BandId, boolean>;
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  // Null = bulk delete (uses `selected`). A specific id = single-row delete.
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const rules: DetectionRule[] = useMemo(() => apiRules || [], [apiRules]);

  // Freeze `now` once per render so every bandOf() call within this pass agrees
  // on the firing/active/silent boundaries — avoids a 1ms race where a rule
  // classified as `firing` in the overview strip reads as `active` in the row.
  const now = useMemo(() => new Date(), [rules]);

  // Build view models once — they pair the raw rule with today-count + 28d activity.
  const views = useMemo(() => {
    return rules.map((r) => {
      const t = todayCounts?.[r.id] ?? 0;
      const activity = buildActivity(stats?.[r.id], t);
      return buildRuleView(r, t, activity);
    });
  }, [rules, todayCounts, stats]);

  // Filter pipeline — applied before band grouping.
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return views.filter((v) => {
      if (sev !== 'all' && v.severity !== sev) return false;
      if (mode !== 'all' && v.mode !== mode) return false;
      if (status !== 'all') {
        if (status === 'live' && !(v.detectionStatus === 'live' || v.detectionStatus === 'alerting')) return false;
        if (status === 'staging' && v.detectionStatus !== 'staging') return false;
        if (status === 'disabled' && v.detectionStatus !== 'paused') return false;
      }
      if (tactic !== 'All tactics') {
        const t = primaryTactic(v.raw);
        if (t !== tactic) return false;
      }
      if (needle && !v.name.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [views, sev, mode, status, tactic, query]);

  const grouped = useMemo(() => {
    const g: Record<BandId, typeof filtered> = {
      firing: [], active: [], silent: [], staging: [], disabled: [],
    };
    filtered.forEach((v) => { g[bandOf(v.raw, now)].push(v); });
    return g;
  }, [filtered, now]);

  const silentCount = useMemo(() => rules.filter((r) => bandOf(r, now) === 'silent').length, [rules, now]);

  const toggleSelect = useCallback((id: string) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((v) => v.id)));
    }
  }, [filtered, selected.size]);

  const refresh = () => {
    refetch();
    refetchTodayCounts();
  };

  const bulkSetMode = async (targetMode: string, label: string) => {
    if (selected.size === 0) return;
    setBulkUpdating(true);
    try {
      const result = await api.bulkUpdateRules({
        rule_ids: Array.from(selected),
        mode: targetMode,
      });
      const parts: string[] = [];
      if (result.updated > 0) parts.push(`${result.updated} ${label}`);
      if (result.skipped > 0) parts.push(`${result.skipped} skipped`);
      if (result.failed.length > 0) parts.push(`${result.failed.length} failed`);
      toast({
        title: 'Bulk update complete',
        description: parts.join(' · '),
        variant: result.failed.length > 0 ? 'destructive' : 'default',
      });
      setSelected(new Set());
      refetch();
    } catch {
      toast({ title: 'Error', description: 'Failed to update rules.', variant: 'destructive' });
    } finally {
      setBulkUpdating(false);
    }
  };

  const confirmDelete = async () => {
    const ids = deleteTarget ? [deleteTarget] : Array.from(selected);
    if (ids.length === 0) return;
    setBulkUpdating(true);
    try {
      const results = await Promise.allSettled(ids.map((id) => api.deleteDetection(id)));
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.length - ok;
      const parts: string[] = [];
      if (ok > 0) parts.push(`${ok} removed`);
      if (failed > 0) parts.push(`${failed} failed`);
      toast({
        title: failed > 0 ? 'Delete partial' : 'Deleted',
        description: parts.join(' · '),
        variant: failed > 0 ? 'destructive' : 'default',
      });
      if (!deleteTarget) setSelected(new Set());
      refetch();
    } catch {
      toast({ title: 'Error', description: 'Failed to delete rules.', variant: 'destructive' });
    } finally {
      setBulkUpdating(false);
      setDeleteConfirmOpen(false);
      setDeleteTarget(null);
    }
  };

  // Per-row Set mode handler — reuses bulkUpdateRules under the hood for
  // consistent audit + validation behaviour.
  const setRuleMode = async (id: string, targetMode: string) => {
    try {
      await api.bulkUpdateRules({ rule_ids: [id], mode: targetMode });
      toast({ title: 'Rule updated', description: `Mode set to ${targetMode}.` });
      refetch();
    } catch {
      toast({ title: 'Error', description: 'Failed to update rule.', variant: 'destructive' });
    }
  };

  const requestDelete = (id: string) => {
    setDeleteTarget(id);
    setDeleteConfirmOpen(true);
  };

  const firingCount = rules.filter((r) => bandOf(r, now) === 'firing').length;
  const needReview = silentCount;

  return (
    <div
      className="relative flex flex-col gap-3"
      style={{ containerType: 'inline-size' }}
    >
      {/* Page header */}
      <div className="flex items-end justify-between gap-2">
        <div className="min-w-0">
          <h1 className="text-[20px] font-semibold text-foreground tracking-[-0.01em] leading-none">
            Detection Rules
          </h1>
          <p className="text-[12px] text-muted-foreground mt-1.5 leading-none truncate">
            {rules.length} total
            <span className="text-muted-foreground/60 mx-1.5">·</span>
            <span className="text-foreground">{firingCount} firing now</span>
            <span className="text-muted-foreground/60 mx-1.5">·</span>
            <span className="text-warning">{needReview} need review</span>
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 @max-[900px]:hidden"
            title="Import (not yet wired)"
          >
            <Download className="w-3.5 h-3.5" strokeWidth={2} />
            Import
          </button>
          <Link
            to="/rules/repositories"
            className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 @max-[900px]:hidden"
          >
            <Database className="w-3.5 h-3.5" strokeWidth={2} />
            {/* NAN-957: label matches destination page title "Rule repositories". */}
            Repositories
          </Link>
          {canCreate && (
            <Link
              to="/rules/retro-hunt/new"
              className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 @max-[900px]:hidden"
              title="Auto retro-hunt: match newly-published threat intel against historical logs"
            >
              <History className="w-3.5 h-3.5" strokeWidth={2} />
              Retro-hunt
            </Link>
          )}
          {canCreate && (
            <Link
              to="/rules/editor/new"
              className="h-8 px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" strokeWidth={2.5} />
              New rule
            </Link>
          )}
        </div>
      </div>

      {/* Overview strip */}
      <RulesOverview
        rules={rules}
        silentCount={silentCount}
        alerts24h={alertCounts?.total ?? 0}
        velocity={alertVelocity}
        fleetHealth={fleetHealth}
        onReviewSilent={() => navigate('/rules/tuning?tab=silent')}
      />

      {/* Tactic chips */}
      <TacticChips value={tactic} onChange={setTactic} />

      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-[300px]">
          <SearchIcon className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search rules…"
            className="h-8 w-full pl-8 pr-3 rounded-md border border-border bg-transparent text-[11.5px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/60"
          />
          <kbd className="absolute right-2 top-1/2 -translate-y-1/2 font-mono text-[9.5px] text-muted-foreground/60 border border-border px-1 rounded @max-[820px]:hidden">
            /
          </kbd>
        </div>
        <SegmentedSev value={sev} onChange={setSev} />
        <div className="flex items-center gap-2 @max-[900px]:hidden">
          <FilterSelect<ModeFilter>
            label="Mode:"
            value={mode}
            onChange={setMode}
            options={[
              { id: 'all', label: 'All' },
              { id: 'scheduled', label: 'Scheduled' },
              { id: 'real-time', label: 'Real-time' },
            ]}
          />
          <FilterSelect<StatusFilter>
            label="Status:"
            value={status}
            onChange={setStatus}
            options={[
              { id: 'all', label: 'All' },
              { id: 'live', label: 'Live' },
              { id: 'staging', label: 'Staging' },
              { id: 'disabled', label: 'Disabled' },
            ]}
          />
        </div>
        <div className="flex-1 @max-[900px]:hidden" />
        <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums ml-auto">
          {filtered.length} of {rules.length}
        </span>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="h-8 w-8 rounded-md border border-border text-muted-foreground hover:bg-foreground/5 hover:text-foreground flex items-center justify-center shrink-0 disabled:opacity-50"
          title="Refresh"
          aria-label="Refresh"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} strokeWidth={2} />
        </button>
      </div>

      {/* Sectioned table */}
      <div
        className="rounded-lg border border-border bg-card overflow-hidden"
        style={{ containerType: 'inline-size' }}
      >
        <table className="w-full border-collapse" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: '3px' }} />
            <col style={{ width: '28px' }} />
            <col style={{ width: '22px' }} />
            <col style={{ width: '70px' }} />
            <col />
            <col className="@max-[820px]:hidden" style={{ width: '180px' }} />
            <col className="@max-[1100px]:hidden" style={{ width: '90px' }} />
            <col style={{ width: '92px' }} />
            <col className="@max-[960px]:hidden" style={{ width: '92px' }} />
            <col style={{ width: '82px' }} />
            <col style={{ width: '36px' }} />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-card">
            <tr className="border-b border-border">
              <th className="p-0" />
              <th className="w-[28px] pl-1 pr-0 h-8 align-middle">
                <Chk
                  checked={filtered.length > 0 && selected.size === filtered.length}
                  indeterminate={selected.size > 0 && selected.size < filtered.length}
                  onChange={toggleSelectAll}
                  ariaLabel="Select all rules"
                />
              </th>
              <th className="h-8" />
              <th className="h-8 px-2 text-right font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                24h
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Rule
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold @max-[820px]:hidden">
                Last 28 days
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold @max-[1100px]:hidden">
                Last match
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Severity
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold @max-[960px]:hidden">
                Mode
              </th>
              <th className="h-8 px-0 text-left font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Status
              </th>
              <th className="h-8" />
            </tr>
          </thead>
          <tbody>
            {BANDS.map((band) => {
              const items = grouped[band.id];
              if (items.length === 0) return null;
              const open = openBands[band.id];
              return (
                <BandGroup
                  key={band.id}
                  band={band}
                  items={items}
                  open={open}
                  onToggle={() => setOpenBands((o) => ({ ...o, [band.id]: !o[band.id] }))}
                  expandedId={expandedId}
                  selected={selected}
                  onToggleExpand={(id) => setExpandedId((v) => (v === id ? null : id))}
                  onToggleSelect={toggleSelect}
                  onSetMode={setRuleMode}
                  onDelete={requestDelete}
                />
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={99} className="py-10">
                  <div className="flex flex-col items-center justify-center gap-1.5 text-center">
                    <ShieldAlert className="w-6 h-6 text-muted-foreground/60" strokeWidth={1.5} />
                    <div className="text-[12px] text-foreground font-medium">
                      No rules match your filters
                    </div>
                    <div className="text-[10.5px] text-muted-foreground">
                      Try a different severity, mode, tactic — or clear your search.
                    </div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer note */}
      <div className="h-6 flex items-center font-mono text-[10px] text-muted-foreground tabular-nums">
        Showing {filtered.length} of {rules.length} rules
        <span className="flex-1" />
        <button
          type="button"
          onClick={() => navigate('/rules/editor/new')}
          className="text-muted-foreground hover:text-foreground disabled:opacity-50"
          disabled={!canCreate}
        >
          ⌘K search · C create new
        </button>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <BulkActionBar
          count={selected.size}
          disabled={bulkUpdating}
          onEnable={() => bulkSetMode('live', 'enabled')}
          onDisable={() => bulkSetMode('paused', 'disabled')}
          onDelete={() => setDeleteConfirmOpen(true)}
          onClear={() => setSelected(new Set())}
        />
      )}

      {(() => {
        const count = deleteTarget ? 1 : selected.size;
        const plural = count === 1 ? '' : 's';
        return (
          <ConfirmDialog
            open={deleteConfirmOpen}
            onOpenChange={(v) => {
              setDeleteConfirmOpen(v);
              if (!v) setDeleteTarget(null);
            }}
            variant="danger"
            title={`Delete ${count} rule${plural}?`}
            description={
              <>
                This permanently removes the selected detection rule{plural}, their
                configuration, and their materialized-view bindings. Historical signal logs
                stay in ClickHouse but future matches stop immediately. This cannot be undone.
              </>
            }
            confirmLabel={`Delete ${count} rule${plural}`}
            loading={bulkUpdating}
            onConfirm={confirmDelete}
          />
        );
      })()}
    </div>
  );
}

// Extracted so the main table body stays flat and JSX-simple.
function BandGroup({
  band,
  items,
  open,
  onToggle,
  expandedId,
  selected,
  onToggleExpand,
  onToggleSelect,
  onSetMode,
  onDelete,
}: {
  band: (typeof BANDS)[number];
  items: ReturnType<typeof buildRuleView>[];
  open: boolean;
  onToggle: () => void;
  expandedId: string | null;
  selected: Set<string>;
  onToggleExpand: (id: string) => void;
  onToggleSelect: (id: string) => void;
  onSetMode: (id: string, mode: 'staging' | 'live' | 'alerting' | 'paused') => void;
  onDelete: (id: string) => void;
}) {
  return (
    <>
      <BandHeader band={band} count={items.length} open={open} onToggle={onToggle} />
      {open &&
        items.map((rule) => (
          <RuleRow
            key={rule.id}
            rule={rule}
            expanded={expandedId === rule.id}
            onToggle={() => onToggleExpand(rule.id)}
            selected={selected.has(rule.id)}
            onSelect={() => onToggleSelect(rule.id)}
            onSetMode={onSetMode}
            onDelete={onDelete}
          />
        ))}
    </>
  );
}

export default Rules;
