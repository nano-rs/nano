// SPDX-License-Identifier: AGPL-3.0-or-later

// SlosTab (NAN-1536) — service-level objectives with error-budget cards.
//
// Ported from the design handoff (obs-alerts.jsx · SLOView + obs-charts2.jsx ·
// BudgetBar) into nano's real app, wired to the live SLO backend:
//   - api.observability.listSlos()  — cards + computed budget/burn/status
//   - api.observability.createSlo() / updateSlo() / deleteSlo() — CRUD editor
//
// The backend returns `current`/`budget_remaining_pct`/`burn_rate`/`status`
// already computed from otel_spans over the rolling window; this surface only
// presents them. Each SLO's service links into the Service detail drill-in.

import { useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, AlertTriangle, Loader2 } from 'lucide-react';

import { api } from '@/lib/api';
import type { Slo, SloInput, SloStatus } from '@/lib/api/observability';
import { ApiClientError } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { BudgetBar } from '@/components/observability/charts';
import { SloEditorDialog } from '@/components/observability/SloEditorDialog';
import { cn } from '@/lib/utils';
import type { ObservabilityTabProps } from '../types';

// Status → tone classes (mirrors the design's HEALTH map onto nano tokens).
const STATUS_TONE: Record<SloStatus, { dot: string; text: string; border: string; bg: string; label: string }> = {
  ok: { dot: 'bg-good', text: 'text-good', border: 'border-border', bg: 'bg-good/10', label: 'Healthy' },
  at_risk: { dot: 'bg-warn', text: 'text-warn', border: 'border-warn/30', bg: 'bg-warn/10', label: 'Burning' },
  breaching: { dot: 'bg-danger', text: 'text-danger', border: 'border-danger/30', bg: 'bg-danger/10', label: 'Breaching' },
};

const fmtPct = (v: number, digits = 2): string => `${v.toFixed(digits)}%`;

export function SlosTab({ onOpenService }: ObservabilityTabProps) {
  const [slos, setSlos] = useState<Slo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Slo | null>(null);
  const [deleting, setDeleting] = useState<Slo | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.observability.listSlos();
      setSlos(res.slos);
    } catch (e) {
      setError(e instanceof ApiClientError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleSubmit = useCallback(
    async (input: SloInput) => {
      if (editing != null) {
        await api.observability.updateSlo(editing.id, input);
      } else {
        await api.observability.createSlo(input);
      }
      await load();
    },
    [editing, load],
  );

  const handleDelete = useCallback(async () => {
    if (deleting == null) return;
    setDeleteBusy(true);
    try {
      await api.observability.deleteSlo(deleting.id);
      setDeleting(null);
      await load();
    } finally {
      setDeleteBusy(false);
    }
  }, [deleting, load]);

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (slo: Slo) => {
    setEditing(slo);
    setEditorOpen(true);
  };

  // Sort by budget consumed (most consumed first), matching the design.
  const sorted = [...slos].sort(
    (a, b) => a.budget_remaining_pct - b.budget_remaining_pct,
  );
  const burning = slos.filter((s) => s.status !== 'ok').length;

  return (
    <div className="flex flex-col gap-3.5">
      {/* header / meta row */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">
          {slos.length} {slos.length === 1 ? 'SLO' : 'SLOs'}
        </span>
        {burning > 0 && (
          <span className="font-mono text-[11px] text-warn">{burning} burning budget</span>
        )}
        <span className="text-[11px] text-fg-4">· sorted by budget consumed</span>
        <div className="flex-1" />
        <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={openCreate}>
          <Plus className="h-[13px] w-[13px]" />
          New SLO
        </Button>
      </div>

      {error != null && (
        <div className="flex items-center gap-2 rounded-lg border border-danger/30 bg-danger/[0.06] px-3.5 py-2.5 text-[12px] text-danger">
          <AlertTriangle className="h-[14px] w-[14px] shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => void load()} className="text-[11px] underline hover:no-underline">
            retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-12 text-[12px] text-fg-3">
          <Loader2 className="h-[14px] w-[14px] animate-spin" />
          Loading SLOs…
        </div>
      ) : sorted.length === 0 && error == null ? (
        <div className="flex flex-col items-center gap-3 py-12 text-center">
          <span className="text-[12.5px] text-fg-3">No SLOs defined yet.</span>
          <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={openCreate}>
            <Plus className="h-[13px] w-[13px] " />
            Define your first SLO
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
          {sorted.map((s) => {
            const tone = STATUS_TONE[s.status];
            // budget_remaining_pct: 100 = full budget, can go negative.
            const consumedPct = 100 - s.budget_remaining_pct;
            const remaining = Math.max(0, s.budget_remaining_pct);
            const targetPct = s.target * 100;
            const currentPct = s.current * 100;
            const metPlan = s.current >= s.target;
            return (
              <div
                key={s.id}
                className={cn(
                  'flex flex-col gap-3 rounded-lg border bg-card p-3.5',
                  tone.border,
                )}
              >
                {/* title row */}
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-medium leading-tight text-fg">
                      {s.name}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 font-mono text-[10.5px] text-fg-4">
                      <button
                        onClick={() => onOpenService(s.service)}
                        className="truncate text-fg-3 hover:text-brand"
                        title={`View ${s.service} detail`}
                      >
                        {s.service}
                      </button>
                      <span>·</span>
                      <span>target {fmtPct(targetPct, 2)}</span>
                      <span>·</span>
                      <span>{s.window_days}d</span>
                      {s.sli_kind === 'latency' && s.latency_threshold_ms != null && (
                        <>
                          <span>·</span>
                          <span>&lt;{s.latency_threshold_ms}ms</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span
                    className={cn(
                      'inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[9.5px] font-medium',
                      tone.border,
                      tone.bg,
                      tone.text,
                    )}
                  >
                    <span className={cn('h-1.5 w-1.5 rounded-full', tone.dot)} />
                    {tone.label}
                  </span>
                </div>

                {/* metrics */}
                <div className="grid grid-cols-3 gap-2">
                  <Metric
                    label="current"
                    value={fmtPct(currentPct, 2)}
                    cls={metPlan ? 'text-good' : 'text-danger'}
                  />
                  <Metric
                    label="budget left"
                    value={fmtPct(remaining, 0)}
                    cls={
                      s.budget_remaining_pct <= 0
                        ? 'text-danger'
                        : s.budget_remaining_pct < 25
                          ? 'text-warn'
                          : 'text-fg'
                    }
                  />
                  <Metric
                    label="burn rate"
                    value={`${s.burn_rate.toFixed(1)}×`}
                    cls={
                      s.burn_rate >= 5 ? 'text-danger' : s.burn_rate >= 2 ? 'text-warn' : 'text-fg-2'
                    }
                  />
                </div>

                {/* error budget bar */}
                <div>
                  <div className="mb-1 flex items-center justify-between font-mono text-[9.5px] text-fg-4">
                    <span>error budget consumed</span>
                    <span
                      className={cn(
                        consumedPct >= 100
                          ? 'text-danger'
                          : consumedPct >= 75
                            ? 'text-warn'
                            : 'text-fg-3',
                      )}
                    >
                      {fmtPct(Math.max(0, consumedPct), 0)}
                    </span>
                  </div>
                  <BudgetBar consumedPct={consumedPct} />
                </div>

                {/* actions */}
                <div className="flex items-center justify-end gap-1 border-t border-border/50 pt-2">
                  <button
                    onClick={() => openEdit(s)}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[10.5px] text-fg-3 hover:bg-fg/5 hover:text-fg"
                  >
                    <Pencil className="h-[11px] w-[11px]" />
                    Edit
                  </button>
                  <button
                    onClick={() => setDeleting(s)}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[10.5px] text-fg-3 hover:bg-danger/10 hover:text-danger"
                  >
                    <Trash2 className="h-[11px] w-[11px]" />
                    Delete
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <SloEditorDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        slo={editing}
        onSubmit={handleSubmit}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(o) => {
          if (!o) setDeleting(null);
        }}
        variant="danger"
        title="Delete SLO"
        description={
          deleting != null ? (
            <>
              Delete{' '}
              <span className="font-medium text-foreground">{deleting.name}</span> for{' '}
              <span className="font-mono text-foreground">{deleting.service}</span>? This removes
              the objective definition; span data is unaffected.
            </>
          ) : null
        }
        confirmLabel="Delete"
        loading={deleteBusy}
        loadingLabel="Deleting…"
        confirmIcon={<Trash2 className="h-[11px] w-[11px]" />}
        onConfirm={handleDelete}
      />
    </div>
  );
}

function Metric({ label, value, cls }: { label: string; value: string; cls: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[9px] uppercase tracking-wider text-fg-4">{label}</span>
      <span className={cn('mt-0.5 font-mono text-[15px] leading-none tabular-nums', cls)}>
        {value}
      </span>
    </div>
  );
}

export default SlosTab;
