// SPDX-License-Identifier: AGPL-3.0-or-later

// SyntheticsTab (NAN-1538) — synthetic HTTP checks with uptime + latency.
//
// Ported from the design handoff (obs-rum.jsx · SyntheticsView + obs-charts2.jsx
// · UptimeBar) into nano's real app, wired to the live synthetics backend:
//   - api.observability.listSynthetics()  — checks + computed uptime/p50/history
//   - api.observability.createSynthetic() / updateSynthetic() / deleteSynthetic()
//
// The backend (PG defs + ClickHouse results) returns each check's `uptime_pct`,
// `p50_latency_ms`, and last-90-run `history` already merged on read; this
// surface presents them. Status is derived from uptime (>=99.9 up · >=99
// degraded · else down). The enabled toggle pauses/resumes probing via
// updateSynthetic.

import { useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, AlertTriangle, Loader2, Radar } from 'lucide-react';

import { api, ApiClientError } from '@/lib/api';
import type { SyntheticCheck, SyntheticCheckInput } from '@/lib/api/observability';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { UptimeBar } from '@/components/observability/UptimeBar';
import { SyntheticEditorDialog } from '@/components/observability/SyntheticEditorDialog';
import { cn } from '@/lib/utils';
import type { ObservabilityTabProps } from '../types';

type SynStatus = 'up' | 'degraded' | 'down' | 'nodata';

const STATUS_TONE: Record<SynStatus, { dot: string; text: string; label: string }> = {
  up: { dot: 'bg-good', text: 'text-good', label: 'Up' },
  degraded: { dot: 'bg-warn', text: 'text-warn', label: 'Degraded' },
  down: { dot: 'bg-danger', text: 'text-danger', label: 'Down' },
  nodata: { dot: 'bg-border-2', text: 'text-fg-4', label: 'No data' },
};

// O33 (NAN-1721): the backend flags checks with zero recorded runs via
// `has_runs`. A brand-new check must NOT report 0% uptime rendered as a red
// pulsing "Down" (a phantom outage) — treat it as a neutral no-data state.
// Read the flag defensively until the shared SyntheticCheck api type carries it
// (Contract #3); when absent (older backend) assume the check has runs so
// existing behavior is preserved.
function hasRuns(c: SyntheticCheck): boolean {
  return (c as { has_runs?: boolean }).has_runs ?? true;
}

function statusOf(c: SyntheticCheck): SynStatus {
  if (!hasRuns(c)) return 'nodata';
  if (!c.enabled) return 'degraded';
  const u = c.uptime_pct ?? 0;
  if (u >= 99.9) return 'up';
  if (u >= 99) return 'degraded';
  return 'down';
}

const fmtMs = (v: number | null): string =>
  v == null ? '–' : v >= 1000 ? `${(v / 1000).toFixed(2)}s` : `${Math.round(v * 10) / 10}ms`;

const fmtUptime = (v: number | null): string => (v == null ? '–' : `${v.toFixed(2)}%`);

export function SyntheticsTab(_props: ObservabilityTabProps) {
  const [checks, setChecks] = useState<SyntheticCheck[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<SyntheticCheck | null>(null);
  const [deleting, setDeleting] = useState<SyntheticCheck | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.observability.listSynthetics();
      setChecks(res.checks);
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
    async (input: SyntheticCheckInput) => {
      if (editing != null) {
        await api.observability.updateSynthetic(editing.id, input);
      } else {
        await api.observability.createSynthetic(input);
      }
      await load();
    },
    [editing, load],
  );

  const handleDelete = useCallback(async () => {
    if (deleting == null) return;
    setDeleteBusy(true);
    try {
      await api.observability.deleteSynthetic(deleting.id);
      setDeleting(null);
      await load();
    } finally {
      setDeleteBusy(false);
    }
  }, [deleting, load]);

  const handleToggle = useCallback(
    async (c: SyntheticCheck, enabled: boolean) => {
      setTogglingId(c.id);
      setError(null);
      try {
        await api.observability.updateSynthetic(c.id, { enabled });
        await load();
      } catch (e) {
        setError(e instanceof ApiClientError ? e.message : String(e));
      } finally {
        setTogglingId(null);
      }
    },
    [load],
  );

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (c: SyntheticCheck) => {
    setEditing(c);
    setEditorOpen(true);
  };

  // Summary counts. A paused check is treated as degraded (not actively up);
  // a check with no recorded runs is neutral no-data (excluded from up/down).
  const up = checks.filter((c) => statusOf(c) === 'up').length;
  const degraded = checks.filter((c) => statusOf(c) === 'degraded').length;
  const down = checks.filter((c) => statusOf(c) === 'down').length;
  // Overall uptime averages only checks that actually recorded runs — a no-run
  // check has no uptime to contribute and must not drag the average toward 0%.
  const withRuns = checks.filter(hasRuns);
  const overall =
    withRuns.length > 0
      ? (withRuns.reduce((a, c) => a + (c.uptime_pct ?? 0), 0) / withRuns.length).toFixed(2)
      : null;

  // Sort by uptime ascending — worst first, matching the design. No-run checks
  // (uptime_pct defaults to 0) aren't "worst"; sort them to the bottom.
  const sorted = [...checks].sort((a, b) => {
    const ar = hasRuns(a);
    const br = hasRuns(b);
    if (ar !== br) return ar ? -1 : 1;
    return (a.uptime_pct ?? 0) - (b.uptime_pct ?? 0);
  });

  return (
    <div className="flex flex-col gap-3.5">
      {/* header / meta row */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">
          {checks.length} {checks.length === 1 ? 'check' : 'checks'}
        </span>
        {down > 0 && <span className="font-mono text-[11px] text-danger">{down} down</span>}
        <span className="text-[11px] text-fg-4">· sorted by uptime</span>
        <div className="flex-1" />
        <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={openCreate}>
          <Plus className="h-[13px] w-[13px]" />
          New check
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

      {/* summary cards */}
      {checks.length > 0 && (
        <div className="grid grid-cols-4 gap-2.5">
          <SummaryCard label="Up" value={up} dot="bg-good" tone="text-fg" />
          <SummaryCard
            label="Degraded"
            value={degraded}
            dot="bg-warn"
            tone={degraded > 0 ? 'text-warn' : 'text-fg'}
          />
          <SummaryCard
            label="Down"
            value={down}
            dot="bg-danger"
            tone={down > 0 ? 'text-danger' : 'text-fg'}
            pulse={down > 0}
          />
          <SummaryCard
            label="Overall uptime"
            value={overall == null ? '–' : `${overall}%`}
            dot="bg-good"
            tone="text-fg"
          />
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-12 text-[12px] text-fg-3">
          <Loader2 className="h-[14px] w-[14px] animate-spin" />
          Loading checks…
        </div>
      ) : sorted.length === 0 && error == null ? (
        <div className="flex flex-col items-center gap-3 py-12 text-center">
          <Radar className="h-6 w-6 text-fg-4" />
          <span className="text-[12.5px] text-fg-3">No synthetic checks defined yet.</span>
          <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={openCreate}>
            <Plus className="h-[13px] w-[13px]" />
            Create your first check
          </Button>
        </div>
      ) : sorted.length > 0 ? (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="px-3.5 py-2.5 border-b border-border font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold flex items-center gap-2">
            <Radar className="w-[12px] h-[12px] text-brand" /> Checks
            <span className="ml-auto normal-case tracking-normal text-[10px] text-fg-4">
              last 90 runs →
            </span>
          </div>
          {sorted.map((c) => {
            const status = statusOf(c);
            const st = STATUS_TONE[status];
            return (
              <div
                key={c.id}
                className="px-3.5 py-2.5 border-b border-border/50 hover:bg-fg/[0.03] grid grid-cols-[minmax(220px,1.4fr)_1.6fr_auto] gap-4 items-center"
              >
                {/* name + target */}
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        'w-2 h-2 rounded-full shrink-0',
                        st.dot,
                        status === 'down' && 'animate-pulse',
                      )}
                      title={st.label}
                    />
                    <span className="font-mono text-[12px] text-fg truncate">{c.name}</span>
                    {!c.enabled && (
                      <span className="text-[9px] uppercase tracking-wider text-fg-4 border border-border rounded px-1 py-0.5">
                        paused
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-fg-4 mt-0.5 font-mono truncate">
                    {c.target_url} · {c.interval_secs}s · expect {c.expected_status}
                  </div>
                </div>

                {/* uptime history bar */}
                <div className="flex flex-col gap-1">
                  <UptimeBar history={c.history} />
                </div>

                {/* metrics + actions */}
                <div className="flex items-center gap-5 shrink-0">
                  <div className="text-right">
                    <div className="text-[9px] uppercase tracking-wider text-fg-4">uptime</div>
                    <div
                      className={cn(
                        'font-mono text-[13px] tabular-nums',
                        !hasRuns(c)
                          ? 'text-fg-4'
                          : (c.uptime_pct ?? 0) >= 99.9
                            ? 'text-good'
                            : (c.uptime_pct ?? 0) >= 99
                              ? 'text-warn'
                              : 'text-danger',
                      )}
                    >
                      {hasRuns(c) ? fmtUptime(c.uptime_pct) : '–'}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-[9px] uppercase tracking-wider text-fg-4">p50</div>
                    <div className="font-mono text-[13px] text-fg-2 tabular-nums">
                      {fmtMs(c.p50_latency_ms)}
                    </div>
                  </div>
                  <Switch
                    className="h-4 w-7"
                    checked={c.enabled}
                    disabled={togglingId === c.id}
                    onCheckedChange={(v) => void handleToggle(c, v)}
                    aria-label={c.enabled ? 'Pause check' : 'Resume check'}
                    title={c.enabled ? 'Pause check' : 'Resume check'}
                  />
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => openEdit(c)}
                      className="inline-flex items-center rounded p-1 text-fg-3 hover:bg-fg/5 hover:text-fg"
                      title="Edit check"
                    >
                      <Pencil className="h-[12px] w-[12px]" />
                    </button>
                    <button
                      onClick={() => setDeleting(c)}
                      className="inline-flex items-center rounded p-1 text-fg-3 hover:bg-danger/10 hover:text-danger"
                      title="Delete check"
                    >
                      <Trash2 className="h-[12px] w-[12px]" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : null}

      <SyntheticEditorDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        check={editing}
        onSubmit={handleSubmit}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(o) => {
          if (!o) setDeleting(null);
        }}
        variant="danger"
        title="Delete check"
        description={
          deleting != null ? (
            <>
              Delete <span className="font-medium text-foreground">{deleting.name}</span>? This
              removes the check definition; recorded run history is retained until it ages out.
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

function SummaryCard({
  label,
  value,
  dot,
  tone,
  pulse,
}: {
  label: string;
  value: number | string;
  dot: string;
  tone: string;
  pulse?: boolean;
}) {
  return (
    <div className="rounded-lg border border-border bg-card px-3.5 py-3 flex flex-col gap-1.5">
      <div className="flex items-center gap-2">
        <span className={cn('w-1.5 h-1.5 rounded-full', dot, pulse && 'animate-pulse')} />
        <span className="text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium">{label}</span>
      </div>
      <span className={cn('text-[24px] font-mono font-semibold leading-none tabular-nums', tone)}>
        {value}
      </span>
    </div>
  );
}

export default SyntheticsTab;
