// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 / NAN-4546 — Flows list (port of soar3-flow.jsx Flows3: one
 * transit line per flow) and the flow route, which opens the editor.
 *
 * NAN-4535 / NAN-4588 — "Draft with pivt" opens the pivt panel with
 * `@flow ` focused. pivt drafts the flow inline in its panel (the server
 * saves it disabled), then navigates here to the saved draft for review.
 */
import { useMemo, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Zap } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarRun } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { openPivtPanel } from '@/enterprise/components/pivt/commands/router';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { actionIndex, flowGraph, runOutcome, triggerLabel, utcDateTime, type PivtFlowDraftState } from './soar-model';
import { Banner, FilterSeg, GatedButton, ListState, Mono, PAGE_TITLE, StatusPill } from './soar-kit';
import { effectErrorMessage, errorStatus, invalidateSoar, useCatalog, useFlow, useFlowStats, useFlows, useRuns } from './soar-queries';
import { useFlowPivt, useSoarGate } from './soar-gate';
import { FlowLine, flowGlyphs } from './TransitMap';
import { FlowEditor } from './FlowEditor';

type FlowFilter = 'all' | 'live' | 'draft' | 'archived';
const DAY = 86_400_000;

/** Hand the brief to pivt: open its panel with `@flow ` ready to type. */
function openFlowPivt() {
  openPivtPanel('@flow ');
}

/** "1h ago" style age against the page clock. */
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < DAY / 1000) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86_400)}d ago`;
}

const LAST_WORD: Record<string, string> = {
  ok: 'succeeded', failed: 'failed', timed_out: 'timed out', canceled: 'canceled', waiting: 'waiting', running: 'running', queued: 'queued', unknown: 'unknown outcome',
};

function lastRuns(runs: SoarRun[]) {
  const last = new Map<string, SoarRun>();
  for (const r of runs) {
    if (!r.flow_id) continue;
    if (!last.has(r.flow_id)) last.set(r.flow_id, r);
  }
  return { last };
}

export function FlowsPage() {
  const gate = useSoarGate();
  const { hasPermission } = useAuth();
  const navigate = useNavigate();
  const client = useQueryClient();
  const enabled = gate.state === 'enabled';
  const flows = useFlows(gate.tenant, enabled);
  const catalog = useCatalog(gate.tenant, enabled);
  const runs = useRuns(gate.tenant, enabled);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  const now = Date.now();
  const stats = useMemo(() => lastRuns(runs.data?.runs ?? []), [runs.data]);
  // NAN-4544: 24h counts come from the server; a flow missing from a loaded response ran 0 times.
  const flowStats24 = useFlowStats(gate.tenant, enabled);
  const day = useMemo(() => new Map((flowStats24.data?.flows ?? []).map((s) => [s.flow_id, s])), [flowStats24.data]);
  const [filter, setFilter] = useState<FlowFilter>('all');
  const all = flows.data?.flows ?? [];
  const visible = all.filter((f) => filter === 'all' || f.status === filter);
  const count = (s: string) => all.filter((f) => f.status === s).length;
  const canManage = !gate.demo && hasPermission('soar:manage');
  const pivt = useFlowPivt(gate.demo) && enabled;

  const create = useMutation({
    mutationFn: () =>
      api.soar.createFlow({
        name: 'Untitled flow',
        definition: { summary: 'Untitled flow', description: '', value: { modules: [{ id: 's1', summary: 'Pass-through', value: { type: 'identity' } }] } },
        trigger: { on: 'manual', match: null, cron: null },
        status: 'draft',
      }),
    onSuccess: (f) => {
      void invalidateSoar(client, gate.tenant);
      navigate(`/automation/flows/${f.id}`);
    },
  });

  return (
    <div className="flex h-full min-h-0 flex-col" data-screen-label="Flows">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2 px-5 pb-3 pt-4">
        <div className="mr-auto">
          <h1 className={PAGE_TITLE}>Flows</h1>
          <div className="mt-1.5 font-mono text-[11px] text-muted-foreground">
            {flows.data ? <>{all.length} flows · {count('live')} live{gate.demo && ' · read-only demo'}</> : 'Automation flows'}
          </div>
        </div>
        {all.length > 0 && (
          <FilterSeg
            label="Flow status"
            value={filter}
            onChange={setFilter}
            options={[['all', 'All', all.length], ['live', 'Live', count('live')], ['draft', 'Draft', count('draft')], ['archived', 'Archived', count('archived')]]}
          />
        )}
        {pivt && (
          <Button variant="outline" size="sm" className="shadow-none" onClick={() => openFlowPivt()}>
            Draft with pivt
          </Button>
        )}
        {!gate.demo && (
          <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" disabled={create.isPending} onClick={() => create.mutate()}>
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />New flow
          </GatedButton>
        )}
      </div>
      {create.isError && <Banner tone="danger" title="Could not create a flow" className="mx-5 mb-3">{effectErrorMessage(create.error, 'The flow was not created.')}</Banner>}
      {flows.data?.admission_backpressure && (
        <Banner tone="warn" title="Trigger admission is throttled" className="mx-5 mb-3">
          {flows.data.admission_backpressure.reason} · since <span className="font-mono">{utcDateTime(flows.data.admission_backpressure.since)}</span>
        </Banner>
      )}
      {(flows.data?.event_overflow_count ?? 0) > 0 && (
        <Banner tone="warn" title="Trigger events dropped" className="mx-5 mb-3">
          <span className="font-mono">{flows.data!.event_overflow_count}</span> events overflowed the trigger queue
          {flows.data!.last_event_overflow_at && <> · last <span className="font-mono">{utcDateTime(flows.data!.last_event_overflow_at)}</span></>}.
        </Banner>
      )}
      <div className="min-h-0 flex-1 overflow-auto border-t border-border">
        {flows.isPending ? (
          <ListState state="loading" cols={[180, 200, 60, 100]} />
        ) : flows.isError ? (
          <ListState state="error" title="Could not load flows" onRetry={() => void flows.refetch()} />
        ) : all.length === 0 ? (
          <ListState state="empty" title="No flows yet" body={pivt ? 'Draft one with pivt, or sequence actions, approvals, conditions and bounded loops yourself.' : 'Flows sequence actions, approvals, conditions and bounded loops.'} />
        ) : visible.length === 0 ? (
          <ListState state="filtered" />
        ) : (
          visible.map((f) => {
            const lr = stats.last.get(f.id);
            const d = day.get(f.id);
            return (
              <Link
                key={f.id}
                to={`/automation/flows/${f.id}`}
                data-testid="flow-row"
                className={cn(
                  'grid h-14 w-full grid-cols-[minmax(0,1fr)_100px] items-center gap-4 border-b border-border px-5 text-left hover:bg-foreground/[0.02] md:grid-cols-[minmax(0,1fr)_260px_100px] xl:grid-cols-[minmax(0,1fr)_320px_200px_100px]',
                  f.status === 'archived' && 'opacity-55',
                )}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[12.5px] font-medium text-foreground">{f.name}</span>
                    <Mono className="text-[10.5px] text-muted-foreground">v{f.version}</Mono>
                    <StatusPill s={f.status} className="text-[11px]" />
                  </div>
                  <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-[11px] text-muted-foreground">
                    <Zap className="h-3 w-3 shrink-0" strokeWidth={1.5} />
                    <span className="truncate">{triggerLabel(f.trigger)}</span>
                  </div>
                </div>
                <div className="hidden md:block"><FlowLine glyphs={flowGlyphs(flowGraph(f.definition).nodes, index)} /></div>
                <span className="hidden font-mono text-[10.5px] text-fg-2 xl:block">{lr ? `${LAST_WORD[runOutcome(lr)] ?? lr.status} ${ago(lr.created_at, now)}` : '—'}</span>
                <span className="text-right font-mono text-[10.5px] text-muted-foreground" title={d ? `${d.succeeded} succeeded · ${d.failed} failed` : undefined}>
                  {flowStats24.data ? `${d?.runs ?? 0} runs · 24h` : '—'}
                </span>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}

export function FlowViewPage() {
  const { id = '' } = useParams<{ id: string }>();
  const location = useLocation();
  const pivtDraft = (location.state as PivtFlowDraftState | null)?.pivtDraft;
  const gate = useSoarGate();
  const flow = useFlow(gate.tenant, id, gate.state === 'enabled' && !!id);
  if (flow.isPending) return <ListState state="loading" />;
  if (flow.isError) {
    return errorStatus(flow.error) === 404 ? (
      <ListState state="empty" title="Flow not found" action={<Link to="/automation/flows" className="text-[11.5px] text-primary hover:underline">All flows</Link>} />
    ) : (
      <ListState state="error" title="Could not load this flow" onRetry={() => void flow.refetch()} />
    );
  }
  const notice =
    pivtDraft && flow.data.status === 'draft' ? (
      <Banner tone="neutral" title="Drafted by pivt">
        Saved disabled. <span className="font-mono">{pivtDraft.approval_gates}</span> approval gate{pivtDraft.approval_gates === 1 ? '' : 's'}
        {pivtDraft.repaired && ' · fixed once after validation'}. Review every step, dry run, then activate.
      </Banner>
    ) : undefined;
  return <FlowEditor key={flow.data.id} flow={flow.data} notice={notice} />;
}

export default FlowsPage;
