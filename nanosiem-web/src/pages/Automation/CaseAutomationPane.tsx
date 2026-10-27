// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the case automation wall (mock soar3-case.jsx Case3), hosted in
 * the case evidence drawer's Automation tab and, expanded, as a full-width
 * sheet with the mock's two-column layout.
 *
 *   Needs a decision · N   approval cards for this case, sorted by expiry
 *   Wall                   receipts (actor, time, target, effect, outcome,
 *                          run link), decided gates, pinned requests
 *   Entities               case entities as verb-palette pills
 *   Playbook               playbook ↔ run linkage is not in the API (NAN-4556)
 *
 * Runs come from the server-side `case_id` filter (case visibility
 * enforced). Open gates come from the detail of suspended runs (bounded).
 * This is not the Cases notebook: it never writes notebook entries or case
 * lifecycle state.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useQueries } from '@tanstack/react-query';
import { Hand, Lock, Maximize2, Play } from 'lucide-react';
import { api } from '@/lib/api';
import type { EntityTypeSummary } from '@/lib/api';
import type { SoarApproval, SoarCatalog, SoarConnection, SoarRun, SoarRunDetail } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { cn } from '@/lib/utils';
import {
  actionIndex,
  asEffect,
  entityKindForCaseType,
  inputTargets,
  lookupAction,
  runOutcome,
  shortId,
  verbOf,
  type IndexedAction,
} from './soar-model';
import {
  Banner,
  EFF_TXT,
  EffMark,
  Entity,
  GatedButton,
  H,
  ListState,
  Mono,
  Note,
  Origin,
  Outcome,
  Receipt,
  StatusPill,
  Vendor,
  originOf,
  outcomeKey,
  smallButton,
} from './soar-kit';
import { soarKeys, useApprovals, useCatalog, useConnections, useFlows, useRuns } from './soar-queries';
import type { SoarGate } from './soar-gate';
import { ApprovalCard } from './ApprovalCard';
import { VerbPalette } from './VerbPalette';
import { RunActionSheet, type RunActionPreset } from './RunActionSheet';
import { hhmm, shortValue } from './case-model';

/** Case header facts the host already has (optional). */
export interface CaseRef {
  case_number?: number;
  title?: string;
  severity?: string;
  status?: string;
  assignee_name?: string | null;
  created_at?: string;
}

const SUSPENDED_DETAILS = 10;
const FAILED_DETAILS = 5;

export function CaseAutomationPane({
  caseId,
  entities,
  gate,
  caseInfo,
}: {
  caseId: string;
  entities: EntityTypeSummary[];
  gate: SoarGate;
  caseInfo?: CaseRef;
}) {
  const [wide, setWide] = useState(false);
  const data = useCaseAutomation(caseId, gate);
  return (
    <>
      <CaseWall caseId={caseId} entities={entities} gate={gate} caseInfo={caseInfo} data={data} layout="drawer" onExpand={() => setWide(true)} />
      <Sheet open={wide} onOpenChange={setWide}>
        <SheetContent
          side="right"
          hideClose
          overlayClassName="bg-black/40 backdrop-blur-none"
          className="flex w-[1180px] max-w-[calc(100vw-24px)] flex-col gap-0 bg-background p-0 text-foreground shadow-xl sm:max-w-[calc(100vw-24px)]"
          data-testid="case-wall-sheet"
        >
          <SheetTitle className="sr-only">Case automation</SheetTitle>
          <SheetDescription className="sr-only">Approvals, receipts and entity actions for this case</SheetDescription>
          <CaseWall caseId={caseId} entities={entities} gate={gate} caseInfo={caseInfo} data={data} layout="wall" onClose={() => setWide(false)} />
        </SheetContent>
      </Sheet>
    </>
  );
}

// ── Data ────────────────────────────────────────────────────────────────

interface CaseAutomationData {
  runs: ReturnType<typeof useRuns>;
  list: SoarRun[];
  catalog: SoarCatalog | undefined;
  connections: SoarConnection[];
  index: Map<string, IndexedAction>;
  details: Map<string, SoarRunDetail>;
  pending: SoarApproval[];
  decided: SoarApproval[];
  flowNames: Map<string, string>;
  canRun: boolean;
}

function useCaseAutomation(caseId: string, gate: SoarGate): CaseAutomationData {
  const { hasPermission } = useAuth();
  const enabled = gate.state === 'enabled';
  const runs = useRuns(gate.tenant, enabled, caseId);
  const catalog = useCatalog(gate.tenant, enabled);
  const canRun = !gate.demo && hasPermission('soar:run');
  const connections = useConnections(gate.tenant, enabled && canRun);
  const flows = useFlows(gate.tenant, enabled);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  const list = useMemo(() => runs.data?.runs ?? [], [runs.data]);

  // Open gates (suspended) and ambiguous sends (failed) need the run detail.
  const detailed = gate.demo
    ? []
    : [
        ...list.filter((r) => r.status === 'suspended').slice(0, SUSPENDED_DETAILS),
        ...list.filter((r) => r.status === 'failed').slice(0, FAILED_DETAILS),
      ];
  const detailQueries = useQueries({
    queries: detailed.map((r) => ({
      queryKey: soarKeys.run(gate.tenant, r.id),
      queryFn: () => api.soar.getRun(r.id, { steps_limit: 50, approvals_limit: 50 }),
      enabled,
    })),
  });
  const details = new Map<string, SoarRunDetail>();
  for (const q of detailQueries) if (q.data) details.set(q.data.id, q.data);
  const pending = [...details.values()]
    .flatMap((d) => (d.approvals ?? []).filter((a) => a.status === 'pending'))
    .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));

  // Decided gates for the wall; the approvals list is fenced for demo.
  const readDecided = enabled && !gate.demo && list.length > 0;
  const approved = useApprovals(gate.tenant, 'approved', readDecided);
  const rejected = useApprovals(gate.tenant, 'rejected', readDecided);
  const expired = useApprovals(gate.tenant, 'expired', readDecided);
  const runIds = new Set(list.map((r) => r.id));
  const decided = [approved, rejected, expired]
    .flatMap((q) => q.data?.approvals ?? [])
    .filter((a) => runIds.has(a.run_id));

  const flowNames = new Map((flows.data?.flows ?? []).map((f) => [f.id, f.name]));
  return { runs, list, catalog: catalog.data, connections: connections.data?.connections ?? [], index, details, pending, decided, flowNames, canRun };
}

// ── View ────────────────────────────────────────────────────────────────

function CaseWall({
  caseId,
  entities,
  gate,
  caseInfo,
  data,
  layout,
  onExpand,
  onClose,
}: {
  caseId: string;
  entities: EntityTypeSummary[];
  gate: SoarGate;
  caseInfo?: CaseRef;
  data: CaseAutomationData;
  layout: 'drawer' | 'wall';
  onExpand?: () => void;
  onClose?: () => void;
}) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [preset, setPreset] = useState<RunActionPreset | null>(null);
  const { runs, list, index, pending, decided, details, canRun } = data;
  const caseLabel = caseInfo?.case_number != null ? `CASE-${caseInfo.case_number}` : shortId(caseId);
  const caseTitle = caseInfo?.title ? `${caseLabel} · ${caseInfo.title}` : caseLabel;

  // Deep link `?approval=<id>`: scroll to and flash that decision card.
  const focus = params.get('approval');
  const [hl, setHl] = useState<string | null>(focus);
  const wallRef = useRef<HTMLDivElement>(null);
  const pendingIds = pending.map((a) => a.id).join(',');
  useEffect(() => {
    if (!focus) return;
    setHl(focus);
    const el = document.getElementById(`apr-${focus}`);
    const c = wallRef.current;
    if (el && c) c.scrollTop += el.getBoundingClientRect().top - c.getBoundingClientRect().top - 16;
    const t = setTimeout(() => setHl(null), 2200);
    return () => clearTimeout(t);
  }, [focus, pendingIds]);

  const chips = entities.flatMap((group) => {
    const kind = entityKindForCaseType(group.entity_type);
    return kind ? group.entities.slice(0, 20).map((e) => ({ kind, value: e.entity_value })) : [];
  });

  const pickInverse = (r: SoarRun) => {
    const found = lookupAction(index, r.pack_name, r.action);
    const rollback = found?.action.rollback;
    if (!found || !rollback) return;
    const inputs = Object.fromEntries(
      Object.entries((r.inputs as Record<string, unknown>) ?? {}).filter(([, v]) => typeof v === 'string' || typeof v === 'number').map(([k, v]) => [k, String(v)]),
    );
    setPreset({ pack: found.pack.name, action: rollback, connectionId: r.connection_id ?? undefined, inputs, caseId, caseLabel: caseTitle });
  };

  // NAN-4544: server display names for current active members; raw id otherwise.
  const who = (requestedBy: string | null | undefined, name?: string | null) =>
    !requestedBy ? '—' : requestedBy === user?.id ? 'You' : requestedBy === 'system' ? 'system' : name || requestedBy;

  // Wall entries, newest first.
  const entries: Array<{ at: string; key: string; el: ReactNode }> = [];
  for (const r of list) {
    const found = lookupAction(index, r.pack_name, r.action);
    const effect = asEffect(found?.action.effect);
    const target = inputTargets(r.inputs, found?.action, 1)[0];
    const detail = details.get(r.id);
    const outcome = runOutcome(r, detail?.steps);
    const approver = decided.find((a) => a.run_id === r.id && a.status === 'approved');
    const approvedBy = approver?.decided_by ?? null;
    const origin = originOf(r.trigger_kind);
    const flowName = r.flow_id ? data.flowNames.get(r.flow_id) : undefined;
    const originWho =
      origin === 'pivt'
        ? `pivt · on behalf of ${who(r.requested_by, r.requested_by_name)}`
        : origin === 'trigger'
          ? [r.trigger_kind === 'schedule' ? 'Schedule' : r.trigger_kind === 'case' ? 'Case' : 'Alert', r.trigger_ref].filter(Boolean).join(' · ')
          : who(r.requested_by, r.requested_by_name);
    entries.push({
      at: r.created_at,
      key: `run-${r.id}`,
      el: (
        <Receipt
          e={effect}
          verb={r.action ? verbOf(r.action, found?.action.display_name) : `Flow · ${flowName ?? shortId(r.flow_id)}`}
          t={target?.kind ?? 'value'}
          v={target ? shortValue(target.value) : undefined}
          p={r.pack_name}
          vendor={found?.pack.vendor}
          inv={!!found?.action.rollback && canRun}
          outcome={
            <>
              <Outcome s={outcomeKey(outcome)} />
              {r.dry_run && <span className="font-mono text-[10.5px] text-muted-foreground">dry run</span>}
            </>
          }
          by={approvedBy ? who(approvedBy, approver?.decided_by_name) : null}
          at={`${hhmm(r.created_at)} UTC`}
          run={
            <Link to={`/automation/runs/${r.id}`} className="hover:underline">
              {shortId(r.id)}
            </Link>
          }
          origin={origin}
          originWho={originWho}
          onInverse={() => pickInverse(r)}
        />
      ),
    });
  }
  for (const a of decided) {
    if (!a.decided_at && a.status !== 'expired') continue;
    const found = lookupAction(index, a.requested_action.pack, a.requested_action.action);
    const target = inputTargets(a.requested_action.inputs, found?.action, 1)[0];
    entries.push({
      at: a.decided_at ?? a.expires_at,
      key: `apr-${a.id}`,
      el: (
        <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-border px-3 py-2 text-[11.5px]" data-testid="wall-decided">
          <Hand className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.5} />
          <span className="text-fg-2">{a.decided_by ? who(a.decided_by, a.decided_by_name) : 'Expired'}</span>
          <StatusPill s={a.status} className="text-[11px]" />
          <span className="text-foreground">
            {verbOf(a.requested_action.action ?? '', found?.action.display_name)} {target ? shortValue(target.value) : ""}
          </span>
          {a.reason && <span className="min-w-0 truncate text-muted-foreground">“{a.reason}”</span>}
          <span className="flex-1" />
          <Link to={`/automation/runs/${a.run_id}`} className="font-mono text-[10.5px] text-primary hover:underline">
            {shortId(a.run_id)}
          </Link>
        </div>
      ),
    });
  }
  for (const a of pending) {
    const found = lookupAction(index, a.requested_action.pack, a.requested_action.action);
    const effect = asEffect(found?.action.effect);
    const target = inputTargets(a.requested_action.inputs, found?.action, 1)[0];
    const o = originOf(a.requested_source);
    entries.push({
      at: a.created_at,
      key: `req-${a.id}`,
      el: (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-dashed border-border-2 px-3 py-2">
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex items-center gap-2 text-[11px]">
              <Origin o={o} who={o === 'pivt' ? `pivt · ${who(a.requested_by, a.requested_by_name)}` : who(a.requested_by, a.requested_by_name)} size={14} />
              <span className="text-muted-foreground">requested approval</span>
            </div>
            <div className="flex min-w-0 items-center gap-1.5">
              <EffMark e={effect} size={9} />
              <span className={cn('text-[12px] font-medium', effect ? EFF_TXT[effect] : 'text-foreground')}>
                {verbOf(a.requested_action.action ?? '', found?.action.display_name)}
              </span>
              {target && <Entity t={target.kind} v={shortValue(target.value)} title={target.value} size="sm" className="max-w-[200px]" />}
              {a.requested_action.pack && <Vendor p={a.requested_action.pack} label={found?.pack.vendor} size={14} />}
            </div>
          </div>
          <button
            type="button"
            className="font-mono text-[10.5px] text-warn hover:underline"
            onClick={() => document.getElementById(`apr-${a.id}`)?.scrollIntoView({ block: 'start', behavior: 'smooth' })}
          >
            pinned above ↑
          </button>
        </div>
      ),
    });
  }
  entries.sort((x, y) => Date.parse(y.at) - Date.parse(x.at));

  const header = (
    <div className={cn('flex shrink-0 items-end gap-3 border-b border-border', layout === 'wall' ? 'flex-wrap px-5 pb-3 pt-4' : 'flex-wrap px-3 py-2')}>
      {layout === 'wall' ? (
        <div className="min-w-0 max-md:basis-full">
          <h2 className="flex items-baseline gap-2.5 text-[20px] font-semibold leading-none tracking-[-0.01em] text-foreground">
            <Mono className="text-[13px] text-muted-foreground">{caseLabel}</Mono>
            <span className="min-w-0 md:truncate">{caseInfo?.title ?? 'Case automation'}</span>
          </h2>
          <div className="mt-1.5 font-mono text-[11px] text-muted-foreground">
            {caseInfo?.severity && <span className={cn(caseInfo.severity === 'critical' || caseInfo.severity === 'high' ? 'text-destructive' : 'text-fg-2')}>{caseInfo.severity}</span>}
            {caseInfo?.status && <> · {caseInfo.status.replace(/_/g, ' ')}</>}
            {caseInfo && <> · owner {caseInfo.assignee_name ?? '—'}</>}
            {caseInfo?.created_at && <> · opened {hhmm(caseInfo.created_at)} UTC</>}
          </div>
        </div>
      ) : null}
      <span className="flex-1" />
      <div className="flex items-center gap-2">
        {!gate.demo && (
          <GatedButton allowed={canRun} why="Requires soar:run" size="sm" variant="outline" className={smallButton} onClick={() => setPreset({ caseId, caseLabel: caseTitle })}>
            {canRun && <Play className="h-3.5 w-3.5" strokeWidth={1.5} />}
            Run action
          </GatedButton>
        )}
        <Button size="sm" variant="outline" className={smallButton} onClick={() => navigate(`/automation/runs?case=${encodeURIComponent(caseId)}`)}>
          Related runs · <span className="font-mono">{list.length}</span>
        </Button>
        {onExpand && (
          <Button size="sm" variant="ghost" className="h-7 w-7 p-0 shadow-none" onClick={onExpand} aria-label="Open case wall" title="Open case wall">
            <Maximize2 className="h-3.5 w-3.5" strokeWidth={1.5} />
          </Button>
        )}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            title="Close (esc)"
            className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-foreground/5 hover:text-foreground"
          >
            <svg viewBox="0 0 24 24" className="h-[14px] w-[14px]" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden>
              <path d="M6 6l12 12M18 6 6 18" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );

  const decisions = pending.length > 0 && (
    <div className="mb-6 flex flex-col gap-2.5" data-testid="case-decisions">
      <div className="flex items-center gap-2">
        <H className="text-warn">Needs a decision · {pending.length}</H>
        <span className="font-mono text-[10.5px] text-muted-foreground">sorted by expiry</span>
        {/* Kept for screen readers and the NAN-4540 contract. */}
        <span className="sr-only">Waiting on approval</span>
      </div>
      {pending.map((a) => (
        <div key={a.id + a.status} id={`apr-${a.id}`} className="scroll-mt-4">
          <ApprovalCard approval={a} index={index} tenant={gate.tenant} demo={gate.demo} highlight={hl === a.id} />
        </div>
      ))}
    </div>
  );

  const wall = (
    <>
      <H className="mb-3">Wall</H>
      {runs.isPending ? (
        <ListState state="loading" cols={[40, 160, 60]} />
      ) : runs.isError ? (
        <ListState state="error" title="Could not load runs" onRetry={() => void runs.refetch()} />
      ) : entries.length === 0 ? (
        <div className="rounded-[8px] border border-dashed border-border px-4 py-6 text-center">
          <H className="mb-1.5">Nothing yet</H>
          <div className="text-[12.5px] text-foreground">No automation has run on this case.</div>
          <div className="mt-1 text-[11.5px] text-muted-foreground">Click an entity for actions, or request one with Run action.</div>
        </div>
      ) : (
        entries.map((e, i) => (
          <div key={e.key} className="grid grid-cols-[44px_minmax(0,1fr)] gap-3 pb-3">
            <div className="flex flex-col items-center">
              <span className="pt-1 font-mono text-[10px] text-fg-4">{hhmm(e.at)}</span>
              {i < entries.length - 1 && <span className="mt-1 w-px flex-1 bg-border" />}
            </div>
            <div className="min-w-0">{e.el}</div>
          </div>
        ))
      )}
      <Note className="mt-1">Receipts: actor, time, target, effect, outcome, run link — no vendor dumps. Entity pills open the verb palette (click or right-click).</Note>
    </>
  );

  const side = (
    <>
      <H>Entities</H>
      {chips.length > 0 ? (
        <>
          <div className="flex flex-wrap gap-1.5" data-testid="case-entities">
            {chips.map((c, i) => (
              <VerbPalette
                key={`${c.kind}-${c.value}-${i}`}
                kind={c.kind}
                value={c.value}
                catalog={data.catalog}
                connections={data.connections}
                canRun={canRun}
                demo={gate.demo}
                caseLabel={caseLabel}
                onPick={(it) =>
                  setPreset({ pack: it.pack.name, action: it.action.name, connectionId: it.connection?.id, inputs: { [it.input]: c.value }, caseId, caseLabel: caseTitle })
                }
              />
            ))}
          </div>
          <div className="text-[10.5px] text-muted-foreground">Click any entity for actions.</div>
        </>
      ) : (
        <div className="text-[11.5px] text-muted-foreground">No entities on this case yet.</div>
      )}
      <H className="mt-2">Playbook</H>
      <Banner tone="neutral" icon={<Lock strokeWidth={1.5} />} title="Playbook steps are not linked to runs yet">
        Executable playbook steps will show queued / running / awaiting approval / completed through their run. Until then the Playbook tab lists
        the steps; no step runs an action from here.
      </Banner>
    </>
  );

  if (layout === 'wall') {
    return (
      <div className="flex h-full min-h-0 flex-col" data-testid="case-wall">
        {header}
        <div className="min-h-0 flex-1 overflow-y-auto md:grid md:grid-cols-[minmax(0,1fr)_260px] md:overflow-hidden xl:grid-cols-[minmax(0,1fr)_320px]">
          <div ref={wallRef} className="flex min-h-0 flex-col px-4 py-4 md:overflow-auto md:px-5">
            {decisions}
            {wall}
          </div>
          <div className="flex flex-col gap-3 border-t border-border p-4 md:overflow-auto md:border-l md:border-t-0">{side}</div>
        </div>
        {canRun && <RunActionSheet open={preset !== null} onOpenChange={(o) => !o && setPreset(null)} tenant={gate.tenant} catalog={data.catalog} connections={data.connections} preset={preset ?? undefined} />}
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col" data-testid="case-automation">
      {header}
      <div ref={wallRef} className="flex min-h-0 flex-1 flex-col overflow-y-auto px-3 py-3">
        {decisions}
        <div className="mb-5 flex flex-col gap-2">{side}</div>
        {wall}
      </div>
      {canRun && <RunActionSheet open={preset !== null} onOpenChange={(o) => !o && setPreset(null)} tenant={gate.tenant} catalog={data.catalog} connections={data.connections} preset={preset ?? undefined} />}
    </div>
  );
}
