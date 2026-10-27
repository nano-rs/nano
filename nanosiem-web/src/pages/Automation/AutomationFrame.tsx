// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the Automation frame from the design mock (soar3-app.jsx):
 * page content, the Approvals drawer (soar3-gate.jsx ApprovalsDrawer) and the
 * ambient status (Ambient3), which NAN-4649 moved into the app footer. The top-bar Approvals button
 * (ApprovalsBell) toggles the drawer through the `approvals` search param, so
 * the drawer is linkable: `?approvals` opens the list, `?approvals=<id>` opens
 * one card.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Check, X } from 'lucide-react';
import type { SoarApproval } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { useLayoutOptional } from '@/contexts/LayoutContext';
import { cn } from '@/lib/utils';
import { actionIndex, asEffect, decisionBlock, inputTargets, lookupAction, minutesLeft, runOutcome, verbOf } from './soar-model';
import { EFF_TXT, EffMark, Entity, FilterSeg, H, ListState, Ring, WAIT, FOG } from './soar-kit';
import { useCatalog, useFlows, useRuns, useRunDetails, soarKeys } from './soar-queries';
import { useQueries } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useSoarGate, type SoarGate } from './soar-gate';
import { ApprovalCard, requesterWho } from './ApprovalCard';
import { usePendingApprovals } from './ApprovalsBell';
export { ApprovalsBell } from './ApprovalsBell';
import { blockWords, shortTarget } from './run-view';
import { caseLabel } from './soar-model';

/** Open / close the drawer from anywhere inside the Automation workspace. */
export function useApprovalsDrawer() {
  const [params, setParams] = useSearchParams();
  const open = params.has('approvals');
  const id = params.get('approvals') || null;
  const set = (next: string | null | false) => {
    const p = new URLSearchParams(params);
    if (next === false) p.delete('approvals');
    else p.set('approvals', next ?? '');
    setParams(p, { replace: true });
  };
  return { open, id, openDrawer: (approvalId?: string) => set(approvalId ?? null), close: () => set(false), toggle: () => set(open ? false : null) };
}

// ── Drawer (mock ApprovalsDrawer) ───────────────────────────────────────
export function ApprovalsDrawer({ gate, initialId, onClose, inline = false }: { gate: SoarGate; initialId: string | null; onClose: () => void; inline?: boolean }) {
  const { user, hasPermission } = useAuth();
  const navigate = useNavigate();
  const enabled = gate.state === 'enabled';
  const catalog = useCatalog(gate.tenant, enabled);
  const runs = useRuns(gate.tenant, enabled);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  const { query, pending, mine } = usePendingApprovals(gate);
  const flows = useFlows(gate.tenant, enabled);
  // Approvals carry no case or flow: read them from the run (loaded page first, else its detail).
  const missing = runs.data ? pending.filter((a) => !runs.data.runs.some((r) => r.id === a.run_id)).slice(0, 20).map((a) => a.run_id) : [];
  const extra = useQueries({
    queries: missing.map((id) => ({ queryKey: soarKeys.run(gate.tenant, id), queryFn: () => api.soar.getRun(id, { steps_limit: 50, approvals_limit: 50 }), enabled: enabled && !gate.demo, staleTime: 30_000 })),
  });
  function runOf(a: SoarApproval) {
    return runs.data?.runs.find((r) => r.id === a.run_id) ?? extra[missing.indexOf(a.run_id)]?.data ?? null;
  }
  function caseOf(a: SoarApproval) {
    return a.case_id ?? runOf(a)?.case_id ?? null;
  }
  function caseNumberOf(a: SoarApproval) {
    return a.case_number ?? runOf(a)?.case_number ?? null;
  }
  function flowOf(a: SoarApproval) {
    const r = runOf(a);
    const f = r?.flow_id ? flows.data?.flows.find((x) => x.id === r.flow_id) : null;
    return f ? { name: f.name, version: r?.flow_version } : null;
  }
  const [tab, setTab] = useState<'mine' | 'all'>('mine');
  const [touched, setTouched] = useState(false);
  const effTab = touched ? tab : mine.length || !query.data ? 'mine' : 'all';
  const list = effTab === 'mine' ? mine : pending;
  const [openId, setOpenId] = useState<string | null>(initialId);
  useEffect(() => { if (initialId) setOpenId(initialId); }, [initialId]);
  // Mock: the first card is open, so the decision is one click away.
  const shownId = openId ?? (initialId === null && !touched ? list.find((a) => !caseOf(a))?.id ?? null : null);
  useEffect(() => {
    if (inline) return;
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !(e.target as HTMLElement | null)?.closest('input,textarea')) onClose();
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [onClose, inline]);

  return (
    <div
      className={cn(
        'flex flex-col bg-panel',
        inline ? 'h-full' : 'absolute bottom-0 right-0 top-0 z-30 w-[440px] max-w-[92%] border-l border-border shadow-[-16px_0_40px_rgba(0,0,0,0.4)]',
      )}
      role={inline ? undefined : 'dialog'}
      aria-label="Approvals"
      data-testid="approvals-drawer"
    >
      <div className="flex flex-col gap-2.5 border-b border-border px-4 pb-3 pt-3.5">
        <div className="flex items-center gap-2">
          <h1 className="flex-1 text-[14px] font-semibold text-foreground">Approvals</h1>
          {!inline && (
            <button type="button" onClick={onClose} title="Close (esc)" aria-label="Close approvals" className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-foreground/[0.05] hover:text-foreground">
              <X className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
          )}
        </div>
        <div className="flex items-center gap-3">
          <FilterSeg
            label="Approvals"
            value={effTab}
            onChange={(v) => { setTab(v); setTouched(true); }}
            options={[['mine', 'Mine', mine.length], ['all', 'All pending', pending.length]]}
          />
          <span className="whitespace-nowrap font-mono text-[10.5px] text-muted-foreground">by expiry</span>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {gate.demo ? (
          <ListState state="forbidden" title="Approvals are not available in the demo" body="The read-only demo cannot view or decide approvals." />
        ) : query.isPending ? (
          <ListState state="loading" cols={[30, 160, 60]} />
        ) : query.isError ? (
          <ListState state="error" title="Could not load approvals" onRetry={() => void query.refetch()} />
        ) : list.length === 0 ? (
          <div className="p-6">
            <div className="flex flex-col items-center rounded-[8px] border border-dashed border-border px-6 py-8 text-center">
              <Check className="mb-2 h-4 w-4 text-primary" strokeWidth={1.5} />
              <H className="mb-1">Clear</H>
              <div className="text-[13px] font-medium text-foreground">Nothing waiting on you</div>
            </div>
          </div>
        ) : (
          list.map((a) => {
            const req = a.requested_action ?? {};
            const found = lookupAction(index, req.pack, req.action);
            const effect = asEffect(found?.action.effect);
            const verb = req.action ? verbOf(req.action, found?.action.display_name) : req.prompt || 'Approval';
            const target = inputTargets(req.inputs, found?.action, 1)[0];
            const block = decisionBlock(a, { userId: user?.id, canApprove: hasPermission('soar:approve'), demo: gate.demo });
            const caseId = caseOf(a);
            const isOpen = shownId === a.id && !caseId;
            const isAi = a.requested_source === 'ai' || a.requested_source === 'pivt';
            return (
              <div key={a.id} className={cn('border-b border-border', isOpen && 'bg-background')} data-testid="approval-row">
                <button
                  type="button"
                  onClick={() => (caseId ? navigate(`/cases/${caseId}?approval=${encodeURIComponent(a.id)}`) : (setOpenId(isOpen ? '' : a.id), setTouched(true)))}
                  className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-foreground/[0.03]"
                >
                  <Ring left={minutesLeft(a.expires_at)} size={30} total={Math.max(1, (Date.parse(a.expires_at) - Date.parse(a.created_at)) / 60_000)} />
                  <div className={cn('flex min-w-0 flex-1 flex-col gap-1', block && 'opacity-60')}>
                    <div className="flex min-w-0 items-center gap-1.5">
                      <EffMark e={effect} size={9} />
                      <span className={cn('shrink-0 whitespace-nowrap text-[12.5px] font-medium', effect ? EFF_TXT[effect] : 'text-foreground')}>{verb}</span>
                      {target && <span className="flex min-w-0 overflow-hidden"><Entity t={target.kind} v={shortTarget(target.value)} size="sm" /></span>}
                      {isAi && <span className="shrink-0 font-mono text-[10px] text-ai">pivt</span>}
                    </div>
                    <div className="truncate font-mono text-[10.5px] text-muted-foreground">
                      {caseLabel(caseId, caseNumberOf(a))} · {requesterWho(a, user?.id, flowOf(a))}
                      {block && <> · {blockWords(block, a).short}</>}
                    </div>
                  </div>
                  <span className="shrink-0 whitespace-nowrap font-mono text-[10.5px] text-muted-foreground">{caseId ? 'open case →' : isOpen ? 'close' : 'review'}</span>
                </button>
                {isOpen && (
                  <div className="px-3 pb-3">
                    <ApprovalCard key={a.id + a.status} approval={a} index={index} tenant={gate.tenant} demo={gate.demo} flow={flowOf(a)} />
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
      <div className="border-t border-border px-4 py-2.5 text-[11px] text-muted-foreground">
        Case approvals open in the case. Past decisions are on each run and in the audit log.
      </div>
    </div>
  );
}

// ── Footer status (mock Ambient3) ───────────────────────────────────────
/**
 * NAN-4649 — the running / waiting-on-you / unknown-outcome counts live in
 * the app-wide footer (LayoutContext.pageStatus slot, same as Search's query
 * stats), not in a second bar above it. Cleared on unmount, so no other route
 * shows them.
 */
function AutomationFooterStatus({ gate }: { gate: SoarGate }) {
  const setPageStatus = useLayoutOptional()?.setPageStatus;
  const enabled = gate.state === 'enabled';
  const runs = useRuns(gate.tenant, enabled);
  const all = runs.data?.runs;
  const details = useRunDetails(gate.tenant, all ?? [], enabled);
  const catalog = useCatalog(gate.tenant, enabled);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  const { openDrawer } = useApprovalsDrawer();
  const { mine } = usePendingApprovals(gate);
  const running = (all ?? []).filter((r) => r.status === 'running' || r.status === 'queued').length;
  const amb = (all ?? []).filter((r) => runOutcome(r, details.get(r.id)?.steps) === 'unknown');
  const ambId = amb[0]?.id;
  const next = mine[0];
  const nextLeft = next ? minutesLeft(next.expires_at) : 0;
  const nextFound = next ? lookupAction(index, next.requested_action?.pack, next.requested_action?.action) : undefined;
  const nextTarget = next ? inputTargets(next.requested_action?.inputs, nextFound?.action, 1)[0] : undefined;
  const nextLabel = next
    ? `${nextLeft}m · ${next.requested_action?.action ? verbOf(next.requested_action.action, nextFound?.action.display_name) : 'Approval'}${nextTarget ? ` ${shortTarget(nextTarget.value)}` : ''}`
    : null;
  const nextId = next?.id;
  // openDrawer closes over the current search params; keep it in a ref so the
  // footer content only rebuilds when the counts change.
  const openRef = useRef(openDrawer);
  openRef.current = openDrawer;

  const content = useMemo(() => (
    <span className="flex items-center gap-[18px] whitespace-nowrap" data-testid="automation-status">
      <Link to="/automation/runs" className="flex items-center gap-1.5 text-primary hover:underline">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
        {running} running
      </Link>
      {!gate.demo && (
        <button
          type="button"
          onClick={() => openRef.current()}
          className={cn('flex items-center gap-1.5 hover:underline', mine.length > 0 ? 'text-warn' : 'hover:text-foreground')}
        >
          <span className="h-2 w-2.5 rounded-sm" style={{ background: WAIT }} />
          {mine.length} waiting on you
        </button>
      )}
      {ambId && (
        <Link to={`/automation/runs/${ambId}`} className="flex items-center gap-1.5 text-warn hover:underline">
          <span className="h-1.5 w-2.5 rounded-sm" style={{ background: FOG }} />
          {amb.length} unknown outcome
        </Link>
      )}
      {nextId && nextLabel && (
        <button type="button" onClick={() => openRef.current(nextId)} className="hidden items-center gap-2 hover:text-foreground lg:flex">
          next expiry <Ring left={nextLeft} size={16} label=" " />
          <span className={nextLeft <= 10 ? 'text-destructive' : 'text-fg-2'}>{nextLabel}</span>
        </button>
      )}
    </span>
  ), [running, gate.demo, mine.length, ambId, amb.length, nextId, nextLabel, nextLeft]);

  useEffect(() => {
    setPageStatus?.(content);
  }, [content, setPageStatus]);
  useEffect(() => () => setPageStatus?.(null), [setPageStatus]);
  return null;
}

/** Full-bleed Automation workspace: content + drawer; counts go to the app footer. */
export function AutomationFrame({ children, drawer: forced }: { children: ReactNode; drawer?: { id: string | null; onClose: () => void } }) {
  const gate = useSoarGate();
  const param = useApprovalsDrawer();
  const drawer = forced ? { open: true, id: forced.id, close: forced.onClose } : param;
  return (
    <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden bg-background" data-testid="automation-frame">
      <div className="relative flex min-h-0 flex-1 flex-col">
        {children}
        {drawer.open && <ApprovalsDrawer gate={gate} initialId={drawer.id} onClose={drawer.close} />}
      </div>
      <AutomationFooterStatus gate={gate} />
    </div>
  );
}

