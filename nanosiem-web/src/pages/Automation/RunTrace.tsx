// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — one run (mock soar3-runs.jsx Trace3): action chip, origin and
 * outcome, the decision card while a human gate is open, state banners, a
 * step timeline on a run-local time axis, and the selected span's detail
 * with the redacted request and the run's connection / case / approvals.
 *
 * Demo principals receive a projection without inputs, rendered requests,
 * approvals or requester; the trace renders whatever fields are present.
 */
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Ban, ChevronDown, Clock, Hand, Workflow } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarFlow, SoarRunDetail } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { cn } from '@/lib/utils';
import { caseLabel, formatDuration, isTerminal, shortId, utcTime, type IndexedAction } from './soar-model';
import {
  ActionChip,
  Banner,
  EffMark,
  GatedButton,
  H,
  KV,
  ListState,
  Mono,
  Origin,
  Outcome,
  SPAN_BG,
  Spinner,
  StatusPill,
  xsButton,
} from './soar-kit';
import { ApprovalCard } from './ApprovalCard';
import { effectErrorMessage, errorStatus, invalidateSoar, useConnections, useRun } from './soar-queries';
import { actorLabel, fmtS, runView, shortTarget, traceSpans, type TraceSpan } from './run-view';
import { useApprovalsDrawer } from './AutomationFrame';

export interface RunActionPreset {
  pack: string;
  action: string;
  inputs?: Record<string, string>;
  caseId?: string;
  connectionId?: string;
}

const ERROR_WORDS: Record<string, [string, string]> = {
  vendor_permission: ['Permissions', 'The vendor refused the request for missing permissions. No change was applied.'],
  vendor_auth: ['Authentication', 'The vendor rejected the connection credentials. No change was applied.'],
  vendor_5xx: ['Vendor error', 'The vendor returned a server error after the retry budget.'],
  vendor_4xx: ['Vendor rejected the request', 'The vendor refused the request as invalid. No change was applied.'],
  step_timeout: ['Step timeout', 'A step exceeded the 15-minute active step limit.'],
  run_deadline: ['Run deadline', 'The run exceeded its wall-clock limit.'],
  action_admission_timeout: ['Admission timeout', 'The action could not be admitted in time.'],
  lease_recovered: ['Executor restarted', 'The executor lost its lease mid-step.'],
  approval_attempt_cap: ['Approval attempts exhausted', 'The approval gate reached its attempt cap.'],
  rate_limited: ['Rate limited', 'The connection hit its per-minute or per-day budget.'],
  soar_disabled: ['SOAR disabled', 'SOAR was turned off while the run was in flight.'],
};

function errorWords(errorClass: string | null): [string, string] {
  if (!errorClass) return ['Failed', 'The run failed.'];
  return ERROR_WORDS[errorClass] ?? [errorClass.replace(/_/g, ' '), `The run failed with ${errorClass}.`];
}

function compact(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const s = JSON.stringify(value);
  if (!s || s === '{}' || s === 'null') return null;
  return s.length <= 90 ? s.replace(/[{}"]/g, '').replace(/,/g, ' · ').replace(/:/g, ' ') : null;
}

/** Method/URL/headers lines from a server-redacted request summary. */
function requestText(req: unknown, runId: string): string | null {
  if (!req || typeof req !== 'object') return null;
  const r = req as { method?: string; url?: string; headers?: Record<string, unknown>; body?: unknown };
  const lines = [`${r.method ?? 'POST'} ${r.url ?? '…'}`];
  for (const [k, v] of Object.entries(r.headers ?? {})) lines.push(`${k}: ${String(v).replace('[redacted]', '‹redacted›')}`);
  lines.push(`x-nano-run: ${runId}`);
  if (r.body !== undefined) lines.push('body: ‹redacted›');
  return lines.join('\n');
}

function spanNote(s: TraceSpan): string {
  if (s.kind === 'none') return 'not started';
  return s.note ?? '';
}

export function RunTraceView({
  run,
  index,
  tenant,
  demo,
  flows,
  onRequestAction,
}: {
  run: SoarRunDetail;
  index: Map<string, IndexedAction>;
  tenant: string;
  demo: boolean;
  flows?: SoarFlow[];
  /** Opens the run-action sheet (inverse / verified retry). */
  onRequestAction?: (preset: RunActionPreset) => void;
}) {
  const { user, hasPermission } = useAuth();
  const client = useQueryClient();
  const drawer = useApprovalsDrawer();
  const [confirmCancel, setConfirmCancel] = useState(false);
  const now = Date.now();
  const view = runView(run, index, { me: user?.id, flows, steps: run.steps, now });
  const { spans, total } = useMemo(() => traceSpans(run, view, index, now), [run, view.flow, index]); // eslint-disable-line react-hooks/exhaustive-deps
  const firstEffect = spans.findIndex((s) => s.effect && s.effect !== 'read');
  // null = automatic: the first effectful span (else the last), recomputed as data arrives.
  const [picked, setSelSpan] = useState<number | null>(null);
  const selSpan = picked ?? (firstEffect >= 0 ? firstEffect : spans.length - 1);
  const sp = spans[selSpan] ?? spans[spans.length - 1];
  const connections = useConnections(tenant, !demo);
  const conn = connections.data?.connections.find((c) => c.id === (sp?.connection ?? run.connection_id))
    ?? connections.data?.connections.find((c) => c.id === run.connection_id);
  const approvals = run.approvals ?? [];
  const pendingApproval = approvals.find((a) => a.status === 'pending');
  const canRun = hasPermission('soar:run');
  const cancellable = !demo && !isTerminal(run.status);
  const outKey = view.okey;
  const inputs = (run.inputs && typeof run.inputs === 'object' ? run.inputs : {}) as Record<string, unknown>;
  const strInputs = Object.fromEntries(Object.entries(inputs).filter(([, v]) => typeof v === 'string' || typeof v === 'number').map(([k, v]) => [k, String(v)]));

  const cancel = useMutation({
    mutationFn: () => api.soar.cancelRun(run.id),
    onSuccess: () => { setConfirmCancel(false); void invalidateSoar(client, tenant); },
  });

  const ticks = 6;
  const [errTitle, errBody] = errorWords(run.error_class);

  return (
    <div className="relative flex min-h-0 flex-1 flex-col" data-testid="run-trace">
      <div className="min-h-0 flex-1 overflow-auto">
        <div className="flex flex-wrap items-center gap-3 px-5 pb-3 pt-4">
          {run.action ? (
            <ActionChip
              e={view.effect}
              verb={view.verb}
              t={view.target?.kind}
              v={view.target ? shortTarget(view.target.value) : undefined}
              p={run.pack_name}
              vendor={view.vendor}
              inv={!!view.inverse}
            />
          ) : (
            <span className="flex items-center gap-2 text-[13px] font-medium text-foreground">
              <Workflow className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.5} />
              {view.name}
              <Mono className="text-[11px] text-muted-foreground">flow v{run.flow_version ?? '—'}</Mono>
            </span>
          )}
          <Origin o={view.origin} who={view.who} size={16} />
          {run.dry_run && <span className="rounded-[3px] border border-border-2 px-1.5 font-mono text-[10px] text-muted-foreground">dry run</span>}
          <span className="flex-1" />
          <Outcome s={outKey} label={outKey === 'ok' ? 'Succeeded' : outKey === 'rej' ? 'Canceled' : run.status === 'timed_out' ? 'Timed out' : undefined} />
          {cancellable && (
            <GatedButton allowed={canRun} why="Requires soar:run" size="sm" variant="outline" className={xsButton} onClick={() => setConfirmCancel(true)}>
              Cancel run
            </GatedButton>
          )}
          {!demo && view.inverse && run.status === 'succeeded' && run.action && view.action?.rollback && onRequestAction && (
            <GatedButton
              allowed={canRun}
              why="Requires soar:run"
              size="sm"
              variant="outline"
              className={xsButton}
              onClick={() => onRequestAction({ pack: run.pack_name!, action: view.action!.rollback!, inputs: strInputs, caseId: run.case_id ?? undefined, connectionId: run.connection_id ?? undefined })}
            >
              ↺ {view.inverse}
            </GatedButton>
          )}
        </div>

        <div className="flex flex-col gap-2.5 px-5">
          {run.status === 'suspended' &&
            (pendingApproval ? (
              <ApprovalCard key={pendingApproval.id + pendingApproval.status} approval={pendingApproval} index={index} tenant={tenant} demo={demo} showCase caseId={run.case_id} caseNumber={run.case_number} showRunLink={false} flow={view.flow ? { name: view.flow.name, version: run.flow_version } : null} />
            ) : (
              <Banner tone="warn" icon={<Hand strokeWidth={1.5} />} title="Waiting on a human">
                The run is suspended at a gate. Pending approvals appear here when you can see them.
              </Banner>
            ))}
          {run.status === 'queued' && (
            <Banner tone="neutral" icon={<Clock strokeWidth={1.5} />} title="Queued">
              {run.executor_pending ? 'Accepted. Waiting for an executor; acceptance does not mean success.' : 'Accepted. Not started yet; acceptance does not mean success.'}
            </Banner>
          )}
          {run.status === 'canceled' && outKey !== 'amb' && (
            <Banner tone="neutral" icon={<Ban strokeWidth={1.5} />} title="Canceled">
              Canceled before completion. Requests already sent to a vendor are not undone.
            </Banner>
          )}
          {outKey === 'amb' && (
            <Banner
              tone="warn"
              title="Unknown outcome · verify target"
              action={
                !demo && run.action && onRequestAction ? (
                  <GatedButton
                    allowed={canRun}
                    why="Requires soar:run"
                    size="sm"
                    variant="outline"
                    className={xsButton}
                    onClick={() => onRequestAction({ pack: run.pack_name!, action: run.action!, inputs: strInputs, caseId: run.case_id ?? undefined, connectionId: run.connection_id ?? undefined })}
                  >
                    Request verified retry
                  </GatedButton>
                ) : undefined
              }
            >
              The vendor may already have applied this action. Verify the target before approving a retry. A retry is a new approval, not a button.
            </Banner>
          )}
          {(run.status === 'failed' || run.status === 'timed_out') && outKey !== 'amb' && (
            <Banner tone="danger" title={errTitle}>
              {errBody} <Mono className="text-[10.5px] text-muted-foreground">{run.error_class ?? ''}</Mono>
            </Banner>
          )}
          {cancel.isError && <Banner tone="danger" title="Could not cancel">{effectErrorMessage(cancel.error, 'The run could not be canceled.')}</Banner>}
        </div>

        <div className="mt-3">
          <div className="grid h-6 grid-cols-[150px_minmax(0,1fr)] border-y border-border font-mono text-[9.5px] text-fg-4 sm:grid-cols-[170px_minmax(0,1fr)] xl:grid-cols-[230px_minmax(0,1fr)]">
            <span className="flex items-center truncate px-5">{shortId(run.id)} · {utcTime(run.started_at ?? run.created_at).slice(0, 5)} UTC</span>
            <div className="flex items-center justify-between whitespace-nowrap pr-3">
              {Array.from({ length: ticks }).map((_, i) => <span key={i} className={cn(i % 2 === 1 && 'hidden sm:inline')}>+{fmtS((total / (ticks - 1)) * i)}</span>)}
            </div>
          </div>
          {spans.map((s, i) => {
            const right = (s.start + s.dur) / total > 0.6;
            return (
              <button
                key={s.key + i}
                type="button"
                onClick={() => setSelSpan(i)}
                aria-pressed={selSpan === i}
                className={cn(
                  'grid h-9 w-full grid-cols-[150px_minmax(0,1fr)] items-center border-b border-border text-left sm:grid-cols-[170px_minmax(0,1fr)] xl:grid-cols-[230px_minmax(0,1fr)]',
                  selSpan === i ? 'bg-primary/[0.06]' : 'hover:bg-foreground/[0.02]',
                )}
                data-testid="trace-span"
              >
                <div className="flex min-w-0 items-center gap-2 px-5 text-[11.5px]">
                  {s.effect && s.effect !== 'read' ? <EffMark e={s.effect} size={9} /> : <span className="w-[9px] shrink-0" />}
                  <span className={cn('truncate', s.kind === 'none' ? 'text-muted-foreground' : 'text-foreground')}>{s.name}</span>
                </div>
                <div className="relative mr-3 h-full">
                  {s.kind === 'none' ? (
                    <div className="absolute top-1/2 h-3 -translate-y-1/2 rounded-[2px] border border-dashed border-fg-4" style={{ left: `min(${(s.start / total) * 100}%, calc(100% - 28px))`, width: 28 }} />
                  ) : (
                    <div className="absolute top-1/2 h-3 -translate-y-1/2 rounded-[2px]" style={{ left: `${(s.start / total) * 100}%`, width: `max(3px, ${(s.dur / total) * 100}%)`, ...SPAN_BG[s.kind] }} />
                  )}
                  <span
                    className={cn(
                      'absolute top-1/2 hidden -translate-y-1/2 whitespace-nowrap font-mono text-[10px] sm:block',
                      s.kind === 'ok' || s.kind === 'queue' ? 'text-muted-foreground' : 'text-fg-2',
                      right && s.start / total < 0.3 && 'rounded-[2px] bg-background/90 px-1',
                    )}
                    style={right && s.start / total < 0.3
                      ? { left: `calc(${(s.start / total) * 100}% + 6px)` }
                      : right || (s.kind === 'none' && s.start / total > 0.6)
                        ? { right: `calc(${100 - (s.start / total) * 100}% + 6px)` }
                        : { left: `calc(${((s.start + s.dur) / total) * 100}% + ${s.kind === 'none' ? 34 : 6}px)` }}
                  >
                    {spanNote(s)}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {sp && (
          <div className="grid grid-cols-1 gap-5 px-5 py-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <div className="flex min-w-0 flex-col gap-3">
              <div>
                <H>Span</H>
                <div className="mt-1 flex items-center gap-2">
                  {sp.effect && <EffMark e={sp.effect} size={10} />}
                  <span className="text-[13px] font-semibold text-foreground">{sp.name}</span>
                </div>
                <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">
                  {sp.at ? `${utcTime(sp.at)} · ` : ''}
                  {sp.kind === 'none' ? '0ms' : formatDuration(sp.dur)}
                  {sp.attempts > 1 ? ` · ${sp.attempts} attempts` : ''}
                </div>
              </div>
              {sp.kind === 'none' && <div className="text-[11.5px] text-muted-foreground">Not started.</div>}
              {sp.policy === 'auto' && sp.effect && sp.effect !== 'read' && sp.kind !== 'none' && <div className="text-[11.5px] text-fg-2">auto-approved by step policy</div>}
              {sp.policy === 'required' && <div className="text-[11.5px] text-fg-2">approval required by step policy</div>}
              {sp.kind === 'wait' && sp.approval && (
                <div className="text-[11.5px] text-fg-2">
                  {sp.approval.status === 'pending' ? `Pending · 1 approver with soar:approve required${sp.step?.deadline_at ? ` · deadline ${utcTime(sp.step.deadline_at).slice(0, 5)} UTC` : ''}` : `${sp.approval.status === 'approved' ? 'Approved' : 'Decided'} by ${actorLabel(sp.approval.decided_by, user?.id, sp.approval.decided_by_name)}`}
                </div>
              )}
              {sp.kind === 'poll' && (
                <div className="flex items-center gap-2 text-[11.5px] text-fg-2">
                  <Spinner className="h-3 w-3 text-primary" />
                  Polling · attempt {sp.step?.attempt ?? 1}
                  {sp.poll && (
                    <Mono className="text-muted-foreground">
                      every {fmtS(sp.poll.interval_secs * 1000)}
                      {sp.step && <> · deadline {utcTime(new Date(sp.step.started_at_ms + sp.poll.max_secs * 1000).toISOString()).slice(0, 5)} UTC</>}
                    </Mono>
                  )}
                </div>
              )}
              {sp.kind === 'amb' && <div className="text-[11.5px] text-fg-2"><Mono className="mr-2 text-muted-foreground">attempt {sp.attempts}</Mono>Sent · the connection closed before the vendor responded. The vendor may have applied the change.</div>}
              {sp.kind === 'fail' && sp.step?.error_class && <div className="text-[11.5px] text-fg-2"><Mono className="mr-2 text-muted-foreground">attempt {sp.attempts}</Mono>{sp.step.error_class.replace(/_/g, ' ')}</div>}
              {sp.step?.skip_reason && <div className="text-[11.5px] text-fg-2">{sp.step.skip_reason}</div>}
              {sp.step?.output_is_placeholder && (
                <div className="text-[11.5px] text-warn italic">
                  Dry-run placeholder · no vendor call was made{sp.step.placeholder_inputs.length > 0 && <> · placeholder inputs <Mono>{sp.step.placeholder_inputs.join(', ')}</Mono></>}
                </div>
              )}
              {sp.iterations.length > 0 && (
                <div className="flex flex-col gap-1">
                  {sp.iterations.map((it, j) => (
                    <div key={it.id} className="flex gap-3 text-[11px]">
                      <Mono className="w-5 text-[11px] text-muted-foreground">#{typeof it.iteration === 'number' ? it.iteration + 1 : j + 1}</Mono>
                      <Mono className="flex-1 text-[11px] text-foreground">{compact(it.outputs) ?? it.module_id}</Mono>
                      <span className="text-fg-2">{it.status === 'succeeded' ? 'done' : it.status.replace(/_/g, ' ')}{it.attempt > 1 ? ` · ${it.attempt} attempts` : ''} · {formatDuration((it.finished_at_ms ?? now) - it.started_at_ms)}</span>
                    </div>
                  ))}
                </div>
              )}
              {sp.step && sp.iterations.length === 0 && compact(sp.step.outputs) && (
                <div className="text-[11.5px] text-fg-2">→ <Mono>{compact(sp.step.outputs)}</Mono></div>
              )}
              {sp.step && sp.iterations.length === 0 && sp.step.outputs != null && !compact(sp.step.outputs) && (
                <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{JSON.stringify(sp.step.outputs, null, 2)}</pre>
              )}
              {sp.effect && sp.effect !== 'read' && (
                <div>
                  <H className="mb-1.5">Request · redacted</H>
                  <pre className="whitespace-pre-wrap break-all rounded-md border border-border px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">
                    {requestText(sp.step?.rendered_request, shortId(run.id)) ?? (sp.kind === 'none' ? 'Not sent yet.' : 'No request summary recorded.')}
                  </pre>
                  <div className="mt-1 text-[10.5px] text-muted-foreground">Unredacted vendor payloads are not downloadable.</div>
                </div>
              )}
              {sp.effect === 'read' && sp.step?.rendered_request !== undefined && (
                <div>
                  <H className="mb-1.5">Request · redacted</H>
                  <pre className="whitespace-pre-wrap break-all rounded-md border border-border px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{requestText(sp.step.rendered_request, shortId(run.id))}</pre>
                </div>
              )}
            </div>
            <div className="flex min-w-0 flex-col gap-3">
              <KV
                rows={[
                  ['Connection', conn ? conn.label : run.connection_id ? <Mono>{shortId(run.connection_id)}</Mono> : '—'],
                  ['Case', run.case_id ? <Link to={`/cases/${run.case_id}`} className="font-mono text-primary hover:underline">{caseLabel(run.case_id, run.case_number)}</Link> : '—'],
                  ['Started', <Mono>{utcTime(run.started_at ?? run.created_at)} UTC</Mono>],
                  ['Duration', <Mono>{view.duration}</Mono>],
                  ['Requested by', <span title={run.requested_by ?? undefined}>{view.who}</span>],
                  // NAN-4544: distinct step targets that were actually sent to.
                  ['Affected entities', run.affected_entities != null ? <Mono>{run.affected_entities}</Mono> : '—'],
                  run.flow_id ? ['Flow', <Link to={`/automation/flows/${run.flow_id}`} className="font-mono text-primary hover:underline">{view.flow?.name ?? shortId(run.flow_id)} v{run.flow_version}</Link>] : null,
                ]}
              />
              <div>
                <H className="mb-1.5">Approvals</H>
                {approvals.length === 0 ? (
                  <div className="text-[11px] text-muted-foreground">None on this run.</div>
                ) : (
                  approvals.map((a) => (
                    <button key={a.id} type="button" onClick={() => drawer.openDrawer(a.id)} className="flex w-full items-center gap-2 py-0.5 text-left text-[11.5px]">
                      <Mono className="text-primary">{shortId(a.id)}</Mono>
                      <StatusPill s={a.status} className="text-[11px]" />
                      {a.decided_by && <span className="text-muted-foreground">{actorLabel(a.decided_by, user?.id, a.decided_by_name)} · {utcTime(a.decided_at)}</span>}
                    </button>
                  ))
                )}
              </div>
              <details className="group">
                <summary className="flex cursor-pointer list-none items-center gap-1.5 text-muted-foreground hover:text-foreground">
                  <ChevronDown className="h-3 w-3 -rotate-90 transition-transform group-open:rotate-0" strokeWidth={1.5} />
                  <H>Audit · {2 + approvals.length + approvals.filter((a) => a.decided_at).length} events</H>
                </summary>
                {/* Audit event IDs are not in the run DTO (NAN-4556); these are the recorded transitions. */}
                <div className="mt-1.5 flex flex-col gap-0.5 font-mono text-[10.5px] text-fg-2">
                  <span>{utcTime(run.created_at)} run.requested</span>
                  {approvals.map((a) => <span key={a.id}>{utcTime(a.created_at)} approval.requested</span>)}
                  {approvals.filter((a) => a.decided_at).map((a) => <span key={a.id + 'd'}>{utcTime(a.decided_at)} approval.{a.status}</span>)}
                  <span>{utcTime(run.finished_at ?? run.started_at ?? run.created_at)} run.state_changed · {run.status}</span>
                </div>
              </details>
              {run.outputs !== null && run.outputs !== undefined && (
                <div>
                  <H className="mb-1.5">Run outputs</H>
                  <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{JSON.stringify(run.outputs, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        variant="warning"
        title={`Cancel ${shortId(run.id)}?`}
        description="Remaining steps will not start. Cancellation cannot undo a request already sent to a vendor."
        confirmLabel="Cancel run"
        cancelLabel="Keep running"
        onConfirm={() => cancel.mutate()}
      />
    </div>
  );
}

/** Loads one run and renders its trace with loading / missing / error states. */
export function RunTrace({
  id,
  index,
  tenant,
  demo,
  flows,
  onRequestAction,
}: {
  id: string;
  index: Map<string, IndexedAction>;
  tenant: string;
  demo: boolean;
  flows?: SoarFlow[];
  onRequestAction?: (preset: RunActionPreset) => void;
}) {
  const query = useRun(tenant, id, true);
  if (query.isPending) return <ListState state="loading" />;
  if (query.isError) {
    return errorStatus(query.error) === 404 ? (
      <ListState state="empty" title="Run not found" body="It may belong to a case you cannot read, or it no longer exists." />
    ) : (
      <ListState state="error" title="Could not load this run" onRetry={() => void query.refetch()} />
    );
  }
  return <RunTraceView key={query.data.id + query.data.status} run={query.data} index={index} tenant={tenant} demo={demo} flows={flows} onRequestAction={onRequestAction} />;
}
