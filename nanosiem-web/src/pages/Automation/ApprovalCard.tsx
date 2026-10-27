// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the decision card (mock soar3-gate.jsx ApprovalCard). One card
 * serves the run trace, the approvals drawer and the case pane. It reads only
 * immutable server fields and posts to the approve/reject routes, which
 * enforce a human session, `soar:approve`, self-approval refusal, expiry and
 * case privacy. Destructive approvals use hold-to-approve.
 *
 * Unsubmitted reason text stays in component state; it is never persisted.
 */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Lock } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarApproval } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import {
  REASON_MAX_BYTES,
  approvalOptions,
  asEffect,
  caseLabel,
  decisionBlock,
  inputTargets,
  lookupAction,
  minutesLeft,
  reasonRequired,
  shortId,
  utcDateTime,
  utcTime,
  utf8Bytes,
  verbOf,
  type IndexedAction,
} from './soar-model';
import { EFF_TXT, EffMark, Entity, HoldButton, KV, Mono, Origin, Ring, Spinner, StatusPill, Vendor, originOf, smallButton } from './soar-kit';
import { effectErrorMessage, errorStatus, invalidateSoar, useConnections } from './soar-queries';
import { actorLabel, blockWords, shortTarget } from './run-view';

const LOST_RACE = 'Another approver decided first, or the request expired. Your decision was not recorded.';

/** NAN-4556: "u_achen rejected at 14:21 UTC first. …" from the refetched approval. */
export function lostRaceText(latest: SoarApproval, me: string | undefined): string | null {
  if (latest.status === 'pending') return null;
  if (latest.status === 'expired') return 'The request expired before your decision. Your decision was not recorded.';
  if (latest.status === 'canceled') return 'The run was canceled before your decision. Your decision was not recorded.';
  if (!latest.decided_by) return null;
  const at = latest.decided_at ? ` at ${utcTime(latest.decided_at).slice(0, 5)} UTC` : '';
  return `${actorLabel(latest.decided_by, me, latest.decided_by_name)} ${latest.status}${at} first. Your decision was not recorded.`;
}

/** Requester wording, mock style ("pivt · on behalf of M. Okafor"). */
export function requesterWho(approval: SoarApproval, me: string | undefined, flow?: { name: string; version?: number | null } | null): string {
  const who = actorLabel(approval.requested_by, me, approval.requested_by_name);
  const src = approval.requested_source;
  if (src === 'ai' || src === 'pivt') return `pivt · ${who}`;
  if (src === 'flow' || src === 'trigger' || src === 'playbook') {
    if (flow) return `Flow · ${flow.name}${flow.version ? ` v${flow.version}` : ''}`;
    return approval.requested_by && approval.requested_by !== 'system' ? `Flow · ${who}` : 'Flow';
  }
  return who;
}

export function ApprovalCard({
  approval,
  index,
  tenant,
  demo,
  showRunLink = true,
  showCase = false,
  flat = false,
  highlight = false,
  caseId: caseIdProp,
  caseNumber: caseNumberProp,
  flow,
  now = Date.now(),
}: {
  approval: SoarApproval;
  index: Map<string, IndexedAction>;
  tenant: string;
  demo: boolean;
  showRunLink?: boolean;
  /** Show the case link in the header (inbox / run trace). */
  showCase?: boolean;
  /** Borderless, for nesting inside a list row. */
  flat?: boolean;
  highlight?: boolean;
  /** The run's case, when known. The approval's own `case_id` (NAN-4556) wins. */
  caseId?: string | null;
  caseNumber?: number | null;
  /** The requesting flow, when known, for "Flow · name vN". */
  flow?: { name: string; version?: number | null } | null;
  now?: number;
}) {
  const { user, hasPermission } = useAuth();
  const client = useQueryClient();
  const caseId = approval.case_id ?? caseIdProp ?? null;
  const caseNumber = approval.case_number ?? caseNumberProp ?? null;
  const request = approval.requested_action ?? {};
  const found = lookupAction(index, request.pack, request.action);
  const effect = asEffect(found?.action.effect);
  const options = approvalOptions(approval);
  const [choice, setChoice] = useState<string | undefined>(options.length === 1 ? options[0] : undefined);
  const [reason, setReason] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [conflict, setConflict] = useState<string | null>(null);
  const connections = useConnections(tenant, !demo);
  const conn = connections.data?.connections.find((c) => c.id === request.connection_id);
  const block = decisionBlock(approval, { userId: user?.id, canApprove: hasPermission('soar:approve'), demo, now });
  const needsReason = reasonRequired(approval, choice);
  const bytes = utf8Bytes(reason.trim());
  const tooLong = bytes > REASON_MAX_BYTES;
  const target = inputTargets(request.inputs, found?.action, 1)[0];
  const verb = request.action ? verbOf(request.action, found?.action.display_name) : request.prompt || 'Approval';
  const source = originOf(approval.requested_source);
  const pending = approval.status === 'pending';
  const left = minutesLeft(approval.expires_at, now);
  const inverse = found?.action.rollback
    ? index.get(`${request.pack}.${found.action.rollback}`)?.action.display_name ?? verbOf(found.action.rollback)
    : null;

  const decide = useMutation({
    mutationFn: (kind: 'approve' | 'reject') =>
      kind === 'approve'
        ? api.soar.approve(approval.id, {
            ...(options.length > 0 ? { choice } : {}),
            ...(reason.trim() ? { reason: reason.trim() } : {}),
          })
        : api.soar.reject(approval.id, reason.trim() ? { reason: reason.trim() } : {}),
    onMutate: () => setConflict(null),
    onSuccess: () => {
      setReason('');
      void invalidateSoar(client, tenant);
    },
    onError: (error) => {
      if (errorStatus(error) === 409) {
        setConflict(LOST_RACE);
        // Name who decided first when the approval says so; otherwise keep the generic text.
        void Promise.resolve()
          .then(() => api.soar.getApproval(approval.id))
          .then((latest) => {
            const first = latest ? lostRaceText(latest, user?.id) : null;
            if (first) setConflict(first);
          })
          .catch(() => undefined);
        void invalidateSoar(client, tenant);
      }
    },
  });

  const reject = () => {
    if (!reason.trim()) {
      setErr('A reason is required to reject.');
      return;
    }
    decide.mutate('reject');
  };
  const approveDisabled = decide.isPending || tooLong || (options.length > 0 && !choice) || (needsReason && !reason.trim());
  const targetText = target ? shortTarget(target.value) : '';
  const inputs = request.inputs && typeof request.inputs === 'object' ? Object.entries(request.inputs as Record<string, unknown>) : [];

  return (
    <div
      id={`apr-${approval.id}`}
      className={cn(
        'bg-card',
        !flat && 'rounded-lg border',
        !flat && (highlight ? 'border-foreground' : !pending ? 'border-border' : effect === 'destructive' ? 'border-destructive/40' : 'border-warning/40'),
      )}
      data-testid="approval-card"
    >
      <div className="flex items-start gap-3 px-3.5 pb-2.5 pt-3">
        {pending && (
          <div className="flex shrink-0 flex-col items-center gap-1">
            <Ring left={left} size={34} total={Math.max(1, (Date.parse(approval.expires_at) - Date.parse(approval.created_at)) / 60_000)} />
            <span className="whitespace-nowrap font-mono text-[9.5px] text-muted-foreground">{utcTime(approval.expires_at).slice(0, 5)}</span>
          </div>
        )}
        <div className="flex min-w-0 flex-1 flex-col gap-1.5">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
            <span className="max-w-full overflow-hidden whitespace-nowrap"><Origin o={source} who={requesterWho(approval, user?.id, flow)} size={14} /></span>
            <span className="whitespace-nowrap">requested · {utcTime(approval.created_at).slice(0, 5)} UTC</span>
            {showCase && <CaseRef caseId={caseId} number={caseNumber} />}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <EffMark e={effect} size={10} />
            <span className={cn('shrink-0 whitespace-nowrap text-[13px] font-medium', effect ? EFF_TXT[effect] : 'text-foreground')}>{verb}</span>
            {target && <Entity t={target.kind} v={targetText} size="sm" title={target.value} />}
            {request.pack && <Vendor p={request.pack} label={found?.pack.display_name} size={16} />}
            {conn && <span className="truncate text-[11px] text-muted-foreground">{conn.label}</span>}
          </div>
        </div>
        {!pending && <StatusPill s={approval.status} className="pt-0.5" />}
      </div>

      <div className="flex flex-col gap-2 px-3.5 pb-3">
        {request.prompt && request.action && <div className="text-[12px] leading-[1.55] text-foreground">{request.prompt}</div>}
        {/* Blast radius and target context are not in the DTO (NAN-4555); the mock falls back to the action description. */}
        {(found?.action.description || (!request.action && request.prompt)) && (
          <div className="text-[12px] leading-[1.55] text-fg-2">{found?.action.description || request.prompt}</div>
        )}
        <div className="text-[11px] text-muted-foreground">
          {inverse ? (
            <>↺ Reversible with <span className="text-fg-2">{inverse}</span>, as a separate approved run.</>
          ) : effect && effect !== 'read' ? (
            'No inverse action. Cannot be undone from nano.'
          ) : null}
        </div>
        {(approval.ambiguous || request.ambiguous) && (
          <div className="text-[11.5px] text-warn">Prior attempt may already have applied. Verify the target first.</div>
        )}
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex items-center gap-1 self-start whitespace-nowrap font-mono text-[10.5px] text-muted-foreground hover:text-foreground"
        >
          <ChevronDown className={cn('h-3 w-3 transition-transform', !open && '-rotate-90')} strokeWidth={1.5} />
          {source === 'pivt' ? 'why pivt asked' : 'request'} · inputs
        </button>
        {open && (
          <div className="flex flex-col gap-2 rounded-md border border-border bg-background px-3 py-2.5">
            <KV
              keyWidth={110}
              rows={[
                ...inputs.map(([k, v]) => [<Mono className="text-muted-foreground">{k}</Mono>, <Mono className="break-all">{typeof v === 'string' ? v : JSON.stringify(v)}</Mono>] as [React.ReactNode, React.ReactNode]),
                request.pack ? ['Pack', <Mono>{request.pack}{request.version ? ` ${request.version}` : ''}</Mono>] : null,
                ['Step', <Mono>{approval.module_id}</Mono>],
                showRunLink
                  ? ['Run', <Link to={`/automation/runs/${approval.run_id}`} className="font-mono text-[11.5px] text-primary hover:underline">{shortId(approval.run_id)}</Link>]
                  : null,
                ['Approval', <Mono>{shortId(approval.id)}</Mono>],
                ['Expires', <Mono>{utcDateTime(approval.expires_at)}</Mono>],
              ]}
            />
            {request.rendered !== undefined && (
              <div>
                <div className="mb-1 text-[10.5px] text-muted-foreground">Preview · redacted by the server</div>
                <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[10.5px] leading-[1.6] text-fg-2">{JSON.stringify(request.rendered, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t border-border px-3.5 py-2.5">
        {conflict ? (
          <span className="flex-1 text-[12px] text-fg-2" role="status">{conflict}</span>
        ) : !pending ? (
          <span className="min-w-0 flex-1 truncate text-[11.5px] text-muted-foreground">
            {approval.decided_by ? actorLabel(approval.decided_by, user?.id, approval.decided_by_name) : ''}
            {approval.decided_at ? <span className="font-mono"> · {utcTime(approval.decided_at)}</span> : null}
            {typeof approval.choice === 'string' && approval.choice !== 'approve' && approval.choice !== 'reject' ? <> · chose <span className="font-mono">{approval.choice}</span></> : null}
            {approval.reason ? ` · “${approval.reason}”` : ''}
          </span>
        ) : block ? (
          <span className="flex flex-1 items-center gap-2 text-[11.5px] text-fg-2">
            <Lock className="h-3.5 w-3.5 shrink-0 text-muted-foreground" strokeWidth={1.5} />
            <span title={blockWords(block, approval).long}>{block}</span>
          </span>
        ) : (
          <>
            {options.length > 0 && (
              <div className="flex flex-wrap items-center gap-1" role="radiogroup" aria-label="Decision option">
                {options.map((o) => (
                  <button
                    key={o}
                    type="button"
                    role="radio"
                    aria-checked={choice === o}
                    onClick={() => setChoice(o)}
                    className={cn('h-8 rounded-md border px-2 font-mono text-[11px]', choice === o ? 'border-primary bg-primary/10 text-primary' : 'border-border-2 text-fg-2 hover:text-foreground')}
                  >
                    {o}
                  </button>
                ))}
              </div>
            )}
            <div className="flex min-w-[200px] flex-1 flex-col">
              <input
                aria-label="Decision reason"
                value={reason}
                onChange={(e) => { setReason(e.target.value); setErr(null); }}
                placeholder={needsReason ? 'Reason · required for this choice' : 'Reason · required to reject'}
                disabled={decide.isPending}
                className={cn(
                  'h-8 rounded-md border bg-background px-2.5 text-[12px] text-foreground placeholder:text-fg-4 focus:outline-none focus:ring-1 focus:ring-ring',
                  err || tooLong ? 'border-destructive/60' : 'border-border-2',
                )}
              />
              {err && <span className="mt-0.5 text-[10.5px] text-destructive">{err}</span>}
              {tooLong && <span className="mt-0.5 font-mono text-[10.5px] text-destructive">{bytes} / {REASON_MAX_BYTES} bytes</span>}
            </div>
            <Button size="sm" variant="outline" className="h-8 shadow-none" disabled={decide.isPending || tooLong} onClick={reject}>
              {decide.isPending && decide.variables === 'reject' ? <><Spinner />Rejecting…</> : 'Reject'}
            </Button>
            {effect === 'destructive' ? (
              decide.isPending && decide.variables === 'approve' ? (
                <Button size="sm" variant="destructive" className="h-8 shadow-none" disabled><Spinner />Approving…</Button>
              ) : (
                <HoldButton
                  label={`Hold to approve · ${verb}${targetText ? ` ${targetText}` : ''}`}
                  disabled={approveDisabled}
                  onDone={() => decide.mutate('approve')}
                />
              )
            ) : (
              <Button size="sm" className="h-8 shadow-none" disabled={approveDisabled} onClick={() => decide.mutate('approve')}>
                {decide.isPending && decide.variables === 'approve' ? <><Spinner />Approving…</> : 'Approve'}
              </Button>
            )}
          </>
        )}
        {showRunLink && (!pending || conflict) && (
          <Button asChild size="sm" variant="outline" className={smallButton}>
            <Link to={`/automation/runs/${approval.run_id}`}>Open run</Link>
          </Button>
        )}
      </div>
      {decide.isError && errorStatus(decide.error) !== 409 && (
        <p role="alert" className="border-t border-border px-3.5 py-2 text-[11.5px] text-destructive">
          {effectErrorMessage(decide.error, 'The decision could not be recorded.')}
        </p>
      )}
    </div>
  );
}

/** Case reference: CASE-n when the server sent the number (NAN-4556). */
function CaseRef({ caseId, number }: { caseId?: string | null; number?: number | null }) {
  if (!caseId) return <span className="shrink-0 whitespace-nowrap font-mono">no case</span>;
  return (
    <Link to={`/cases/${caseId}`} className="shrink-0 whitespace-nowrap font-mono text-primary hover:underline">
      {caseLabel(caseId, number)}
    </Link>
  );
}
