// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Credentials (NAN-2593, design §3.3): the tenant's ingest
 * credentials, each with its routes, and tenant self-revoke with a reason
 * (`nano_shared.revoke_tenant_ingest_credential`, ~5 s to take effect at the
 * edge). Rows never carry a secret.
 */

import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ChevronRight, KeyRound, ShieldOff } from 'lucide-react';

import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { IngestCredentialActivitySummary, TenantIngestCredential, TenantIngestCredentialRequest } from '@/lib/api/types';
import { INGEST_CREDENTIALS_QUERY_KEY, PROTOCOL_LABEL, tokenLost } from '@/lib/add-data-sources';
import { formatCompactNumber, formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import { rejectionHint } from '@/lib/first-event';
import { describeIngestCredentialError, describeRefusal, refusalCode } from '@/lib/ingest-credential-errors';
import { cn } from '@/lib/utils';

function shortTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace('T', ' ');
}

function StateBadge({ state }: { state: string }) {
  const tone =
    state === 'active' || state === 'issued'
      ? 'text-emerald-500 border-emerald-500/40'
      : state === 'pending'
        ? 'text-amber-500 border-amber-500/40'
        : state === 'rejected'
          ? 'text-red-500 border-red-500/40'
          : 'text-muted-foreground border-border';
  return <span className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[10px]', tone)}>{state}</span>;
}

function SlugChips({ slugs, implicitUnknown }: { slugs: string[]; implicitUnknown?: boolean }) {
  return (
    <span className="flex flex-wrap gap-1">
      {slugs.map((s) => (
        <span key={s} className="font-mono text-[10.5px] px-1.5 h-4 inline-flex items-center rounded-sm border border-border text-foreground/80">
          {s}
        </span>
      ))}
      {implicitUnknown && (
        <span
          className="font-mono text-[10.5px] px-1.5 h-4 inline-flex items-center rounded-sm border border-dashed border-border text-muted-foreground"
          title="Collector events that declare no source land as unknown (Unattributed)"
        >
          unknown
        </span>
      )}
    </span>
  );
}

/** NAN-2599 activity columns: last seen, events (24 h), last error. */
function ActivityCells({ activity, active }: { activity?: IngestCredentialActivitySummary | null; active: boolean }) {
  if (!activity) {
    return (
      <>
        <td className="px-2 font-mono text-[10.5px] text-muted-foreground">—</td>
        <td className="px-2 font-mono text-[10.5px] text-muted-foreground text-right">—</td>
        <td className="px-2 font-mono text-[10.5px] text-muted-foreground">—</td>
      </>
    );
  }
  const events = activity.edge_events_24h ?? activity.lake_events_24h;
  // A rejection older than the last accepted request is history, not a problem.
  const rejectedAt = activity.last_rejected_at ? new Date(activity.last_rejected_at).getTime() : null;
  const seenAt = activity.last_seen_at ? new Date(activity.last_seen_at).getTime() : null;
  const current = rejectedAt !== null && (seenAt === null || rejectedAt >= seenAt);
  const hint = activity.last_rejected_at ? rejectionHint(activity) : null;
  const redactedTitle = 'Hidden: this credential writes a source you are restricted from';
  return (
    <>
      <td className="px-2 font-mono text-[10.5px]" data-testid="credential-last-seen">
        {activity.last_seen_at ? (
          <span title={formatUTC(activity.last_seen_at)}>{formatRelativeCompact(activity.last_seen_at)}</span>
        ) : activity.redacted ? (
          <span className="text-muted-foreground" title={redactedTitle}>restricted</span>
        ) : (
          <span className="text-muted-foreground">{active ? 'never' : '—'}</span>
        )}
      </td>
      <td className="px-2 font-mono text-[10.5px] text-right tabular-nums" data-testid="credential-events-24h">
        {activity.redacted && events === 0 && activity.edge_events_24h === null ? (
          <span className="text-muted-foreground" title={redactedTitle}>—</span>
        ) : (
          <span title={`edge ${activity.edge_events_24h ?? '—'} · lake ${activity.lake_events_24h}`}>{formatCompactNumber(events)}</span>
        )}
        {activity.parse_failures_24h > 0 && (
          <span className="ml-1 text-amber-500" title={`${activity.parse_failures_24h} events failed to parse (24 h)`}>
            · {formatCompactNumber(activity.parse_failures_24h)} failed
          </span>
        )}
      </td>
      <td className="px-2 text-[10.5px] max-w-[200px]" data-testid="credential-last-error">
        {hint && activity.last_rejected_at ? (
          <span
            className={cn('inline-flex items-center gap-1 truncate font-mono', current ? 'text-red-500' : 'text-muted-foreground')}
            title={`${formatUTC(activity.last_rejected_at)}: ${hint.title}. ${hint.detail}`}
          >
            {current && <AlertTriangle className="w-3 h-3 shrink-0" strokeWidth={1.5} />}
            <span className="truncate">
              {activity.last_rejection_status ?? ''} {activity.last_rejection_class ?? ''}
            </span>
          </span>
        ) : (
          <span className="text-muted-foreground font-mono">—</span>
        )}
      </td>
    </>
  );
}

export function IngestCredentialsTable({
  credentials,
  requests,
  currentUserId,
  initialRevokeId,
}: {
  credentials: TenantIngestCredential[];
  requests: TenantIngestCredentialRequest[];
  currentUserId?: string;
  /** Open the revoke dialog for this credential once (deep link `?revoke=<id>`, NAN-2597). */
  initialRevokeId?: string | null;
}) {
  const { hasPermission } = useAuth();
  const canRevoke = hasPermission('log_sources:deploy');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [target, setTarget] = useState<TenantIngestCredential | null>(null);
  const [reason, setReason] = useState('');

  const revoke = useMutation({
    mutationFn: ({ credentialId, reason }: { credentialId: string; reason: string }) => api.revokeIngestCredential(credentialId, reason),
    onSuccess: (result, vars) => {
      toast({
        title: result.replayed ? 'Already revoked' : 'Credential revoked',
        description: `${vars.credentialId} stops authenticating within about 5 seconds.`,
      });
      void queryClient.invalidateQueries({ queryKey: INGEST_CREDENTIALS_QUERY_KEY });
    },
    onError: (err) => {
      const problem = describeIngestCredentialError(err);
      toast({ title: `Revoke failed: ${problem.title}`, description: problem.detail, variant: 'destructive' });
      void queryClient.invalidateQueries({ queryKey: INGEST_CREDENTIALS_QUERY_KEY });
    },
  });

  const openRequests = useMemo(
    () => requests.filter((r) => r.state === 'pending' || r.state === 'rejected'),
    [requests],
  );
  const deepLinked = useRef(false);
  useEffect(() => {
    if (deepLinked.current || !initialRevokeId || !canRevoke) return;
    const match = credentials.find((c) => c.credential_id === initialRevokeId && c.revocable);
    if (!match) return;
    deepLinked.current = true;
    setTarget(match);
    setExpanded(match.credential_id);
  }, [canRevoke, credentials, initialRevokeId]);
  const trimmedReason = reason.trim();
  const reasonValid = trimmedReason.length >= 1 && trimmedReason.length <= 256;
  const who = (id?: string | null) => (!id ? '—' : id === currentUserId ? 'you' : id);

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border overflow-hidden">
        <table className="w-full text-left" data-testid="ingest-credentials-table">
          <thead className="bg-card/60 border-b border-border">
            <tr className="h-7 text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
              <th className="w-6" />
              <th className="px-2 font-normal">Label</th>
              <th className="px-2 font-normal">Type</th>
              <th className="px-2 font-normal">Protocol</th>
              <th className="px-2 font-normal">Sources</th>
              <th className="px-2 font-normal">Issued</th>
              <th className="px-2 font-normal">Revealed</th>
              <th className="px-2 font-normal">Last seen</th>
              <th className="px-2 font-normal text-right">Events 24h</th>
              <th className="px-2 font-normal">Last error</th>
              <th className="px-2 font-normal">State</th>
              <th className="px-2 font-normal text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {credentials.length === 0 && (
              <tr>
                <td colSpan={12} className="px-3 py-6 text-center text-[11.5px] text-muted-foreground">
                  No ingest credentials yet. Issue one from Add data.
                </td>
              </tr>
            )}
            {credentials.map((c) => {
              const open = expanded === c.credential_id;
              const lost = tokenLost(c);
              return (
                <Fragment key={c.credential_id}>
                  <tr className={cn('h-7 border-b border-border/60 text-[12px]', c.state !== 'active' && 'text-muted-foreground')}>
                    <td className="pl-1.5">
                      <button
                        type="button"
                        aria-label={open ? `Hide routes for ${c.label}` : `Show routes for ${c.label}`}
                        aria-expanded={open}
                        onClick={() => setExpanded(open ? null : c.credential_id)}
                        className="w-5 h-5 inline-flex items-center justify-center rounded hover:bg-accent"
                      >
                        <ChevronRight className={cn('w-3 h-3 transition-transform', open && 'rotate-90')} strokeWidth={1.5} />
                      </button>
                    </td>
                    <td className="px-2 font-mono text-[11.5px] text-foreground truncate max-w-[220px]" title={c.label}>
                      {c.label}
                    </td>
                    <td className="px-2 font-mono text-[11px]">{c.kind}</td>
                    <td className="px-2 text-[11.5px]">{PROTOCOL_LABEL[c.protocol] ?? c.protocol}</td>
                    <td className="px-2"><SlugChips slugs={c.source_slugs} implicitUnknown={c.kind === 'collector'} /></td>
                    <td className="px-2 text-[11px]">
                      {c.request_id ? (
                        <span className="font-mono text-[10.5px]" title={c.requested_at ? formatUTC(c.requested_at) : undefined}>
                          {shortTime(c.requested_at ?? c.created_at)} · <span title={c.requested_by ?? undefined}>{who(c.requested_by)}</span>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">
                          <span className="font-mono text-[10.5px]">{shortTime(c.created_at)}</span> · issued on app.nano.rs
                        </span>
                      )}
                    </td>
                    <td className="px-2 font-mono text-[10.5px]">
                      {c.revealed_at ? shortTime(c.revealed_at) : c.request_id ? (
                        lost ? (
                          <span className="inline-flex items-center gap-1 text-amber-500" title="Issued but never revealed within 10 minutes; nobody holds this token. Revoke it.">
                            <AlertTriangle className="w-3 h-3" strokeWidth={1.5} /> never
                          </span>
                        ) : (
                          'not yet'
                        )
                      ) : (
                        '—'
                      )}
                    </td>
                    <ActivityCells activity={c.activity} active={c.state === 'active'} />
                    <td className="px-2"><StateBadge state={c.state} /></td>
                    <td className="px-2 text-right">
                      {c.revocable && canRevoke ? (
                        <button
                          type="button"
                          onClick={() => {
                            setTarget(c);
                            setReason(lost ? 'token never revealed' : '');
                          }}
                          className="inline-flex items-center gap-1 h-6 px-2 rounded border border-border text-[11px] text-red-500 hover:bg-red-500/10"
                        >
                          <ShieldOff className="w-3 h-3" strokeWidth={1.5} /> Revoke
                        </button>
                      ) : c.state === 'revoked' ? (
                        <span className="font-mono text-[10.5px] text-muted-foreground" title={c.revoked_at ? formatUTC(c.revoked_at) : undefined}>
                          {shortTime(c.revoked_at)}
                        </span>
                      ) : null}
                    </td>
                  </tr>
                  {open && (
                    <tr className="border-b border-border/60 bg-card/40">
                      <td />
                      <td colSpan={11} className="px-2 py-2">
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10.5px] font-mono text-muted-foreground mb-1.5">
                          <span>credential <span className="text-foreground/80">{c.credential_id}</span></span>
                          <span>cell <span className="text-foreground/80">{c.cell_name}</span></span>
                          {c.request_id && <span>request <span className="text-foreground/80">{c.request_id}</span></span>}
                        </div>
                        {c.kind === 'collector' && Object.keys(c.source_aliases ?? {}).length > 0 && (
                          <div className="flex flex-wrap items-center gap-1 mb-1.5 text-[10.5px]" data-testid={`aliases-${c.credential_id}`}>
                            <span className="font-mono text-muted-foreground/70 uppercase tracking-[0.1em] text-[9.5px] mr-1">Aliases</span>
                            {Object.entries(c.source_aliases ?? {}).map(([name, slug]) => (
                              <span key={name} className="font-mono px-1.5 h-4 inline-flex items-center rounded-sm border border-border text-foreground/80">
                                {name} → {slug}
                              </span>
                            ))}
                          </div>
                        )}
                        <table className="text-left" data-testid={`routes-${c.credential_id}`}>
                          <thead>
                            <tr className="h-6 text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
                              <th className="pr-4 font-normal">Route</th>
                              <th className="pr-4 font-normal">Source</th>
                              <th className="pr-4 font-normal">Revision</th>
                              <th className="font-normal">State</th>
                            </tr>
                          </thead>
                          <tbody>
                            {c.routes.map((r) => (
                              <tr key={r.route_id} className="h-6 font-mono text-[10.5px]">
                                <td className="pr-4 text-foreground/80">{r.route_id}</td>
                                <td className="pr-4 text-foreground">{r.source_slug}</td>
                                <td className="pr-4 tabular-nums">{r.revision}</td>
                                <td><StateBadge state={r.state} /></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {openRequests.length > 0 && (
        <div className="rounded-md border border-border overflow-hidden" data-testid="ingest-credential-requests">
          <div className="px-3 h-7 flex items-center border-b border-border bg-card/60 text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
            Requests not issued
          </div>
          {openRequests.map((r) => {
            const problem = r.state === 'rejected' ? describeRefusal(refusalCode(r.disposition), r.disposition ?? undefined) : null;
            return (
              <div key={r.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 items-center px-3 min-h-7 py-1 border-b border-border/60 last:border-b-0">
                <div className="flex items-center gap-2 min-w-0 text-[11.5px]">
                  <KeyRound className="w-3 h-3 text-muted-foreground shrink-0" strokeWidth={1.5} />
                  <span className="font-mono truncate">{r.label}</span>
                  <SlugChips slugs={r.source_slugs ?? []} />
                  <span className="font-mono text-[10.5px] text-muted-foreground">{shortTime(r.requested_at)} · {who(r.requested_by)}</span>
                  {problem && (
                    <span className="text-[11px] text-red-500 truncate" title={r.disposition ?? undefined}>
                      {problem.title}: {problem.detail}
                    </span>
                  )}
                  {r.state === 'pending' && (
                    <span className="text-[11px] text-muted-foreground">waiting for nano to mint the token (a new source waits for its rollout)</span>
                  )}
                </div>
                <StateBadge state={r.state} />
              </div>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) setTarget(null);
        }}
        title="Revoke ingest credential"
        icon={<ShieldOff className="w-4 h-4 text-red-500" strokeWidth={1.5} />}
        description={
          target ? (
            <>
              Senders using <span className="font-mono text-foreground">{target.label}</span> are refused within about 5
              seconds. Events already accepted stay searchable. This cannot be undone.
            </>
          ) : null
        }
        confirmLabel="Revoke"
        loadingLabel="Revoking…"
        variant="danger"
        loading={revoke.isPending}
        confirmDisabled={!reasonValid}
        onConfirm={() => {
          if (target && reasonValid) revoke.mutate({ credentialId: target.credential_id, reason: trimmedReason });
        }}
      >
        <label className="block text-[10.5px] font-medium text-foreground/80 mb-1.5" htmlFor="revoke-reason">
          Reason (recorded in the audit log)
        </label>
        <textarea
          id="revoke-reason"
          value={reason}
          maxLength={256}
          rows={2}
          onChange={(e) => setReason(e.target.value)}
          placeholder="rotated sender config"
          className="w-full rounded-md border border-input bg-background px-2.5 py-1.5 text-[12px] text-foreground focus:border-primary focus:outline-none resize-none"
        />
        <div className="mt-1 text-right font-mono text-[10px] text-muted-foreground tabular-nums">{trimmedReason.length}/256</div>
      </ConfirmDialog>
    </div>
  );
}
