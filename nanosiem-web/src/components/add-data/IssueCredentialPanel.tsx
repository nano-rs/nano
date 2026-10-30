// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Issue an ingest credential and show its token once (NAN-2593): a per-source
 * credential for one `source`, or (NAN-2597) a collector credential for an
 * allowlist of `collectorSources`, with aliases per source.
 *
 * The browser makes the reveal key pair, the SIEM API records the request,
 * the platform mints and seals the token, and this panel opens it
 * (`lib/ingest-credential-issuance.ts`). The token lives only in this
 * component's state: never in React Query, storage or the URL.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, ShieldAlert } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { TenantIngestEndpoint } from '@/lib/api/types';
import {
  PROTOCOL_LABEL,
  SENDER_TEMPLATES_QUERY_KEY,
  defaultCredentialLabel,
  protocolsFor,
  isPlatformOnlySource,
  type AddDataSource,
  type DirectProtocol,
} from '@/lib/add-data-sources';
import {
  describeIngestCredentialError,
  describeRefusal,
  refusalCode,
  type IngestCredentialProblem,
} from '@/lib/ingest-credential-errors';
import {
  IssuanceAborted,
  IssuanceError,
  issueIngestCredential,
  type IssuancePhase,
  type IssuedCredential,
} from '@/lib/ingest-credential-issuance';
import {
  collectorProtocols,
  collectorSelectionProblem,
  defaultCollectorLabel,
  syncAliases,
  type SourceAliases,
} from '@/lib/collector-sources';
import { cn } from '@/lib/utils';
import { CollectorAliasEditor } from './CollectorAliasEditor';
import { FirstEventPanel } from './FirstEventPanel';
import { OneTimeToken } from './OneTimeToken';
import { SenderSnippets } from './SenderSnippets';
import { Checkbox } from '@/components/ui/checkbox';

const PHASE_COPY: Record<IssuancePhase, string> = {
  keygen: 'Generating a browser key…',
  requesting: 'Recording the request…',
  waiting: 'Waiting for nano to mint and seal the token…',
  revealing: 'Collecting the sealed token…',
  opening: 'Decrypting in your browser…',
};

type Shown = IssuedCredential & { copied: boolean; kind: 'source' | 'collector'; aliases: SourceAliases; issuedAt: string };

/** A copied credential whose first event the panel is waiting for (NAN-2599). */
type Watched = { requestId: string; credentialId: string; issuedAt: string; sourceSlugs: string[] };

const NO_SOURCES: AddDataSource[] = [];

/** Verdicts that `source_scopes:manage` (plus the acknowledgement) would clear. */
const MANAGE_VERDICTS = new Set(['source_restricted', 'mixed_restrictions_require_manage']);

/** The value after it has been stable for `ms` (checkbox toggles cost one precheck, not one each). */
function useSettled<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return settled;
}

export function IssueCredentialPanel({
  endpoint,
  source,
  collectorSources,
  logSourceId,
  initialProtocol,
  linear = false,
  onTokenSaved,
  onIssued,
  onBusyChange,
}: {
  endpoint: TenantIngestEndpoint;
  /** Direct: the one source the token is fixed to. */
  source?: AddDataSource;
  /** Collector (NAN-2597): the allowlist; set instead of `source`. */
  collectorSources?: AddDataSource[];
  logSourceId?: string;
  initialProtocol?: DirectProtocol;
  linear?: boolean;
  onTokenSaved?: () => void;
  onBusyChange?: (busy: boolean) => void;
  /** Called after a token was revealed (e.g. to refresh the credential list). */
  onIssued?: (credential: Pick<IssuedCredential, 'requestId' | 'credentialId'>) => void;
}) {
  const { hasPermission } = useAuth();
  const canDeploy = hasPermission('log_sources:deploy');
  const canManageScopes = hasPermission('source_scopes:manage');
  const canViewScopes = hasPermission('source_scopes:view');

  const collector = collectorSources !== undefined;
  const kind: 'source' | 'collector' = collector ? 'collector' : 'source';
  const targets = useMemo(
    () => (collector ? collectorSources ?? NO_SOURCES : source ? [source] : NO_SOURCES),
    [collector, collectorSources, source],
  );
  const slugs = useMemo(() => targets.map((t) => t.slug), [targets]);
  const slugsKey = slugs.join(',');
  const primarySlug = slugs[0] ?? '';

  const protocols = collector ? collectorProtocols(targets) : protocolsFor(source);
  const [protocol, setProtocol] = useState<DirectProtocol>(
    initialProtocol && protocols.includes(initialProtocol) ? initialProtocol : protocols[0] ?? 'hec',
  );
  // The source can change under a mounted panel (Step 1 re-picked): keep the protocol valid for it.
  const protocolsKey = protocols.join(',');
  useEffect(() => {
    if (!protocols.includes(protocol)) setProtocol(protocols[0] ?? 'hec');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [protocolsKey]);
  const defaultLabel = (p: string) => (collector ? defaultCollectorLabel(p) : defaultCredentialLabel(primarySlug, p));
  const [label, setLabel] = useState(() => defaultLabel(protocol));
  const labelTouched = useRef(false);
  useEffect(() => {
    if (!labelTouched.current) setLabel(defaultLabel(protocol));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [primarySlug, protocol, collector]);

  // Collector aliases: vendor sourcetypes prefilled for each source as it
  // joins the allowlist; the user's edits to earlier sources are kept.
  const [aliases, setAliases] = useState<SourceAliases>(() => (collector ? syncAliases({}, slugs) : {}));
  const previousSlugs = useRef<string[]>(slugs);
  useEffect(() => {
    if (!collector) return;
    setAliases((current) => syncAliases(current, slugs, previousSlugs.current));
    previousSlugs.current = slugs;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slugsKey, collector]);
  const selectionProblem = collector ? collectorSelectionProblem(slugs, aliases) : null;
  // NAN-2617: collectors authenticate only on a tenant whose Worker speaks
  // ingress v2; the API derives the flag per tenant.
  const collectorUnavailable = collector && endpoint.ingress_contract?.collector_credentials !== true;

  // NAN-2617: the server's own issuance guard decides whether a restriction
  // matters (decision b): only when the issuer is restricted from a selected
  // source, or the selection mixes restriction sets. A failed precheck (older
  // API, network) falls back to the refusal at issue time.
  const precheckKey = useSettled(`${kind}|${[...slugs].sort().join(',')}`, 150);
  const precheckSlugs = useMemo(() => precheckKey.split('|')[1]?.split(',').filter(Boolean) ?? [], [precheckKey]);
  const { data: precheck } = useQuery({
    queryKey: ['ingest-credential-precheck', precheckKey],
    queryFn: () =>
      api.precheckIngestCredential({ kind: precheckKey.split('|')[0] as 'source' | 'collector', source_slugs: precheckSlugs }),
    enabled: canDeploy && precheckSlugs.length > 0 && !collectorUnavailable,
    staleTime: 30 * 1000,
    retry: false,
  });
  // Only trust a verdict for the selection on screen.
  const verdict = precheckKey === `${kind}|${[...slugs].sort().join(',')}` ? precheck : undefined;

  const { data: restrictedResp } = useQuery({
    queryKey: ['source-scopes-restricted'],
    queryFn: () => api.sourceScopes.listRestricted(),
    enabled: canViewScopes,
    staleTime: 5 * 60 * 1000,
  });
  const restrictedSlugs = useMemo(
    () => slugs.filter((slug) => (restrictedResp?.restricted ?? []).some((r) => r.source_type === slug)),
    [restrictedResp, slugs],
  );
  const { data: catalog } = useQuery({
    queryKey: SENDER_TEMPLATES_QUERY_KEY,
    queryFn: () => api.getSenderTemplates(),
    staleTime: Infinity,
  });

  const [acknowledged, setAcknowledged] = useState(false);
  // Sticky once the server says the source needs an acknowledgement.
  const [ackRequiredByServer, setAckRequiredByServer] = useState(false);
  useEffect(() => {
    setAckRequiredByServer(false);
    setAcknowledged(false);
  }, [slugsKey]);
  const [problem, setProblem] = useState<IngestCredentialProblem | null>(null);
  const [phase, setPhase] = useState<IssuancePhase | null>(null);
  const [waitingCopy, setWaitingCopy] = useState<string | null>(null);
  const [pendingRequestId, setPendingRequestId] = useState<string | null>(null);
  const [cancelledRequestId, setCancelledRequestId] = useState<string | null>(null);
  const [shown, setShown] = useState<Shown[]>([]);
  // NAN-2599: the first-event checklist starts once a token is copied and
  // outlives dismissing the token.
  const [watched, setWatched] = useState<Watched[]>([]);
  const watch = useCallback((cred: Shown) => {
    if (!cred.credentialId) return;
    const credentialId = cred.credentialId;
    setWatched((prev) =>
      prev.some((w) => w.requestId === cred.requestId)
        ? prev
        : [{ requestId: cred.requestId, credentialId, issuedAt: cred.issuedAt, sourceSlugs: cred.sourceSlugs }, ...prev],
    );
  }, []);
  const abortRef = useRef<AbortController | null>(null);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const busy = phase !== null;
  useEffect(() => { onBusyChange?.(busy); return () => onBusyChange?.(false); }, [busy, onBusyChange]);
  const needsAck = verdict?.needs_acknowledgement === true || ackRequiredByServer;
  const manageBlocked = verdict?.blocked === true && verdict.verdict !== null && MANAGE_VERDICTS.has(verdict.verdict);
  const ackBlocked = manageBlocked || (ackRequiredByServer && !canManageScopes);
  const mixedRestrictions = verdict?.verdict === 'mixed_restrictions_require_manage';
  // Any other refusal the precheck already knows about (membership, permission, ...).
  const otherBlock =
    slugs.some(isPlatformOnlySource) ? describeRefusal('source_platform_only') :
    verdict?.blocked === true && verdict.verdict !== null && !MANAGE_VERDICTS.has(verdict.verdict)
      ? describeRefusal(refusalCode(verdict.verdict), verdict.verdict)
      : null;
  const trimmedLabel = label.trim();
  const labelValid = trimmedLabel.length > 0 && trimmedLabel.length <= 128;
  const canIssue =
    canDeploy && !busy && labelValid && !ackBlocked && (!needsAck || acknowledged) && otherBlock === null &&
    !collectorUnavailable && slugs.length > 0 && protocols.length > 0 && selectionProblem === null;

  // Abort an in-flight issuance when the panel goes away.
  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (!busy) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [busy]);

  // Leaving now would lose the browser key (in flight) or an unsaved token.
  const unsaved = busy || shown.some((s) => !s.copied);
  useEffect(() => {
    if (!unsaved) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [unsaved]);

  const issue = useCallback(async () => {
    if (!canIssue) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setProblem(null);
    setWaitingCopy(null);
    setCancelledRequestId(null);
    setStartedAt(Date.now());
    setNow(Date.now());
    let requestId: string | null = null;
    const issuedAliases = collector ? { ...aliases } : {};
    try {
      const credential = await issueIngestCredential(
        api,
        {
          protocol,
          label: trimmedLabel,
          kind,
          source_slugs: slugs,
          ...(collector && Object.keys(issuedAliases).length > 0 ? { source_aliases: issuedAliases } : {}),
          ...(needsAck ? { restricted_sources_acknowledged: acknowledged } : {}),
          ...(logSourceId && !collector ? { log_source_id: logSourceId } : {}),
        },
        {
          signal: controller.signal,
          onWaiting: (status) => {
            setWaitingCopy(status.waiting_reason === 'awaiting_enrollment'
              ? `Preparing the ${(status.waiting_source_slugs?.length ? status.waiting_source_slugs : status.source_slugs).join(', ')} ingest path`
              : status.waiting_reason === 'source_platform_only'
                ? describeRefusal('source_platform_only').detail
                : null);
          },
          onPhase: (p, request) => {
            setPhase(p);
            if (request) {
              requestId = request.id;
              setPendingRequestId(request.id);
            }
          },
        },
      );
      // A new token never replaces one still on screen: they stack until each is dismissed.
      const shownCredential: Shown = { ...credential, copied: false, kind, aliases: issuedAliases, issuedAt: new Date().toISOString() };
      setShown((prev) => [shownCredential, ...prev]);
      if (linear) watch(shownCredential);
      setAcknowledged(false);
      labelTouched.current = false;
      onIssued?.({ requestId: credential.requestId, credentialId: credential.credentialId });
    } catch (err) {
      if (err instanceof IssuanceAborted) {
        setCancelledRequestId(err.requestId ?? requestId);
      } else {
        const p = err instanceof IssuanceError ? err.problem : describeIngestCredentialError(err);
        if (p.needsAcknowledgement) setAckRequiredByServer(true);
        setProblem(p);
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setPhase(null);
      setPendingRequestId(null);
      setStartedAt(null);
    }
  }, [acknowledged, aliases, canIssue, collector, kind, logSourceId, needsAck, onIssued, protocol, slugs, trimmedLabel, linear, watch]);

  const elapsed = startedAt ? Math.max(0, Math.round((now - startedAt) / 1000)) : 0;
  const parserHref = logSourceId && !collector ? `/ingestion/log-sources/${logSourceId}` : '/ingestion/log-sources';
  const renderFirstEvent = (w: Watched) => (
    <FirstEventPanel key={w.requestId} credentialId={w.credentialId} issuedAt={w.issuedAt} sourceSlugs={w.sourceSlugs} parserHref={parserHref} />
  );

  return (
    <div className="space-y-3" data-testid="issue-credential-panel">
      {!(linear && (shown.length > 0 || watched.length > 0)) && <>
      <div className={linear ? "space-y-3" : "grid grid-cols-12 gap-3"}>
        <div className={linear ? "hidden" : "col-span-12 md:col-span-4"}>
          <div className="text-[10.5px] font-medium text-foreground/80 mb-1.5">{collector ? 'Sources' : 'Source'}</div>
          <div className="h-8 flex items-center gap-2 rounded-md border border-border bg-card px-2.5">
            {collector ? (
              <>
                <span className="font-mono text-[12px] text-foreground tabular-nums" data-testid="collector-source-count">
                  {slugs.length}
                </span>
                <span className="text-[11.5px] text-muted-foreground">
                  {slugs.length === 1 ? 'source' : 'sources'} + <span className="font-mono">unknown</span>
                </span>
              </>
            ) : (
              <span className="font-mono text-[12px] text-foreground truncate">{primarySlug}</span>
            )}
            {targets.some((t) => !t.enrolled) && (
              <span className="font-mono text-[9.5px] text-amber-500 border border-amber-500/40 rounded-sm px-1 h-4 inline-flex items-center">
                rolling out
              </span>
            )}
          </div>
        </div>
        <div className={linear ? "hidden" : "col-span-12 md:col-span-4"}>
          <div className="text-[10.5px] font-medium text-foreground/80 mb-1.5">Protocol</div>
          <div className="h-8 inline-flex items-center rounded-md border border-border bg-card p-0.5" role="radiogroup" aria-label="Protocol">
            {protocols.map((p) => (
              <button
                key={p}
                type="button"
                role="radio"
                aria-checked={protocol === p}
                disabled={busy}
                onClick={() => setProtocol(p)}
                className={cn(
                  'h-6 px-2.5 rounded text-[11.5px]',
                  protocol === p ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {PROTOCOL_LABEL[p] ?? p}
              </button>
            ))}
          </div>
        </div>
        <div className="col-span-12 md:col-span-4">
          <label className="block text-[10.5px] font-medium text-foreground/80 mb-1.5" htmlFor="ingest-credential-label">
            Label
          </label>
          <input
            id="ingest-credential-label"
            value={label}
            maxLength={128}
            disabled={busy}
            onChange={(e) => {
              labelTouched.current = true;
              setLabel(e.target.value);
            }}
            className="h-8 w-full rounded-md border border-input bg-background px-2.5 font-mono text-[12px] text-foreground focus:border-primary focus:outline-none"
          />
        </div>
      </div>

      {collector && (
        <div className="space-y-1.5">
          <CollectorAliasEditor slugs={slugs} aliases={aliases} onChange={setAliases} disabled={busy} />
          <div className="text-[10.5px] text-muted-foreground leading-relaxed" data-testid="collector-unknown-note">
            Each event declares its source by slug or alias (HEC <span className="font-mono">sourcetype</span>,{' '}
            <span className="font-mono">X-Source-Type</span> or a <span className="font-mono">source_type</span> field,
            OTLP <span className="font-mono">nano.source</span> or <span className="font-mono">x-nano-source</span>). Events
            that declare nothing land as <span className="font-mono">unknown</span> (Unattributed); any other name rejects
            the whole request with <span className="font-mono">403 source_not_allowed</span>. The token writes every
            source listed here, so keep the list to what this pipeline sends.
          </div>
          {protocols.length === 0 && (
            <div className="text-[11px] text-red-500" role="alert">
              These sources share no protocol. Issue one collector per protocol.
            </div>
          )}
          {selectionProblem && (
            <div className="text-[11px] text-red-500" role="alert" data-testid="collector-selection-problem">
              {selectionProblem.message}
            </div>
          )}
        </div>
      )}

      {targets.filter((t) => !t.enrolled).length > 0 && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/[0.04] px-3 py-2 text-[11px] text-foreground/80">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-amber-500 shrink-0" strokeWidth={1.5} />
          <span>
            <span className="font-mono">{targets.filter((t) => !t.enrolled).map((t) => t.slug).join(', ')}</span>{' '}
            {targets.filter((t) => !t.enrolled).length === 1 ? 'is' : 'are'} being connected to your ingest endpoint. The
            token is issued once {collector ? 'every source is' : 'the source is'} enrolled; keep this page open until
            it appears.
          </span>
        </div>
      )}

      {collectorUnavailable && (
        <div className="flex items-start gap-2 rounded-md border border-border px-3 py-2 text-[11px] text-foreground/80" role="status" data-testid="collector-unavailable">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-muted-foreground shrink-0" strokeWidth={1.5} />
          <span>
            Collector credentials are not enabled for this tenant yet: its ingest Worker accepts per-source credentials
            only. Issue one direct credential per source meanwhile.
          </span>
        </div>
      )}

      {otherBlock && !problem && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/[0.04] px-3 py-2" role="alert" data-testid="precheck-blocked">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-red-500 shrink-0" strokeWidth={1.5} />
          <div className="text-[11px] leading-relaxed">
            <div className="text-foreground font-medium">{otherBlock.title}</div>
            <div className="text-muted-foreground">{otherBlock.detail}</div>
          </div>
        </div>
      )}

      {(needsAck || ackBlocked) && (
        <div
          className={cn(
            'rounded-md border px-3 py-2',
            ackBlocked ? 'border-red-500/40 bg-red-500/[0.04]' : 'border-amber-500/40 bg-amber-500/[0.04]',
          )}
          data-testid="restricted-ack"
        >
          <div className="flex items-start gap-2">
            <ShieldAlert className={cn('w-3.5 h-3.5 mt-px shrink-0', ackBlocked ? 'text-red-500' : 'text-amber-500')} strokeWidth={1.5} />
            <div className="text-[11px] text-foreground/80 leading-relaxed">
              {collector ? (
                <>
                  {!mixedRestrictions && restrictedSlugs.length > 0 ? (
                    <>
                      <span className="font-mono">{restrictedSlugs.join(', ')}</span>{' '}
                      {restrictedSlugs.length === 1 ? 'is' : 'are'} restricted
                    </>
                  ) : (
                    'These sources have different restrictions'
                  )}
                  : some groups cannot see those events. One collector token spanning them can write data those groups
                  will not see.{' '}
                </>
              ) : (
                <>
                  <span className="font-mono">{primarySlug}</span> is restricted: some groups cannot see its events. A
                  token for it can write data those groups will not see.{' '}
                </>
              )}
              {ackBlocked ? (
                <span className="text-red-500">
                  Issuing it needs the <span className="font-mono">source_scopes:manage</span> permission.
                </span>
              ) : (
                <>
                  Issuing it needs <span className="font-mono">source_scopes:manage</span> (you have it) and your
                  acknowledgement.
                </>
              )}
            </div>
          </div>
          {!ackBlocked && (
            <label className="mt-2 flex items-center gap-2 text-[11.5px] text-foreground cursor-pointer">
              <Checkbox
                checked={acknowledged}
                disabled={busy}
                onCheckedChange={(checked) => setAcknowledged(checked === true)}
                className="h-3.5 w-3.5"
              />
              {collector
                ? 'I understand this collector credential writes to restricted sources.'
                : 'I understand this credential writes to a restricted source.'}
            </label>
          )}
        </div>
      )}

      {problem && (!problem.needsAcknowledgement || ackBlocked || acknowledged) && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/[0.04] px-3 py-2" role="alert">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-red-500 shrink-0" strokeWidth={1.5} />
          <div className="text-[11px] leading-relaxed">
            <div className="text-foreground font-medium">{problem.title}</div>
            <div className="text-muted-foreground">{problem.detail}</div>
          </div>
        </div>
      )}

      {cancelledRequestId && (
        <div className="text-[11px] text-muted-foreground" role="status">
          Cancelled. Request <span className="font-mono">{cancelledRequestId}</span> may still be issued; its token
          cannot be revealed now, so revoke it from Credentials if it appears.
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button size="sm" className={cn("h-8 gap-1.5 text-[11.5px]", linear && "shadow-none")} disabled={!canIssue} onClick={() => void issue()}>
          {busy ? <LoadingIcon className="w-3.5 h-3.5" /> : <KeyRound className="w-3.5 h-3.5" strokeWidth={1.5} />}
          {shown.length > 0 ? 'Issue another credential' : 'Issue credential'}
        </Button>
        {busy && (
          <>
            <span className="text-[11px] text-muted-foreground" role="status">
              {phase === 'waiting' && waitingCopy ? waitingCopy : PHASE_COPY[phase!]}
            </span>
            {pendingRequestId && <span className="font-mono text-[10.5px] text-muted-foreground/70">{pendingRequestId}</span>}
            <span className="font-mono text-[10.5px] text-muted-foreground/70 tabular-nums">{elapsed}s</span>
            <Button variant="ghost" size="sm" className="h-7 text-[11px]" onClick={() => abortRef.current?.abort()}>
              Cancel
            </Button>
          </>
        )}
        {!canDeploy && (
          <span className="text-[11px] text-muted-foreground">
            Needs <span className="font-mono">log_sources:deploy</span>.
          </span>
        )}
      </div>

      </>}
      {shown.map((cred) => (
        <div key={cred.requestId} className="space-y-2">
          <OneTimeToken
            credential={cred}
            copied={cred.copied}
            onCopied={() => {
              setShown((prev) => prev.map((s) => (s.requestId === cred.requestId ? { ...s, copied: true } : s)));
              watch(cred);
              onTokenSaved?.();
            }}
            onDismiss={() => { setShown((prev) => prev.filter((s) => s.requestId !== cred.requestId)); onTokenSaved?.(); }}
          />
          <SenderSnippets
            linear={linear}
            catalog={catalog}
            endpoint={endpoint}
            protocol={cred.protocol}
            label={cred.label}
            token={cred.token}
            kind={cred.kind}
            sources={cred.kind === 'collector' ? { slugs: cred.sourceSlugs, aliases: cred.aliases } : undefined}
          />
          {watched.filter((w) => w.requestId === cred.requestId).map(renderFirstEvent)}
        </div>
      ))}

      {/* Tokens already dismissed keep their checklist. */}
      {watched.filter((w) => !shown.some((s) => s.requestId === w.requestId)).map(renderFirstEvent)}
    </div>
  );
}
