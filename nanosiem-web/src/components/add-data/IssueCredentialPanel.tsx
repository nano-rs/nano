// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Issue an ingest token for one source and show it once (main's NAN-2593
 * panel, re-backed for the ClickHouse product by NAN-4922 on the
 * single-tenant ingest tokens of NAN-4907).
 *
 * The token is bound to the source and decides it: every event sent with it
 * lands there over HEC, HTTP JSON or OTLP, whatever source type the sender
 * declares, and before any parser is published. The token lives only in this
 * component's state: never in React Query, storage or the URL.
 *
 * `linear` (the Add source Connect step) renders main's fixed order: create a
 * credential → send data with it → first events. Otherwise (Log Source detail)
 * it is a form with the token, snippets and first-event checklist below.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { IngestEndpoint } from '@/lib/api/types';
import { INGEST_TOKENS_QUERY_KEY } from '@/lib/api/ingest-tokens';
import { CONNECT_STATUS_QUERY_KEY, connectDetailQueryKey } from '@/lib/api/log-source-connect';
import {
  PROTOCOL_LABEL,
  defaultCredentialLabel,
  protocolsFor,
  isPlatformOnlySource,
  type AddDataSource,
  type DirectProtocol,
} from '@/lib/add-data-sources';
import { describeIngestCredentialError, type IngestCredentialProblem } from '@/lib/ingest-credential-errors';
import { issueIngestCredential, type IssuedCredential } from '@/lib/ingest-credential-issuance';
import { firstEventFacts } from '@/lib/first-event';
import { cn } from '@/lib/utils';
import { authHeader, connectStage, type ConnectStage } from '@/lib/connect-stage';
import { ConnectStep, type ConnectStepState } from './ConnectStep';
import { CopyButton } from './CopyButton';
import { IngestEndpointCard } from './IngestEndpointCard';
import { FirstEventPanel } from './FirstEventPanel';
import { OneTimeToken } from './OneTimeToken';
import { SenderSnippets } from './SenderSnippets';

/** Issuing an ingest token is a token-management action on this product. */
export const ISSUE_TOKEN_PERMISSION = 'settings:system';

type Shown = IssuedCredential & { copied: boolean; issuedAt: string };

/** A copied token whose first event the panel is waiting for. */
type Watched = { requestId: string; credentialId: string; issuedAt: string; sourceSlugs: string[] };

/** `connect-stage` speaks HEC / HTTP / OTLP. */
function headerProtocol(protocol: string): 'hec' | 'http' | 'otlp' {
  return protocol === 'hec' ? 'hec' : protocol === 'otlp_http' ? 'otlp' : 'http';
}

export function IssueCredentialPanel({
  endpoint,
  source,
  logSourceId,
  initialProtocol,
  linear = false,
  onTokenSaved,
  onIssued,
  onBusyChange,
  onStageChange,
  signal,
  searchField,
}: {
  endpoint: IngestEndpoint;
  /** The source the token is bound to. */
  source: AddDataSource;
  /** The log source to bind (defaults to `source.logSource.id`). */
  logSourceId?: string;
  initialProtocol?: DirectProtocol;
  linear?: boolean;
  onTokenSaved?: () => void;
  onBusyChange?: (busy: boolean) => void;
  /** Where the token → send → first events sequence stands. */
  onStageChange?: (stage: ConnectStage) => void;
  /** OTLP signal for the endpoint row in the linear Send step. */
  signal?: string;
  /** The field Search scopes a source by (`metadata.log_source` on OCSF). */
  searchField?: string;
  /** Called after a token was issued (e.g. to refresh the token list). */
  onIssued?: (credential: Pick<IssuedCredential, 'requestId' | 'credentialId'>) => void;
}) {
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const canIssueToken = hasPermission(ISSUE_TOKEN_PERMISSION);
  const bindId = logSourceId ?? source.logSource?.id;

  const protocols = protocolsFor(source);
  const [protocol, setProtocol] = useState<DirectProtocol>(
    initialProtocol && protocols.includes(initialProtocol) ? initialProtocol : protocols[0] ?? 'hec',
  );
  useEffect(() => {
    if (initialProtocol && protocols.includes(initialProtocol)) setProtocol(initialProtocol);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialProtocol]);
  const [label, setLabel] = useState(() => defaultCredentialLabel(source.slug, protocol));
  const labelTouched = useRef(false);
  useEffect(() => {
    if (!labelTouched.current) setLabel(defaultCredentialLabel(source.slug, protocol));
  }, [source.slug, protocol]);

  const [problem, setProblem] = useState<IngestCredentialProblem | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<Shown[]>([]);
  // The latest token this panel issued: the Send step is built from it.
  const [latest, setLatest] = useState<Omit<Shown, 'token' | 'copied'> | null>(null);
  // The first-event checklist starts once a token is copied and outlives dismissing it.
  const [watched, setWatched] = useState<Watched[]>([]);
  const watch = useCallback((cred: Shown) => {
    setWatched((prev) =>
      prev.some((w) => w.requestId === cred.requestId)
        ? prev
        : [{ requestId: cred.requestId, credentialId: cred.credentialId, issuedAt: cred.issuedAt, sourceSlugs: cred.sourceSlugs }, ...prev],
    );
  }, []);

  useEffect(() => { onBusyChange?.(busy); return () => onBusyChange?.(false); }, [busy, onBusyChange]);

  const blocked = isPlatformOnlySource(source.slug);
  const trimmedLabel = label.trim();
  const labelValid = trimmedLabel.length > 0 && trimmedLabel.length <= 128;
  const canIssue = canIssueToken && !busy && labelValid && !blocked && !!bindId;

  // Leaving now would lose a token that was never copied.
  const unsaved = shown.some((s) => !s.copied);
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
    if (!canIssue || !bindId) return;
    setProblem(null);
    setBusy(true);
    try {
      const credential = await issueIngestCredential(api.ingestTokens, {
        label: trimmedLabel,
        protocol,
        logSourceId: bindId,
        sourceSlug: source.slug,
      });
      // A new token never replaces one still on screen: they stack until each is dismissed.
      const shownCredential: Shown = { ...credential, copied: false, issuedAt: new Date().toISOString() };
      setShown((prev) => [shownCredential, ...prev]);
      const { token: _token, copied: _copied, ...rest } = shownCredential;
      void _token; void _copied;
      setLatest(rest);
      if (linear) watch(shownCredential);
      labelTouched.current = false;
      void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: CONNECT_STATUS_QUERY_KEY });
      onIssued?.({ requestId: credential.requestId, credentialId: credential.credentialId });
    } catch (err) {
      setProblem(describeIngestCredentialError(err));
    } finally {
      setBusy(false);
    }
  }, [bindId, canIssue, linear, onIssued, protocol, queryClient, source.slug, trimmedLabel, watch]);

  // Observe the FirstEventPanel's live query without issuing a second request.
  const { data: detail } = useQuery({
    queryKey: connectDetailQueryKey(bindId ?? ''),
    queryFn: () => api.logSourceConnect.getStatus(bindId as string),
    enabled: false,
  });
  const watchedOne = watched[0];
  const receiving = !!watchedOne && firstEventFacts(detail, watchedOne.credentialId, watchedOne.issuedAt).state === 'searchable';
  const issued = shown.length > 0 || watched.length > 0 || latest !== null;
  const stage = connectStage({ busy, failed: problem !== null, issued, receiving });
  useEffect(() => { onStageChange?.(stage); }, [stage, onStageChange]);

  const parserHref = bindId ? `/ingestion/log-sources/new?source_id=${encodeURIComponent(bindId)}&stage=parse` : '/ingestion/log-sources';
  const renderFirstEvent = (w: Watched) =>
    bindId ? (
      <FirstEventPanel
        key={w.requestId}
        logSourceId={bindId}
        credentialId={w.credentialId}
        issuedAt={w.issuedAt}
        sourceSlugs={w.sourceSlugs}
        parserHref={parserHref}
        searchField={searchField}
      />
    ) : null;

  const form = (
    <>
      <div className={linear ? 'space-y-3' : 'grid grid-cols-12 gap-3'}>
        <div className={linear ? 'hidden' : 'col-span-12 md:col-span-4'}>
          <div className="text-[10.5px] font-medium text-foreground/80 mb-1.5">Source</div>
          <div className="h-8 flex items-center gap-2 rounded-md border border-border bg-card px-2.5">
            <span className="font-mono text-[12px] text-foreground truncate">{source.slug}</span>
          </div>
        </div>
        <div className={linear ? 'hidden' : 'col-span-12 md:col-span-4'}>
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
            Token name
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

      {blocked && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/[0.04] px-3 py-2" role="alert" data-testid="precheck-blocked">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-red-500 shrink-0" strokeWidth={1.5} />
          <div className="text-[11px] leading-relaxed text-muted-foreground">
            <span className="font-mono">{source.slug}</span> is nano&apos;s own lane and takes no ingest tokens.
          </div>
        </div>
      )}

      {problem && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/[0.04] px-3 py-2" role="alert">
          <AlertTriangle className="w-3.5 h-3.5 mt-px text-red-500 shrink-0" strokeWidth={1.5} />
          <div className="text-[11px] leading-relaxed">
            <div className="text-foreground font-medium">{problem.title}</div>
            <div className="text-muted-foreground">{problem.detail}</div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button size="sm" className={cn('h-8 gap-1.5 text-[11.5px]', linear && 'shadow-none')} disabled={!canIssue} onClick={() => void issue()}>
          {busy ? <LoadingIcon className="w-3.5 h-3.5" /> : <KeyRound className="w-3.5 h-3.5" strokeWidth={1.5} />}
          {problem && !problem.terminal ? 'Try again' : shown.length > 0 ? 'Issue another token' : 'Issue token'}
        </Button>
        {busy && <span className="text-[11px] text-muted-foreground" role="status">Issuing…</span>}
        {!canIssueToken && (
          <span className="text-[11px] text-muted-foreground">
            Needs <span className="font-mono">{ISSUE_TOKEN_PERMISSION}</span>.
          </span>
        )}
      </div>
    </>
  );

  const tokenSaved = (cred: Shown) => {
    setShown((prev) => prev.map((s) => (s.requestId === cred.requestId ? { ...s, copied: true } : s)));
    watch(cred);
    onTokenSaved?.();
  };
  const tokenCard = (cred: Shown) => (
    <OneTimeToken
      key={cred.requestId}
      credential={cred}
      copied={cred.copied}
      onCopied={() => tokenSaved(cred)}
      onDismiss={() => { setShown((prev) => prev.filter((s) => s.requestId !== cred.requestId)); onTokenSaved?.(); }}
    />
  );

  if (linear) {
    const sendProtocol = latest?.protocol ?? protocol;
    const onScreenCredential = latest ? shown.find((s) => s.requestId === latest.requestId) : undefined;
    const onScreenToken = onScreenCredential?.token;
    const header = authHeader(headerProtocol(sendProtocol), onScreenToken);
    const step1: { state: ConnectStepState; status: string } =
      issued ? { state: 'done', status: 'ready' }
        : stage === 'pending' ? { state: 'active', status: 'issuing' }
          : stage === 'failed' ? { state: 'error', status: 'failed' }
            : { state: 'active', status: 'start here' };
    return (
      <div className="space-y-3" data-testid="issue-credential-panel">
        <ol className="space-y-2" data-testid="connect-steps" aria-label="Connect steps">
          <ConnectStep n={1} title="Create a credential" testId="connect-step-credential" {...step1}>
            {issued ? (
              <>
                {shown.map(tokenCard)}
                {shown.length === 0 && latest && (
                  <div className="text-[11px] text-muted-foreground">
                    Token <span className="font-mono text-[10.5px] text-foreground/80">{latest.label}</span> is ready.
                  </div>
                )}
              </>
            ) : (
              <>
                {stage === 'none' && (
                  <div className="text-[11px] text-muted-foreground">
                    Senders authenticate with this token, and it decides the source, so create it first. Nothing has to be sent yet.
                  </div>
                )}
                {form}
              </>
            )}
          </ConnectStep>

          <ConnectStep n={2} title="Send data with it" testId="connect-step-send"
            state={issued ? 'active' : 'locked'} status={issued ? 'send now' : 'after step 1'}>
            {issued && latest ? (
              <>
                <IngestEndpointCard endpoint={endpoint} protocol={sendProtocol} signal={signal} />
                <div className="rounded-md border border-border bg-card grid grid-cols-[88px_minmax(0,1fr)_auto] items-center gap-2 px-3 h-7" data-testid="connect-auth-header">
                  <span className="text-[11px] text-muted-foreground">header</span>
                  <span className="font-mono text-[11.5px] text-foreground truncate">{authHeader(headerProtocol(sendProtocol))}</span>
                  <CopyButton text={header} aria-label="Copy header" onCopied={() => { if (onScreenCredential) tokenSaved(onScreenCredential); }} />
                </div>
                <SenderSnippets linear endpoint={endpoint} protocol={sendProtocol} label={latest.label} token={onScreenToken} />
              </>
            ) : (
              <div className="text-[11px] text-muted-foreground">
                Your {PROTOCOL_LABEL[sendProtocol] ?? sendProtocol} endpoint, the token header and an example request appear
                here once the token is ready.
              </div>
            )}
          </ConnectStep>

          <ConnectStep n={3} title={issued ? stage === 'receiving' ? 'First events received' : 'Waiting for first events' : 'Check for first events'} testId="connect-step-events"
            state={stage === 'receiving' ? 'done' : issued ? 'active' : 'locked'}
            status={stage === 'receiving' ? 'receiving' : issued ? 'listening' : 'after step 2'}>
            {issued ? (
              watched.length > 0 ? watched.map(renderFirstEvent) : (
                <div className="text-[11px] text-muted-foreground">Copy the token to start watching for its first event.</div>
              )
            ) : (
              <div className="text-[11px] text-muted-foreground">Starts once the token is ready and you send data with it.</div>
            )}
          </ConnectStep>
        </ol>
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="issue-credential-panel">
      {form}
      {shown.map((cred) => (
        <div key={cred.requestId} className="space-y-2">
          {tokenCard(cred)}
          <SenderSnippets endpoint={endpoint} protocol={cred.protocol} label={cred.label} token={cred.token} />
          {watched.filter((w) => w.requestId === cred.requestId).map(renderFirstEvent)}
        </div>
      ))}

      {/* Tokens already dismissed keep their checklist. */}
      {watched.filter((w) => !shown.some((s) => s.requestId === w.requestId)).map(renderFirstEvent)}
    </div>
  );
}
