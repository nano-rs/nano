// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Ingestion → Credentials on dedicated / open-core deployments (NAN-3770):
 * named, revocable HEC / HTTP ingest tokens plus the install token
 * (`VECTOR_AUTH_TOKEN`, "Install token (legacy)").
 *
 * NAN-3806: a token decides the source, 100% token based. Every token is bound
 * to one log source when it is issued, and every event sent with it lands in
 * that source whatever sourcetype it declares. A token with no source (one the
 * upgrade could not bind unambiguously, the install token, or one whose source
 * was deleted) is refused until an admin binds it here. A binding never
 * changes: revoke and issue a new token instead.
 *
 * A token value is shown once, in the issue dialog, and is never readable
 * again (the server keeps only its SHA-256). Rows carry the prefix only.
 * Vector re-reads its hashed tokens file every ~2 s, so issue, bind and revoke
 * take effect within seconds.
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Check, Copy, KeyRound, Link2, Plus, ShieldOff } from 'lucide-react';

import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import {
  INGEST_TOKENS_QUERY_KEY,
  type BindableSource,
  type IngestToken,
  type IssuedIngestToken,
} from '@/lib/api/ingest-tokens';
import { hecCurl, httpCurl, tokenEnvVar, vectorAggregator } from '@/lib/ingest-token-snippets';
import { cn } from '@/lib/utils';

function shortTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace('T', ' ');
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed';
}

function StateBadge({ state }: { state: string }) {
  const tone =
    state === 'active' || state === 'enabled'
      ? 'text-emerald-500 border-emerald-500/40'
      : state === 'disabled' || state === 'unbound'
        ? 'text-amber-500 border-amber-500/40'
        : 'text-muted-foreground border-border';
  return <span className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[10px]', tone)}>{state}</span>;
}

/** Source column: route key in mono, source name muted. */
function SourceCell({ name, routeKey }: { name?: string | null; routeKey?: string | null }) {
  if (!routeKey) return <span className="font-mono text-[10.5px] text-amber-500">no source</span>;
  return (
    <span className="inline-flex items-baseline gap-1.5 min-w-0">
      <span className="font-mono text-[10.5px] text-foreground">{routeKey}</span>
      {name && <span className="truncate text-[11px] text-muted-foreground">{name}</span>}
    </span>
  );
}

/** The shared Select over bindable sources. */
function SourcePicker({
  id,
  label,
  sources,
  value,
  onChange,
  disabled,
}: {
  id: string;
  label: string;
  sources: BindableSource[];
  value: string;
  onChange: (sourceId: string) => void;
  disabled?: boolean;
}) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled || sources.length === 0}>
      <SelectTrigger id={id} aria-label={label} className="h-7 px-2.5 text-[12px]">
        <SelectValue placeholder={sources.length ? 'Pick a source…' : 'No source can receive pushed events yet'} />
      </SelectTrigger>
      <SelectContent>
        {sources.map((source) => (
          <SelectItem key={source.source_id} value={source.source_id} className="text-[12px]">
            <span className="font-mono text-[11px]">{source.route_key}</span>
            <span className="ml-2 text-muted-foreground">{source.name}</span>
            {!source.enabled && <span className="ml-2 font-mono text-[10px] text-amber-500">disabled</span>}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** The issue dialog: name + source → value shown once, with copy. */
function IssueTokenDialog({
  open,
  onOpenChange,
  sources,
  initialSourceId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sources: BindableSource[];
  initialSourceId?: string;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [sourceId, setSourceId] = useState(initialSourceId ?? '');
  const [issued, setIssued] = useState<IssuedIngestToken | null>(null);
  const [copied, setCopied] = useState(false);
  const create = useMutation({
    mutationFn: ({ value, source }: { value: string; source: string }) => api.ingestTokens.create(value, source),
    onSuccess: (result) => {
      setIssued(result);
      void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
    },
  });

  const close = (next: boolean) => {
    if (!next) {
      // Drop the value from memory as soon as the dialog closes.
      setIssued(null);
      setName('');
      setSourceId('');
      setCopied(false);
      create.reset();
    }
    onOpenChange(next);
  };

  const copy = async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const canIssue = !!name.trim() && !!sourceId && !create.isPending;
  const submit = () => {
    if (canIssue) create.mutate({ value: name.trim(), source: sourceId });
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-w-md gap-0 p-0" data-testid="issue-ingest-token-dialog">
        <DialogHeader className="border-b border-border px-5 py-4">
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} /> New ingest token
          </DialogTitle>
          <DialogDescription>
            {issued
              ? 'Copy the token now. It is shown once and cannot be read again.'
              : 'Name the sender and pick its source. Every event sent with the token lands in that source, whatever sourcetype it declares. The binding never changes.'}
          </DialogDescription>
        </DialogHeader>
        <div className="px-5 py-4 space-y-2">
          {issued ? (
            <>
              <div className="text-[11px] text-muted-foreground">
                <span className="font-mono text-foreground">{issued.credential.name}</span>
                <span className="mx-1.5">→</span>
                <span className="font-mono text-foreground">{issued.credential.route_key}</span>
                <span className="mx-1.5">·</span>
                <span className="font-mono">{issued.credential.credential_id}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <code
                  className="flex-1 min-w-0 break-all rounded-sm border border-border bg-muted/40 px-2 py-1.5 font-mono text-[11px] select-all"
                  data-testid="issued-ingest-token"
                >
                  {issued.token}
                </code>
                <Button variant="outline" size="sm" className="h-7 gap-1 text-[11.5px]" onClick={() => void copy()}>
                  {copied ? <Check className="w-3 h-3" strokeWidth={1.5} /> : <Copy className="w-3 h-3" strokeWidth={1.5} />}
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
              <div className="text-[11px] text-muted-foreground">
                Send it as <span className="font-mono">Authorization: Splunk &lt;token&gt;</span> (HEC, :8088) or{' '}
                <span className="font-mono">Authorization: Bearer &lt;token&gt;</span> (HTTP, :8080).
              </div>
            </>
          ) : (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
            >
              <div>
                <label className="block text-[11px] text-muted-foreground mb-1" htmlFor="ingest-token-name">
                  Name
                </label>
                <Input
                  id="ingest-token-name"
                  value={name}
                  maxLength={100}
                  autoFocus
                  placeholder="fw-edge-01"
                  className="h-7 font-mono text-[12px]"
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-[11px] text-muted-foreground mb-1" htmlFor="ingest-token-source">
                  Source
                </label>
                <SourcePicker
                  id="ingest-token-source"
                  label="Source"
                  sources={sources}
                  value={sourceId}
                  onChange={setSourceId}
                />
              </div>
              {create.error && (
                <div className="text-[11px] text-red-500" role="alert">
                  {errorText(create.error)}
                </div>
              )}
            </form>
          )}
        </div>
        <DialogFooter className="border-t border-border px-5 py-3">
          {issued ? (
            <Button size="sm" className="h-8 text-[11.5px]" onClick={() => close(false)}>
              Done
            </Button>
          ) : (
            <>
              <Button variant="outline" size="sm" className="h-8 text-[11.5px]" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button size="sm" className="h-8 text-[11.5px]" disabled={!canIssue} onClick={submit}>
                {create.isPending ? 'Issuing…' : 'Issue token'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** What is being bound: a named token, or the install token. */
type BindTarget = { kind: 'token'; token: IngestToken } | { kind: 'install' };

function BindDialog({
  target,
  onClose,
  sources,
}: {
  target: BindTarget | null;
  onClose: () => void;
  sources: BindableSource[];
}) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [sourceId, setSourceId] = useState('');
  const bind = useMutation({
    mutationFn: async (source: string): Promise<void> => {
      if (target?.kind === 'token') await api.ingestTokens.bind(target.token.credential_id, source);
      else await api.ingestTokens.bindInstallToken(source);
    },
    onSuccess: () => {
      toast({ title: 'Token bound', description: 'Vector accepts it within a few seconds.' });
      setSourceId('');
      onClose();
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY }),
  });
  const label = target?.kind === 'token' ? target.token.name : 'Install token (legacy)';
  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) {
          setSourceId('');
          bind.reset();
          onClose();
        }
      }}
    >
      <DialogContent className="max-w-md gap-0 p-0" data-testid="bind-ingest-token-dialog">
        <DialogHeader className="border-b border-border px-5 py-4">
          <DialogTitle className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} /> Bind this token to a source
          </DialogTitle>
          <DialogDescription>
            <span className="font-mono text-foreground">{label}</span> is refused until it is bound. Pick the source its
            sender feeds: every event it sends lands there, whatever sourcetype it declares. The binding never changes.
          </DialogDescription>
        </DialogHeader>
        <div className="px-5 py-4 space-y-2">
          <SourcePicker id="bind-token-source" label="Source" sources={sources} value={sourceId} onChange={setSourceId} />
          {bind.error && (
            <div className="text-[11px] text-red-500" role="alert">
              {errorText(bind.error)}
            </div>
          )}
        </div>
        <DialogFooter className="border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" className="h-8 text-[11.5px]" onClick={onClose}>
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px]"
            disabled={!sourceId || bind.isPending}
            onClick={() => bind.mutate(sourceId)}
          >
            {bind.isPending ? 'Binding…' : 'Bind'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Snippet({ title, body, testId }: { title: string; body: string; testId: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="border border-border">
      <div className="flex items-center h-7 px-2 border-b border-border">
        <span className="font-mono text-[10.5px] uppercase tracking-wide text-muted-foreground">{title}</span>
        <span className="flex-1" />
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 gap-1 text-[11px]"
          onClick={() => {
            void navigator.clipboard
              .writeText(body)
              .then(() => setCopied(true))
              .catch(() => setCopied(false));
          }}
        >
          {copied ? <Check className="w-3 h-3" strokeWidth={1.5} /> : <Copy className="w-3 h-3" strokeWidth={1.5} />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <pre className="overflow-x-auto px-2 py-1.5 font-mono text-[11px] leading-[1.5] text-foreground" data-testid={testId}>
        {body}
      </pre>
    </div>
  );
}

/**
 * Send data: per-source tokens and copy-paste snippets, plus a Vector
 * aggregator example with one HEC sink per log type, each with its own token.
 */
function SendDataSection({
  sources,
  tokens,
  canManage,
  onIssue,
}: {
  sources: BindableSource[];
  tokens: IngestToken[];
  canManage: boolean;
  onIssue: (sourceId: string) => void;
}) {
  const [sourceId, setSourceId] = useState('');
  const source = sources.find((s) => s.source_id === sourceId) ?? null;
  const host = typeof window !== 'undefined' && window.location.hostname ? window.location.hostname : 'nano.example';
  const bound = source ? tokens.filter((t) => t.state === 'active' && t.source_id === source.source_id) : [];
  // The aggregator example: the sources that already have tokens, else the
  // picked one plus the next source, so it always shows two log types.
  const aggregatorSources = useMemo(() => {
    const withTokens = sources.filter((s) => tokens.some((t) => t.state === 'active' && t.source_id === s.source_id));
    if (withTokens.length >= 2) return withTokens;
    const picked = source ? [source] : [];
    const rest = sources.filter((s) => !picked.some((p) => p.source_id === s.source_id));
    return [...picked, ...rest].slice(0, 2);
  }, [sources, tokens, source]);

  return (
    <section className="space-y-2 border-t border-border pt-3" data-testid="send-data-section">
      <div className="flex items-center gap-3">
        <span className="font-mono text-[10.5px] uppercase tracking-wide text-muted-foreground">Send data</span>
        <div className="w-72">
          <SourcePicker id="send-data-source" label="Send data to" sources={sources} value={sourceId} onChange={setSourceId} />
        </div>
        {source && canManage && (
          <Button size="sm" variant="outline" className="h-7 gap-1.5 text-[11.5px]" onClick={() => onIssue(source.source_id)}>
            <Plus className="w-3 h-3" strokeWidth={1.5} /> Token for {source.route_key}
          </Button>
        )}
      </div>
      <div className="text-[11px] text-muted-foreground">
        One token per source. The token decides where events land; a sourcetype in the event is kept as{' '}
        <span className="font-mono">claimed_source_type</span> and never routes.
      </div>
      {source && (
        <div className="space-y-2">
          <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums" data-testid="send-data-tokens">
            {bound.length
              ? `${bound.length} token${bound.length === 1 ? '' : 's'} bound: ${bound.map((t) => `${t.name} (${t.token_prefix}…)`).join(', ')}`
              : 'No token bound to this source yet.'}
          </div>
          <div className="grid gap-2 lg:grid-cols-2">
            <Snippet title={`HEC · :8088 · $${tokenEnvVar(source)}`} body={hecCurl(host, source)} testId="snippet-hec" />
            <Snippet title={`HTTP · :8080 · $${tokenEnvVar(source)}`} body={httpCurl(host, source)} testId="snippet-http" />
          </div>
        </div>
      )}
      {aggregatorSources.length > 0 && (
        <Snippet
          title="Vector aggregator · one sink per log type"
          body={vectorAggregator(host, aggregatorSources)}
          testId="snippet-vector-aggregator"
        />
      )}
    </section>
  );
}

export function IngestTokensPanel() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission('settings:system');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [issue, setIssue] = useState<{ sourceId?: string } | null>(null);
  const [bindTarget, setBindTarget] = useState<BindTarget | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<IngestToken | null>(null);
  const [installConfirm, setInstallConfirm] = useState<boolean | null>(null);

  const list = useQuery({
    queryKey: INGEST_TOKENS_QUERY_KEY,
    queryFn: () => api.ingestTokens.list(),
    // "Last used" and request counts are sampled server-side every 30 s.
    refetchInterval: 30_000,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.ingestTokens.revoke(id),
    onSuccess: (token) => {
      toast({ title: 'Ingest token revoked', description: `${token.name} is refused within a few seconds.` });
    },
    onError: (error) => toast({ title: 'Revoke failed', description: errorText(error), variant: 'destructive' }),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY }),
  });

  const install = useMutation({
    mutationFn: (enabled: boolean) => api.ingestTokens.setInstallTokenEnabled(enabled),
    onError: (error) => toast({ title: 'Update failed', description: errorText(error), variant: 'destructive' }),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY }),
  });

  if (list.isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingIcon className="w-5 h-5 text-muted-foreground" />
      </div>
    );
  }
  if (list.error || !list.data) {
    return (
      <div className="text-[12px] text-red-500" role="alert">
        {errorText(list.error)}
      </div>
    );
  }

  const { tokens, install_token: installToken } = list.data;
  const sources = list.data.sources ?? [];
  const count = (state: string) => tokens.filter((t) => t.state === state).length;
  const unbound = count('unbound');
  const installUnbound = installToken.state === 'unbound';

  return (
    <div className="space-y-3" data-testid="ingest-tokens-panel">
      <div className="flex items-center gap-3">
        <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
          {count('active')} active · {unbound} unbound · {count('revoked')} revoked · install token {installToken.state.replace('_', ' ')}
        </span>
        <span className="flex-1" />
        {canManage && (
          <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => setIssue({})}>
            <Plus className="w-3 h-3" strokeWidth={1.5} /> New token
          </Button>
        )}
      </div>

      {(unbound > 0 || installUnbound) && (
        <div
          className="flex items-start gap-2 border border-amber-500/40 px-2.5 py-2 text-[11.5px] text-amber-500"
          role="alert"
          data-testid="unbound-tokens-alert"
        >
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" strokeWidth={1.5} />
          <span>
            {unbound + (installUnbound ? 1 : 0)} token{unbound + (installUnbound ? 1 : 0) === 1 ? ' is' : 's are'} not
            bound to a source and {unbound + (installUnbound ? 1 : 0) === 1 ? 'is' : 'are'} refused (HTTP 401). Bind
            each one to the source its sender feeds: the token decides where events land, a sourcetype never does.
          </span>
        </div>
      )}

      <table className="w-full border border-border text-[12px]">
        <thead>
          <tr className="h-7 border-b border-border text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
            <th className="px-2 font-medium">Name</th>
            <th className="px-2 font-medium">Source</th>
            <th className="px-2 font-medium">Prefix</th>
            <th className="px-2 font-medium">State</th>
            <th className="px-2 font-medium text-right">Requests</th>
            <th className="px-2 font-medium">Last used (UTC)</th>
            <th className="px-2 font-medium">Created (UTC)</th>
            <th className="px-2 w-28" />
          </tr>
        </thead>
        <tbody>
          <tr className="h-7 border-b border-border" data-testid="install-token-row">
            <td className="px-2 text-foreground">{installToken.name}</td>
            <td className="px-2">
              <SourceCell name={installToken.source_name} routeKey={installToken.route_key} />
            </td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">VECTOR_AUTH_TOKEN</td>
            <td className="px-2">
              <StateBadge state={installToken.state === 'active' ? 'enabled' : installToken.state.replace('_', ' ')} />
            </td>
            <td className="px-2 text-right font-mono text-[10.5px] text-muted-foreground">—</td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">—</td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">install</td>
            <td className="px-2 text-right whitespace-nowrap">
              {canManage && installUnbound && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[11px] text-amber-500"
                  onClick={() => setBindTarget({ kind: 'install' })}
                >
                  Bind
                </Button>
              )}
              {canManage && installToken.state !== 'not_configured' && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[11px]"
                  disabled={install.isPending}
                  onClick={() => setInstallConfirm(!installToken.enabled)}
                >
                  {installToken.enabled ? 'Disable' : 'Enable'}
                </Button>
              )}
            </td>
          </tr>
          {tokens.map((token) => (
            <tr key={token.credential_id} className="h-7 border-b border-border last:border-b-0" data-testid="ingest-token-row">
              <td className={cn('px-2', token.state === 'revoked' ? 'text-muted-foreground' : 'text-foreground')}>{token.name}</td>
              <td className="px-2">
                {token.state === 'revoked' ? (
                  <span className="font-mono text-[10.5px] text-muted-foreground">{token.route_key ?? '—'}</span>
                ) : (
                  <SourceCell name={token.source_name} routeKey={token.route_key} />
                )}
              </td>
              <td className="px-2 font-mono text-[10.5px]">{token.token_prefix}…</td>
              <td className="px-2">
                <StateBadge state={token.state} />
              </td>
              <td className="px-2 text-right font-mono text-[10.5px] tabular-nums text-muted-foreground">
                {(token.request_count ?? 0).toLocaleString('en-US')}
              </td>
              <td className="px-2 font-mono text-[10.5px] text-muted-foreground">
                {token.state === 'revoked' ? `revoked ${shortTime(token.revoked_at)}` : shortTime(token.last_used_at)}
              </td>
              <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{shortTime(token.created_at)}</td>
              <td className="px-2 text-right whitespace-nowrap">
                {canManage && token.state === 'unbound' && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-[11px] text-amber-500"
                    onClick={() => setBindTarget({ kind: 'token', token })}
                  >
                    Bind
                  </Button>
                )}
                {canManage && token.revocable && token.state !== 'revoked' && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-[11px] text-red-500 hover:text-red-600"
                    onClick={() => setRevokeTarget(token)}
                  >
                    Revoke
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {tokens.length === 0 && (
        <div className="text-[11.5px] text-muted-foreground">
          No named tokens yet. Issue one per sender and source: its events land in that source, you can tell senders
          apart in search (<span className="font-mono">metadata.nano_credential_id</span>), and you can revoke one
          without touching the others.
        </div>
      )}

      <SendDataSection
        sources={sources}
        tokens={tokens}
        canManage={canManage}
        onIssue={(sourceId) => setIssue({ sourceId })}
      />

      {canManage && issue !== null && (
        <IssueTokenDialog
          key={issue.sourceId ?? 'new'}
          open
          onOpenChange={(open) => {
            if (!open) setIssue(null);
          }}
          sources={sources}
          initialSourceId={issue.sourceId}
        />
      )}

      {canManage && <BindDialog target={bindTarget} onClose={() => setBindTarget(null)} sources={sources} />}

      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        title="Revoke ingest token"
        icon={<ShieldOff className="w-4 h-4 text-red-500" strokeWidth={1.5} />}
        description={
          revokeTarget ? (
            <>
              Senders using <span className="font-mono text-foreground">{revokeTarget.name}</span> (
              <span className="font-mono">{revokeTarget.token_prefix}…</span>) are refused within a few seconds. Events
              already accepted stay searchable. This cannot be undone.
            </>
          ) : undefined
        }
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={() => {
          if (revokeTarget) revoke.mutate(revokeTarget.credential_id);
          setRevokeTarget(null);
        }}
      />

      <ConfirmDialog
        open={installConfirm !== null}
        onOpenChange={(open) => {
          if (!open) setInstallConfirm(null);
        }}
        title={installConfirm ? 'Enable the install token' : 'Disable the install token'}
        icon={<AlertTriangle className="w-4 h-4 text-amber-500" strokeWidth={1.5} />}
        description={
          installConfirm ? (
            installToken.route_key ? (
              <>
                Senders using <span className="font-mono text-foreground">VECTOR_AUTH_TOKEN</span> are accepted again;
                their events land in <span className="font-mono text-foreground">{installToken.route_key}</span>.
              </>
            ) : (
              'The install token stays refused until it is bound to a source.'
            )
          ) : (
            <>
              Senders using <span className="font-mono text-foreground">VECTOR_AUTH_TOKEN</span> are refused on the HEC
              and HTTP ingest endpoints within a few seconds. Built-in collector integrations use their own platform
              credential and keep delivering. Move every sender to a named token first.
            </>
          )
        }
        confirmLabel={installConfirm ? 'Enable' : 'Disable'}
        variant={installConfirm ? 'default' : 'warning'}
        onConfirm={() => {
          if (installConfirm !== null) install.mutate(installConfirm);
          setInstallConfirm(null);
        }}
      />
    </div>
  );
}
