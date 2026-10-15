// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3038 — code-free IOC lists. Upload a static indicator list (CSV /
// JSON / one-per-line text, or paste), publish it to the tenant IOC snapshot,
// and see counts + last publication. Same density as Lookup tables.

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronRight, Info, Plus, Trash2, Upload, Send } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import {
  uploadFormatFor,
  type IocListSummary,
  type IocType,
  type IocUploadFormat,
} from '@/lib/api/ioc-lists';
import { cn } from '@/lib/utils';
import { IocListViewer } from './IocListViewer';
import { ExpirySelect, NO_EXPIRY, expiryInstant, type ExpiryValue } from './IocExpirySelect';

const QUERY_KEY = ['ioc-lists'];
const POLL_MS = 2000;
const TYPES: IocType[] = ['ip', 'domain', 'hash', 'url', 'email'];

const inputClass =
  'h-[28px] w-full px-2 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

function relative(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const min = Math.round((Date.now() - d.getTime()) / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min}m ago`;
  const h = Math.round(min / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.round(h / 24);
  return days < 30 ? `${days}d ago` : d.toISOString().slice(0, 10);
}

interface UploadTarget {
  /** Existing list (append/replace) or a new one. */
  list: IocListSummary | null;
}

export function IocLists() {
  useDocumentTitle('IOC lists');
  const client = useQueryClient();
  const { toast } = useToast();
  // NAN-3882: publication runs in the background; poll the (cheap) summaries
  // while any list is publishing.
  const lists = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => api.iocLists.list(),
    retry: false,
    refetchInterval: (query) =>
      query.state.data?.some((l) => l.publish_state === 'publishing') ? POLL_MS : false,
  });
  const [upload, setUpload] = useState<UploadTarget | null>(null);
  const [toDelete, setToDelete] = useState<IocListSummary | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const refresh = () => client.invalidateQueries({ queryKey: QUERY_KEY });

  const publish = useMutation({
    mutationFn: (list: IocListSummary) => api.iocLists.publish(list.id),
    onSuccess: (result) => {
      client.setQueryData<IocListSummary[]>(QUERY_KEY, (old) =>
        old?.map((l) => (l.id === result.list.id ? result.list : l)),
      );
      if (!result.started) toast({ title: 'Already publishing', description: result.list.name });
      refresh();
    },
    onError: (err) => toast({ title: 'Publish failed', description: errorMessage(err), variant: 'destructive' }),
  });

  // Announce a background publication's outcome once.
  const previous = useRef<Map<string, IocListSummary['publish_state']>>(new Map());
  useEffect(() => {
    for (const list of lists.data ?? []) {
      const before = previous.current.get(list.id);
      if (before === 'publishing' && list.publish_state === 'published') {
        toast({
          title: 'IOC list published',
          description: `${list.name}: ${(list.last_published_count ?? 0).toLocaleString()} indicators live`,
        });
      } else if (before === 'publishing' && list.publish_state === 'failed') {
        toast({ title: 'Publish failed', description: `${list.name}: ${list.publish_error ?? 'unknown error'}`, variant: 'destructive' });
      }
      previous.current.set(list.id, list.publish_state);
    }
  }, [lists.data, toast]);

  const remove = useMutation({
    mutationFn: (list: IocListSummary) => api.iocLists.remove(list.id),
    onSuccess: (_, list) => {
      toast({ title: 'IOC list deleted', description: list.name });
      setToDelete(null);
      refresh();
    },
    onError: (err) => toast({ title: 'Delete failed', description: errorMessage(err), variant: 'destructive' }),
  });

  const all = lists.data ?? [];
  const total = all.reduce((acc, l) => acc + l.indicator_count, 0);

  return (
    <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden bg-background">
      <div className="shrink-0 px-6 pt-6 pb-3 flex items-end gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <h1 className="text-[20px] font-semibold tracking-[-0.015em] text-foreground">IOC lists</h1>
            <HowItWorks />
          </div>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            <span className="font-mono tabular-nums">{all.length.toLocaleString()}</span> list{all.length === 1 ? '' : 's'}
            {' · '}
            <span className="font-mono tabular-nums">{total.toLocaleString()}</span> indicators
            {' · '}static indicators stamped on ingest as <span className="font-mono">threat_intelligence</span>
          </p>
        </div>
        <span className="flex-1" />
        <button
          type="button"
          onClick={() => setUpload({ list: null })}
          className="h-[30px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 flex items-center gap-1.5 text-[12px] font-semibold"
        >
          <Plus className="w-[13px] h-[13px]" strokeWidth={1.5} />
          New IOC list
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-6 pb-6 space-y-3">
        {upload && (
          <UploadPanel
            target={upload.list}
            onClose={() => setUpload(null)}
            onSaved={() => {
              setUpload(null);
              refresh();
            }}
          />
        )}

        {lists.isLoading ? (
          <div className="rounded-lg border border-border bg-card p-12 flex items-center justify-center">
            <LoadingIcon className="w-5 h-5 text-muted-foreground" strokeWidth={1.5} />
          </div>
        ) : lists.isError ? (
          <div className="rounded-lg border border-border bg-card py-12 text-center text-[11.5px] font-mono text-muted-foreground">
            IOC lists are unavailable: {errorMessage(lists.error)}
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            <div className="h-[28px] px-4 flex items-center gap-3 border-b border-border text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
              <span className="w-[13px]" />
              <span className="flex-1">name</span>
              <span className="w-[72px] text-right">indicators</span>
              <span className="w-[220px]">by type</span>
              <span className="w-[120px]">last published</span>
              <span className="w-[80px] text-right">updated</span>
              <span className="w-[92px]" />
            </div>
            {all.length === 0 ? (
              <div className="py-16 text-center text-[11.5px] font-mono text-muted-foreground">
                No IOC lists yet. Upload a CSV, JSON or one-indicator-per-line file.
              </div>
            ) : (
              all.map((list, i) => (
                <div key={list.id} className={cn(i < all.length - 1 && 'border-b border-border/40')}>
                <div className="group flex items-center gap-3 px-4 h-[40px] hover:bg-primary/[0.04]">
                  <button
                    type="button"
                    aria-label={expanded === list.id ? `Hide ${list.name} indicators` : `View ${list.name} indicators`}
                    aria-expanded={expanded === list.id}
                    onClick={() => setExpanded(expanded === list.id ? null : list.id)}
                    className="w-[13px] h-[13px] flex items-center justify-center text-muted-foreground hover:text-foreground shrink-0"
                  >
                    <ChevronRight
                      className={cn('w-[13px] h-[13px] transition-transform', expanded === list.id && 'rotate-90')}
                      strokeWidth={1.5}
                    />
                  </button>
                  <div className="flex-1 min-w-0 cursor-pointer" onClick={() => setExpanded(expanded === list.id ? null : list.id)}>
                    <div className="text-[12.5px] font-mono text-foreground truncate">{list.name}</div>
                    {list.description && (
                      <div className="text-[10.5px] text-muted-foreground truncate">{list.description}</div>
                    )}
                  </div>
                  <span className="w-[72px] text-right text-[11px] font-mono tabular-nums text-foreground/80">
                    {list.indicator_count.toLocaleString()}
                  </span>
                  <span className="w-[220px] flex gap-2 text-[10.5px] font-mono text-muted-foreground truncate">
                    {TYPES.filter((t) => list.counts[t]).map((t) => (
                      <span key={t}>
                        {t} <span className="text-foreground/80 tabular-nums">{list.counts[t]?.toLocaleString()}</span>
                      </span>
                    ))}
                  </span>
                  <span className="w-[120px] text-[10.5px] font-mono truncate">
                    <PublishStatus list={list} />
                  </span>
                  <span className="w-[80px] text-right text-[10.5px] font-mono text-muted-foreground">
                    {relative(list.updated_at)}
                  </span>
                  <span className="w-[92px] flex justify-end gap-1">
                    <IconButton
                      label={list.publish_state === 'publishing' ? 'Publishing…' : 'Publish'}
                      onClick={() => publish.mutate(list)}
                      busy={(publish.isPending && publish.variables?.id === list.id) || list.publish_state === 'publishing'}
                    >
                      <Send className="w-3.5 h-3.5" strokeWidth={1.5} />
                    </IconButton>
                    <IconButton label="Upload indicators" onClick={() => setUpload({ list })}>
                      <Upload className="w-3.5 h-3.5" strokeWidth={1.5} />
                    </IconButton>
                    <IconButton label="Delete" onClick={() => setToDelete(list)} danger>
                      <Trash2 className="w-3.5 h-3.5" strokeWidth={1.5} />
                    </IconButton>
                  </span>
                </div>
                {expanded === list.id && <IocListViewer list={list} />}
                </div>
              ))
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(open) => !open && setToDelete(null)}
        variant="danger"
        title="Delete IOC list"
        description={
          <>
            Delete <span className="font-mono">{toDelete?.name}</span>? A published list is withdrawn from the tenant
            IOC snapshot first; new events stop matching its indicators.
          </>
        }
        confirmLabel="Delete"
        onConfirm={() => toDelete && remove.mutate(toDelete)}
      />
    </div>
  );
}

/** Publication status cell: last success, a running attempt, or the failure. */
function PublishStatus({ list }: { list: IocListSummary }) {
  if (list.publish_state === 'publishing') {
    return (
      <span className="inline-flex items-center gap-1 text-muted-foreground" title={list.publish_started_at ? `started ${relative(list.publish_started_at)}` : undefined}>
        <LoadingIcon className="w-3 h-3" strokeWidth={1.5} />
        publishing…
      </span>
    );
  }
  if (list.publish_state === 'failed') {
    return (
      <span className="text-destructive" title={list.publish_error ?? undefined}>
        failed{list.last_published_at && ` · last ${relative(list.last_published_at)}`}
      </span>
    );
  }
  if (!list.last_published_at) return <span className="text-amber-600 dark:text-amber-400">never</span>;
  return (
    <span
      className={list.publish_pending ? 'text-amber-600 dark:text-amber-400' : 'text-muted-foreground'}
      title={list.publish_pending ? 'Changed since last publish' : undefined}
    >
      {relative(list.last_published_at)}
      {' · '}
      <span className="tabular-nums">{list.last_published_count?.toLocaleString()}</span>
      {list.publish_pending && ' · pending'}
    </span>
  );
}

/** How a list goes from upload to matching, on demand rather than as page copy. */
function HowItWorks() {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type="button" aria-label="How IOC lists work" className="text-muted-foreground hover:text-foreground">
          <Info className="w-[13px] h-[13px]" strokeWidth={1.5} />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[340px] text-[11.5px] leading-[1.45] space-y-1.5">
        <div className="font-semibold text-[12px] text-foreground">How IOC lists work</div>
        <ol className="list-decimal pl-4 space-y-1 text-muted-foreground">
          <li><span className="text-foreground">Upload</span> a CSV, JSON or one-per-line file. Indicators are validated and stored; nothing matches yet.</li>
          <li><span className="text-foreground">Publish</span> pushes the list into your tenant&apos;s IOC snapshot. It runs in the background; the status column shows progress.</li>
          <li>From then on, <span className="text-foreground">new events are matched at ingest</span> and stamped under <span className="font-mono">threat_intelligence</span> with the list name as provider. The threat-intel flyout on an event checks your lists too. Expired indicators stop matching.</li>
        </ol>
        <div className="text-muted-foreground">Uploading again marks the list <span className="font-mono">pending</span>: publish to apply the change. Past events are not re-stamped.</div>
      </PopoverContent>
    </Popover>
  );
}

function IconButton({
  label, onClick, children, danger, busy,
}: { label: string; onClick: () => void; children: ReactNode; danger?: boolean; busy?: boolean }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      onClick={onClick}
      disabled={busy}
      className={cn(
        'w-[24px] h-[24px] flex items-center justify-center rounded border border-transparent text-muted-foreground hover:border-border',
        danger ? 'hover:text-destructive' : 'hover:text-foreground',
      )}
    >
      {busy ? <LoadingIcon className="w-3.5 h-3.5" strokeWidth={1.5} /> : children}
    </button>
  );
}

function UploadPanel({
  target, onClose, onSaved,
}: { target: IocListSummary | null; onClose: () => void; onSaved: () => void }) {
  const { toast } = useToast();
  const fileInput = useRef<HTMLInputElement>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [risk, setRisk] = useState('75');
  const [tags, setTags] = useState('');
  const [content, setContent] = useState('');
  const [format, setFormat] = useState<IocUploadFormat>('text');
  const [mode, setMode] = useState<'append' | 'replace'>('append');
  const [expiry, setExpiry] = useState<ExpiryValue>(NO_EXPIRY);
  const [context, setContext] = useState('');
  const expiresAt = expiryInstant(expiry);

  const save = useMutation({
    mutationFn: async () => {
      const riskScore = Number(risk);
      const payload = {
        content: content.trim() ? content : undefined,
        format,
        default_risk_score: Number.isFinite(riskScore) ? riskScore : undefined,
        default_tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        default_expires_at: expiryInstant(expiry) ?? undefined,
        default_note: context.trim() || undefined,
      };
      return target
        ? api.iocLists.update(target.id, { ...payload, mode })
        : api.iocLists.create({ ...payload, name: name.trim(), description: description.trim() || undefined });
    },
    onSuccess: (list) => {
      toast({ title: target ? 'IOC list updated' : 'IOC list created', description: `${list.name}: ${list.indicator_count.toLocaleString()} indicators. Publish to start matching.` });
      onSaved();
    },
    onError: (err) => toast({ title: 'Upload rejected', description: errorMessage(err), variant: 'destructive' }),
  });

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setFormat(uploadFormatFor(file.name));
    setContent(await file.text());
  };

  const label = 'text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70';
  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-[12.5px] font-semibold text-foreground">
          {target ? <>Upload to <span className="font-mono">{target.name}</span></> : 'New IOC list'}
        </span>
        <span className="flex-1" />
        <button type="button" onClick={onClose} className="text-[11px] font-mono text-muted-foreground hover:text-foreground">
          cancel
        </button>
      </div>
      <div className="grid grid-cols-[1fr_1fr_90px_1fr] gap-3">
        {!target && (
          <>
            <label className="space-y-1">
              <span className={label}>name</span>
              <input className={cn(inputClass, 'font-mono')} value={name} onChange={(e) => setName(e.target.value)} placeholder="apt29-infra" />
            </label>
            <label className="space-y-1">
              <span className={label}>description</span>
              <input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="optional" />
            </label>
          </>
        )}
        {target && (
          <label className="space-y-1 col-span-2">
            <span className={label}>mode</span>
            <select className={cn(inputClass, 'font-mono')} value={mode} onChange={(e) => setMode(e.target.value as 'append' | 'replace')}>
              <option value="append">append (same value: new row wins)</option>
              <option value="replace">replace whole list</option>
            </select>
          </label>
        )}
        <label className="space-y-1">
          <span className={label}>default risk</span>
          <input className={cn(inputClass, 'font-mono tabular-nums')} value={risk} onChange={(e) => setRisk(e.target.value)} inputMode="numeric" />
        </label>
        <label className="space-y-1">
          <span className={label}>default tags</span>
          <input className={cn(inputClass, 'font-mono')} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="c2, phishing" />
        </label>
      </div>
      <div className="flex items-end gap-3">
        <div className="space-y-1">
          <span className={label}>expires</span>
          <ExpirySelect value={expiry} onChange={setExpiry} />
        </div>
        <label className="space-y-1 flex-1">
          <span className={label}>context</span>
          <input
            className={cn(inputClass, 'font-mono')}
            value={context}
            onChange={(e) => setContext(e.target.value)}
            maxLength={500}
            placeholder="optional: incident or case ref"
          />
        </label>
      </div>
      <p className="text-[10.5px] text-muted-foreground -mt-1">
        Expiry and context apply to indicators without their own <span className="font-mono">expires_at</span> /{' '}
        <span className="font-mono">note</span>. Expired indicators stop matching but stay in the list.
      </p>
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className={label}>indicators</span>
          <select
            className="h-[22px] px-1 rounded border border-border bg-card text-[10.5px] font-mono"
            value={format}
            onChange={(e) => setFormat(e.target.value as IocUploadFormat)}
          >
            <option value="text">one per line</option>
            <option value="csv">csv</option>
            <option value="json">json</option>
          </select>
          <span className="flex-1" />
          <input ref={fileInput} type="file" accept=".csv,.json,.txt,.list" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
          <button
            type="button"
            onClick={() => fileInput.current?.click()}
            className="h-[22px] px-2 rounded border border-border text-[10.5px] font-mono text-muted-foreground hover:text-foreground flex items-center gap-1"
          >
            <Upload className="w-3 h-3" strokeWidth={1.5} /> file
          </button>
        </div>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={6}
          spellCheck={false}
          placeholder={'45.33.32.156\n198.51.100.0/28\nevil[.]example\nhxxps://evil.example/login\n9dfc3317c19f4ca2a1e6d09f180a9dbd01a65632f5f2c5cc2c52f8f186807db7\nphisher@evil.example'}
          className="w-full px-2 py-1.5 rounded-md border border-border bg-background text-[11.5px] font-mono text-foreground placeholder:text-muted-foreground/50 outline-none focus:border-primary/50"
        />
        <p className="text-[10.5px] text-muted-foreground">
          IPs, CIDRs (≤ 256 addresses), domains, MD5/SHA-1/SHA-256/SHA-512, URLs, e-mail. Defanged forms are accepted.
          CSV columns: <span className="font-mono">indicator, type, risk_score, tags (a;b), expires_at, note</span>. Max 50,000 per list.
        </p>
      </div>
      <div className="flex justify-end">
        <button
          type="button"
          disabled={save.isPending || (!target && !name.trim()) || expiresAt === undefined}
          onClick={() => save.mutate()}
          className="h-[28px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 disabled:opacity-50 text-[12px] font-semibold flex items-center gap-1.5"
        >
          {save.isPending && <LoadingIcon className="w-3.5 h-3.5" strokeWidth={1.5} />}
          {target ? 'Save' : 'Create'}
        </button>
      </div>
    </div>
  );
}

export default IocLists;
