// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3882 — IOC list viewer. Entries are read a keyset page at a time with
// server-side search (prefix uses the value index; contains is a bounded
// scan that hands back a continuation cursor). The total comes from the list
// summary, never from a COUNT per keystroke.

import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { IocExpiryChange, IocListSummary, IocMatchMode, IocType } from '@/lib/api/ioc-lists';
import type { RetroListRow } from '@/lib/api/types';
import { fetchRetroPage } from '@/components/search/retro/useRetro';
import { RETRO_IOC_WINDOW_DAYS, lastDaysRange, retroListQuery, retroSearchUrl } from '@/components/search/retro/links';
import { cn } from '@/lib/utils';
import { ExpirySelect, NO_EXPIRY, expiryInstant, type ExpiryValue } from './IocExpirySelect';

const PAGE_SIZE = 100;
/** Indicators one hit count covers (one retro campaign page). */
const HITS_MAX = 500;
const TYPES: IocType[] = ['ip', 'domain', 'hash', 'url', 'email'];

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}

function shortDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace('T', ' ');
}

export function IocListViewer({ list }: { list: IocListSummary }) {
  const [search, setSearch] = useState('');
  const [match, setMatch] = useState<IocMatchMode>('prefix');
  const [type, setType] = useState<IocType | ''>('');
  const [hideExpired, setHideExpired] = useState(true);
  const q = useDebounced(search.trim(), 250);
  const present = TYPES.filter((t) => list.counts[t]);

  const entries = useInfiniteQuery({
    queryKey: ['ioc-lists', list.id, 'indicators', q, match, type, hideExpired, list.updated_at],
    queryFn: ({ pageParam }) =>
      api.iocLists.indicators(list.id, {
        q: q || undefined,
        match: q ? match : undefined,
        type: type || undefined,
        after: pageParam,
        limit: PAGE_SIZE,
        hide_expired: hideExpired,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    retry: false,
  });

  const rows = entries.data?.pages.flatMap((p) => p.indicators) ?? [];
  const last = entries.data?.pages[entries.data.pages.length - 1];
  const hits = useIndicatorHits(rows.map((r) => r.value));
  const filtered = Boolean(q || type || (hideExpired && list.expired_count));

  return (
    <div className="border-t border-border/60 bg-background/40 px-4 py-2 space-y-2" data-testid="ioc-list-viewer">
      <div className="flex items-center gap-2">
        <div className="relative w-[280px]">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" strokeWidth={1.5} />
          <input
            aria-label="Search indicators"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={match === 'prefix' ? 'value starts with…' : 'value contains…'}
            spellCheck={false}
            className="h-[24px] w-full pl-6 pr-2 rounded border border-border bg-card text-[11.5px] font-mono outline-none focus:border-primary/50"
          />
        </div>
        <select
          aria-label="Match mode"
          value={match}
          onChange={(e) => setMatch(e.target.value as IocMatchMode)}
          className="h-[24px] px-1 rounded border border-border bg-card text-[10.5px] font-mono"
        >
          <option value="prefix">starts with</option>
          <option value="contains">contains</option>
        </select>
        <select
          aria-label="Indicator type"
          value={type}
          onChange={(e) => setType(e.target.value as IocType | '')}
          className="h-[24px] px-1 rounded border border-border bg-card text-[10.5px] font-mono"
        >
          <option value="">all types</option>
          {(present.length ? present : TYPES).map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <label className="flex items-center gap-1 text-[10.5px] font-mono text-muted-foreground">
          <input type="checkbox" checked={hideExpired} onChange={(e) => setHideExpired(e.target.checked)} aria-label="Hide expired" />
          hide expired
          {list.expired_count ? <span className="tabular-nums">({list.expired_count.toLocaleString()})</span> : null}
        </label>
        <span className="flex-1" />
        <button
          type="button"
          onClick={hits.run}
          disabled={hits.loading || rows.length === 0}
          title={`Count log events matching the shown indicators over the last ${RETRO_IOC_WINDOW_DAYS} days (ingest and retro matches). Runs only when clicked.`}
          className="h-[22px] px-2 rounded border border-border text-[10.5px] font-mono text-muted-foreground hover:text-foreground disabled:opacity-50 flex items-center gap-1"
        >
          {hits.loading && <LoadingIcon className="w-3 h-3" strokeWidth={1.5} />}
          {hits.counts ? 'recount hits' : `count hits (${RETRO_IOC_WINDOW_DAYS}d)`}
        </button>
        {hits.error && (
          <span className="text-[10.5px] font-mono text-destructive truncate max-w-[220px]" title={hits.error}>
            {hits.error}
          </span>
        )}
        <span className="text-[10.5px] font-mono text-muted-foreground tabular-nums">
          {filtered ? `${rows.length.toLocaleString()}${entries.hasNextPage ? '+' : ''} shown` : `${rows.length.toLocaleString()} of ${list.indicator_count.toLocaleString()}`}
        </span>
      </div>

      <div className="rounded border border-border overflow-hidden">
        <div className="h-[24px] px-3 flex items-center gap-3 border-b border-border text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 bg-card">
          <span className="flex-1">value</span>
          <span className="w-[56px]">type</span>
          <span className="w-[40px] text-right">risk</span>
          <span className="w-[64px] text-right" title={`log events matching the indicator over the last ${RETRO_IOC_WINDOW_DAYS} days`}>hits {RETRO_IOC_WINDOW_DAYS}d</span>
          <span className="w-[180px]">tags</span>
          <span className="w-[120px]">expires</span>
          <span className="w-[120px]">added</span>
        </div>
        <div className="max-h-[360px] overflow-y-auto">
          {entries.isLoading ? (
            <div className="py-6 flex justify-center">
              <LoadingIcon className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
            </div>
          ) : entries.isError ? (
            <div className="py-6 text-center text-[11px] font-mono text-destructive">
              {entries.error instanceof Error ? entries.error.message : 'Indicators unavailable'}
            </div>
          ) : rows.length === 0 && !entries.hasNextPage ? (
            <div className="py-6 text-center text-[11px] font-mono text-muted-foreground">
              {filtered ? 'No matching indicators' : 'No indicators'}
            </div>
          ) : (
            rows.map((row) => (
              <div
                key={row.value}
                data-expired={row.expired || undefined}
                className={cn(
                  'h-[24px] px-3 flex items-center gap-3 border-b border-border/40 last:border-b-0 text-[11px]',
                  row.expired && 'opacity-50',
                )}
              >
                <span className={cn('flex-1 min-w-0 font-mono text-foreground truncate', row.expired && 'line-through')} title={row.note ?? undefined}>{row.value}</span>
                <span className="w-[56px] font-mono text-muted-foreground">{row.ioc_type}</span>
                <span className="w-[40px] text-right font-mono tabular-nums text-foreground/80">{row.risk_score}</span>
                <HitCount value={row.value} counts={hits.counts} />
                <span className="w-[180px] font-mono text-[10.5px] text-muted-foreground truncate">{row.tags.join(', ') || '—'}</span>
                <span className={cn('w-[120px] font-mono text-[10.5px] tabular-nums', row.expired ? 'text-destructive' : 'text-muted-foreground')}>
                  {shortDate(row.expires_at)}
                </span>
                <span className="w-[120px] font-mono text-[10.5px] text-muted-foreground tabular-nums">{shortDate(row.added_at)}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {entries.hasNextPage && (
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => entries.fetchNextPage()}
            disabled={entries.isFetchingNextPage}
            className={cn(
              'h-[22px] px-2 rounded border border-border text-[10.5px] font-mono text-muted-foreground hover:text-foreground flex items-center gap-1',
              entries.isFetchingNextPage && 'opacity-60',
            )}
          >
            {entries.isFetchingNextPage && <LoadingIcon className="w-3 h-3" strokeWidth={1.5} />}
            {last?.scan_limited ? 'keep searching' : 'load more'}
          </button>
          {last?.scan_limited && (
            <span className="text-[10.5px] font-mono text-muted-foreground">
              searched part of the list; more rows remain
            </span>
          )}
        </div>
      )}
      <ListExpiry list={list} />
    </div>
  );
}

interface IndicatorHits {
  /** Lowercased indicator -> matching events over the window; `null` until counted. */
  counts: Map<string, number> | null;
  loading: boolean;
  error: string | null;
  run: () => void;
}

/**
 * NAN-4169: per-indicator hit counts over the retro IOC window, through the
 * existing retro campaign view (`ioc in [..] | retro`): one list rollup for the
 * shown indicators. On request only — it is a background retro job on lean
 * tenants, never queued just by opening the list.
 */
function useIndicatorHits(values: string[]): IndicatorHits {
  const [counts, setCounts] = useState<Map<string, number> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const key = values.join('\n');
  const current = useRef(key);
  useEffect(() => {
    current.current = key;
    setCounts(null);
    setError(null);
  }, [key]);
  const run = () => {
    const shown = values.slice(0, HITS_MAX);
    if (shown.length === 0) return;
    const runKey = key;
    setLoading(true);
    setError(null);
    fetchRetroPage(
      { query: retroListQuery(shown), axis: 'indicator', offset: 0, limit: HITS_MAX },
      lastDaysRange(),
    )
      .then((response) => {
        // The shown rows changed while counting: drop the stale result.
        if (current.current !== runKey) return;
        const next = new Map<string, number>(shown.map((v) => [v.toLowerCase(), 0]));
        for (const row of (response.rows ?? []) as RetroListRow[]) next.set(row.value.toLowerCase(), row.hits);
        setCounts(next);
      })
      .catch((err) => current.current === runKey && setError(err instanceof Error ? err.message : 'Hit count failed'))
      .finally(() => setLoading(false));
  };
  return { counts, loading, error, run };
}

function HitCount({ value, counts }: { value: string; counts: Map<string, number> | null }) {
  const count = counts?.get(value.toLowerCase());
  if (count === undefined) {
    return <span className="w-[64px] text-right font-mono text-[10.5px] text-muted-foreground">—</span>;
  }
  if (count === 0) {
    return <span className="w-[64px] text-right font-mono tabular-nums text-muted-foreground">0</span>;
  }
  return (
    <Link
      to={retroSearchUrl(value)}
      title="Open in the retro view"
      className="w-[64px] text-right font-mono tabular-nums text-primary hover:underline"
    >
      {count.toLocaleString()}
    </Link>
  );
}

/** Whole-list expiry: set, clear, or purge entries already expired. */
function ListExpiry({ list }: { list: IocListSummary }) {
  const client = useQueryClient();
  const { toast } = useToast();
  const [value, setValue] = useState<ExpiryValue>({ ...NO_EXPIRY, choice: '30d' });
  const [confirmPurge, setConfirmPurge] = useState(false);
  const change = useMutation({
    mutationFn: (request: { expiry?: IocExpiryChange; purge_expired?: boolean }) => api.iocLists.update(list.id, request),
    onSuccess: (next, request) => {
      client.setQueryData<IocListSummary[]>(['ioc-lists'], (old) => old?.map((l) => (l.id === next.id ? next : l)));
      client.invalidateQueries({ queryKey: ['ioc-lists'] });
      toast({
        title: request.purge_expired ? 'Expired indicators purged' : 'Expiry updated',
        description: `${next.name}: ${next.indicator_count.toLocaleString()} indicators${next.publish_state === 'publishing' ? ' · re-publishing' : ''}`,
      });
      setConfirmPurge(false);
    },
    onError: (err) => toast({ title: 'Expiry change failed', description: err instanceof Error ? err.message : String(err), variant: 'destructive' }),
  });
  const at = expiryInstant(value);
  const busy = change.isPending || list.publish_state === 'publishing';
  const button = 'h-[22px] px-2 rounded border border-border text-[10.5px] font-mono text-muted-foreground hover:text-foreground disabled:opacity-50';
  return (
    <div className="flex items-center gap-2 text-[10.5px] font-mono text-muted-foreground" data-testid="ioc-list-expiry">
      <span>whole list</span>
      <span className="tabular-nums">
        {list.with_expiry != null ? `${list.with_expiry.toLocaleString()} with expiry` : ''}
        {list.next_expiry_at ? ` · next ${shortDate(list.next_expiry_at)}` : ''}
      </span>
      <span className="flex-1" />
      <ExpirySelect value={value} onChange={setValue} label="List expiry" />
      <button
        type="button"
        className={button}
        disabled={busy || value.choice === 'never' || !at}
        onClick={() => at && change.mutate({ expiry: { action: 'set', expires_at: at } })}
      >
        set expiry
      </button>
      <button type="button" className={button} disabled={busy} onClick={() => change.mutate({ expiry: { action: 'clear' } })}>
        clear expiry
      </button>
      <button type="button" className={cn(button, 'hover:text-destructive')} disabled={busy || !list.expired_count} onClick={() => setConfirmPurge(true)}>
        purge expired
      </button>
      <ConfirmDialog
        open={confirmPurge}
        onOpenChange={setConfirmPurge}
        variant="danger"
        title="Purge expired indicators"
        description={
          <>
            Delete <span className="font-mono tabular-nums">{(list.expired_count ?? 0).toLocaleString()}</span> expired
            indicators from <span className="font-mono">{list.name}</span>? They already no longer match; purging removes
            them from the list for good.
          </>
        }
        confirmLabel="Purge"
        onConfirm={() => change.mutate({ purge_expired: true })}
      />
    </div>
  );
}
