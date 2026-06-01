// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-509 — Lookup Tables list. Ports `design-ref/shadcn/lookup-landing.jsx`
// to the redesign density (10–13px, mono, 1px borders, no shadows). Replaces
// the pre-redesign 3-col card grid with a dense-table list + scope filters
// + sort buttons + search-as-you-type.

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ChevronRight,
  Database,
  Loader2,
  MoreHorizontal,
  Plus,
  Search,
  Trash2,
} from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useDeleteLookupTable, useLookupTables } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import type { LookupTable } from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatUTC } from '@/lib/date-utils';

import { SourceTag, type LookupSource } from '@/components/lookup/shared';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';

type Scope = 'all' | 'used' | 'unused' | 'mine';
type SortKey = 'updated' | 'name' | 'rows' | 'used';

const SCOPES: Array<{ id: Scope; label: string }> = [
  { id: 'all',    label: 'All' },
  { id: 'used',   label: 'In use' },
  { id: 'unused', label: 'Unused' },
  { id: 'mine',   label: 'Mine' },
];

const SORT_KEYS: SortKey[] = ['updated', 'name', 'rows', 'used'];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Backend doesn't (yet) return `source` / `usedBy`. Derive what we can
// client-side; remaining fields surface as `—` until the API catches up.
// Owner is now wired (NAN-514) — the LookupRow renders `table.created_by`
// directly with `—` fallback for legacy rows.
// `STUB` chip pattern from the matches port: visible marker so design review
// can see what's not wired.
function deriveSource(_table: LookupTable): LookupSource {
  // TODO(NAN-509-followup): infer from ingestion job presence; for now every
  // table is presumed to come from "upload" since that's the legacy default.
  return 'upload';
}

export function LookupTables() {
  useDocumentTitle('Lookup tables');

  const navigate = useNavigate();
  const { toast } = useToast();
  const { data: tables, loading, refetch } = useLookupTables();
  const { mutate: deleteTable } = useDeleteLookupTable();

  const [query, setQuery] = useState('');
  const [scope, setScope] = useState<Scope>('all');
  const [sort, setSort] = useState<SortKey>('updated');
  const [tableToDelete, setTableToDelete] = useState<LookupTable | null>(null);

  const all = useMemo<LookupTable[]>(() => tables ?? [], [tables]);

  // STUBs: backend doesn't return usedBy yet, so "used" / "unused" filters
  // are no-ops until we wire it. Mine filter falls back to all today.
  const filtered = useMemo<LookupTable[]>(() => {
    let list = all.slice();
    const needle = query.trim().toLowerCase();
    if (needle) {
      list = list.filter((t) =>
        t.name.toLowerCase().includes(needle) ||
        (t.description?.toLowerCase() ?? '').includes(needle),
      );
    }
    if (sort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
    else if (sort === 'rows') list.sort((a, b) => b.row_count - a.row_count);
    else if (sort === 'used') list.sort((a, b) => b.row_count - a.row_count); // STUB: usedBy proxy
    else list.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return list;
  }, [all, query, sort]);

  const totalRows = useMemo(() => all.reduce((acc, t) => acc + t.row_count, 0), [all]);

  const counts: Record<Scope, number> = {
    all:    all.length,
    used:   0,           // STUB: API doesn't expose usage today
    unused: all.length,  // STUB: every table reads as "unused" until wired
    mine:   all.length,  // STUB: ownership wiring not in API
  };

  const handleDelete = async () => {
    if (!tableToDelete) return;
    try {
      await deleteTable(tableToDelete.name);
      toast({ title: 'Lookup table deleted', description: tableToDelete.name });
      setTableToDelete(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Failed to delete',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  return (
    <div
      className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 flex-col bg-background"
      style={{ containerType: 'inline-size' }}
    >
      {/* Header — global TopBar (AppBreadcrumbs) renders the breadcrumb */}
      <div className="shrink-0 px-6 pt-6 pb-3 flex items-end gap-3 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-[20px] font-semibold tracking-[-0.015em] text-foreground">
            Lookup tables
          </h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            <span className="font-mono tabular-nums">{all.length.toLocaleString()}</span>{' '}
            table{all.length === 1 ? '' : 's'}
            {' · '}
            <span className="font-mono tabular-nums">{totalRows.toLocaleString()}</span>{' '}
            row{totalRows === 1 ? '' : 's'} total
          </p>
        </div>
        <span className="flex-1" />
        <div className="relative w-[240px]">
          <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" strokeWidth={2} />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="search tables…"
            className="h-[30px] w-full pl-7 pr-2 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => navigate('/rules/lookup-tables/new')}
          className="h-[30px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 flex items-center gap-1.5 text-[12px] font-semibold"
        >
          <Plus className="w-[13px] h-[13px]" strokeWidth={2} />
          New lookup table
        </button>
      </div>

      {/* Toolbar — scope filters + sort */}
      <div className="shrink-0 px-6 pb-3 flex items-center gap-2 flex-wrap">
        {SCOPES.map((s) => {
          const active = scope === s.id;
          return (
            <button
              key={s.id}
              type="button"
              onClick={() => setScope(s.id)}
              className={cn(
                'h-[26px] px-2.5 rounded-md flex items-center gap-1.5 text-[11.5px] font-mono border transition-colors',
                active
                  ? 'bg-primary/10 text-primary border-primary/40'
                  : 'border-border text-muted-foreground hover:text-foreground hover:border-border/80',
              )}
            >
              {s.label}
              <span
                className={cn(
                  'text-[10px] tabular-nums',
                  active ? 'text-primary/70' : 'text-muted-foreground/60',
                )}
              >
                {counts[s.id]}
              </span>
            </button>
          );
        })}
        <span className="flex-1" />
        <div className="flex items-center gap-1 text-[10.5px] font-mono text-muted-foreground/70">
          <span>sort</span>
          {SORT_KEYS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSort(s)}
              className={cn(
                'px-1.5 py-0.5 rounded-sm transition-colors',
                sort === s ? 'bg-primary/10 text-primary' : 'hover:text-foreground',
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 min-h-0 overflow-y-auto px-6 pb-6">
        {loading ? (
          <div className="rounded-lg border border-border bg-card p-12 flex items-center justify-center">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" strokeWidth={2} />
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            {/* Column headers */}
            <div className="h-[28px] px-4 flex items-center gap-3 border-b border-border text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
              <span className="w-[13px]" />
              <span className="flex-1">name</span>
              <span className="w-[80px] text-right">rows</span>
              <span className="w-[60px] text-right">size</span>
              <span className="w-[80px]">source</span>
              <span className="w-[90px]">owner</span>
              <span className="w-[72px] text-right">used by</span>
              <span className="w-[76px] text-right">updated</span>
              <span className="w-[24px]" />
            </div>

            {filtered.length === 0 ? (
              <div className="py-16 text-center text-[11.5px] font-mono text-muted-foreground">
                {all.length === 0 ? 'No lookup tables yet.' : 'No tables match.'}
              </div>
            ) : (
              filtered.map((t, i) => (
                <LookupRow
                  key={t.id}
                  table={t}
                  isLast={i === filtered.length - 1}
                  onOpen={() => navigate(`/rules/lookup-tables/${encodeURIComponent(t.name)}`)}
                  onDelete={() => setTableToDelete(t)}
                />
              ))
            )}
          </div>
        )}
      </div>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!tableToDelete}
        onOpenChange={(open) => !open && setTableToDelete(null)}
        variant="danger"
        title="Delete lookup table"
        description={
          <>
            Permanently delete <span className="font-mono">{tableToDelete?.name}</span>? All rows
            and ingestion config are removed; rules referencing it will fail until rewired.
          </>
        }
        confirmLabel="Delete"
        onConfirm={handleDelete}
      />
    </div>
  );
}

// ------------------------------------------------------------------
// Row
// ------------------------------------------------------------------

interface LookupRowProps {
  table: LookupTable;
  isLast: boolean;
  onOpen: () => void;
  onDelete: () => void;
}

function LookupRow({ table, isLast, onOpen, onDelete }: LookupRowProps) {
  const source = deriveSource(table);
  return (
    <div
      className={cn(
        'group w-full flex items-center gap-3 px-4 py-[10px] hover:bg-primary/[0.04] transition-colors',
        !isLast && 'border-b border-border/40',
      )}
    >
      <Database className="w-[13px] h-[13px] text-muted-foreground shrink-0" strokeWidth={2} />
      <button
        type="button"
        onClick={onOpen}
        className="flex-1 min-w-0 text-left"
      >
        <div className="flex items-center gap-2">
          <span className="text-[12.5px] font-mono text-foreground truncate group-hover:text-primary transition-colors">
            {table.name}
          </span>
          {table.primary_key && (
            <span className="font-mono text-[9.5px] text-muted-foreground/70">
              pk: <span className="text-foreground/80">{table.primary_key}</span>
            </span>
          )}
        </div>
        {table.description && (
          <div className="text-[10.5px] text-muted-foreground truncate mt-0.5">
            {table.description}
          </div>
        )}
      </button>
      <span className="w-[80px] text-[11px] font-mono text-foreground/80 text-right tabular-nums">
        {table.row_count.toLocaleString()}
      </span>
      <span className="w-[60px] text-[10.5px] font-mono text-muted-foreground text-right">
        {formatBytes(table.size_bytes)}
      </span>
      <div className="w-[80px]">
        <SourceTag source={source} />
      </div>
      <span
        className={cn(
          'w-[90px] text-[10.5px] font-mono truncate',
          table.created_by ? 'text-foreground/80' : 'text-muted-foreground/60',
        )}
        title={table.created_by?.email}
      >
        {table.created_by?.name || table.created_by?.email || '—'}
      </span>
      <span className="w-[72px] text-[11px] font-mono text-right tabular-nums text-muted-foreground/60">
        —
      </span>
      <span className="w-[76px] text-[10.5px] font-mono text-muted-foreground text-right truncate">
        {formatRelativeUpdated(table.updated_at)}
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            onClick={(e) => e.stopPropagation()}
            className="w-[24px] h-[24px] flex items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-foreground/5 opacity-0 group-hover:opacity-100 transition-opacity"
            aria-label="Row actions"
          >
            <MoreHorizontal className="w-3.5 h-3.5" strokeWidth={2} />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={onOpen}>
            <ChevronRight className="w-3.5 h-3.5 mr-2" strokeWidth={2} />
            Open
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={onDelete}
            className="text-destructive focus:text-destructive focus:bg-destructive/10"
          >
            <Trash2 className="w-3.5 h-3.5 mr-2" strokeWidth={2} />
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

function formatRelativeUpdated(iso: string): string {
  // Mockup uses "2h" / "Apr 19, 14:22" — keep it short. Full UTC available
  // on hover via title (caller can wrap in <Tooltip>); for now we render
  // the short ISO date to match the table density.
  const d = new Date(iso);
  if (isNaN(d.getTime())) return formatUTC(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffH = Math.round(diffMin / 60);
  if (diffH < 24) return `${diffH}h ago`;
  const diffD = Math.round(diffH / 24);
  if (diffD < 30) return `${diffD}d ago`;
  return d.toISOString().slice(0, 10);
}

export default LookupTables;
