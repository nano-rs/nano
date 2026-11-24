// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Saved Queries palette (NAN-373 Phase 3)
 *
 * Net-new UI that replaces the old Search Hub drawer. Mirrors
 * `design-ref/shadcn/saved-queries.jsx` — a command-palette-style modal
 * with a left sidebar of smart groups + log sources and a main area for
 * the query list. Keyboard-navigable (↑↓/↵/esc).
 *
 * Data model note: mockup's `folder`, `pinned`, and `freq` fields don't
 * exist on our `SavedSearch` yet. We:
 *   - infer the log source (`metadata.log_source`) by regex-scanning the
 *     query (fallback "other")
 *   - track `pinned` in localStorage per-user (lightweight until backend
 *     gets a real pinned flag)
 *   - skip `folder` and `freq` in the UI for now
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { X, Search, Bookmark, User, Users, Clock, Play, Edit3, Share2, CalendarClock, Trash2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import type { SavedSearch, SavedSearchTimeRange } from '@/lib/api';
import { extractLogSource } from './saved-query-log-source';
import { Term } from '@/components/ui/term';

interface SavedQueriesPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  savedSearches: SavedSearch[];
  sharedSearches?: SavedSearch[];
  currentUserId?: string;
  /** NAN-5311: `timeRange` is the window the query was saved with, when it has one. */
  onSelectQuery: (query: string, mode?: 'piped' | 'sql', timeRange?: SavedSearchTimeRange) => void;
  /**
   * NAN-5695: save an edit of one of the caller's own queries. Rejecting
   * keeps the editor open and shows the error. Without it, no Edit action.
   */
  onUpdateQuery?: (id: string, changes: SavedQueryEdit) => Promise<unknown>;
  onShareQuery?: (id: string) => void;
  /**
   * NAN-5695: delete one of the caller's own queries (after confirmation).
   * Without it, no Delete action.
   */
  onDeleteQuery?: (id: string) => Promise<unknown>;
  /** NAN-1793: schedule this saved query as a recurring report. */
  onScheduleQuery?: (query: { id: string | number; name: string; query: string }) => void;
}

/** The fields an analyst can edit on a saved query (NAN-5695). */
export interface SavedQueryEdit {
  name: string;
  query: string;
  /** Empty string clears the description. */
  description: string;
}

const PINNED_KEY = 'nanosiem-saved-queries-pinned';

function loadPinned(): Set<string> {
  try {
    const raw = localStorage.getItem(PINNED_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr : []);
  } catch {
    return new Set();
  }
}

function savePinned(set: Set<string>) {
  try {
    localStorage.setItem(PINNED_KEY, JSON.stringify(Array.from(set)));
  } catch { /* ignore */ }
}


function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = Math.max(0, now - then);
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  const weeks = Math.floor(days / 7);
  if (weeks < 4) return `${weeks}w ago`;
  return new Date(iso).toLocaleDateString();
}

interface EnrichedQuery {
  id: string;
  name: string;
  query: string;
  description: string;
  queryMode: 'piped' | 'sql';
  timeRange?: SavedSearchTimeRange;
  logSource: string;
  updatedAt: string;
  last: string;
  isMine: boolean;
  shared: boolean;
  pinned: boolean;
}

function enrich(
  searches: SavedSearch[],
  pinned: Set<string>,
  currentUserId: string | undefined,
): EnrichedQuery[] {
  return searches.map(s => ({
    id: s.id,
    name: s.name,
    query: s.query,
    description: s.description ?? '',
    queryMode: s.query_mode,
    timeRange: s.time_range,
    logSource: extractLogSource(s.query),
    updatedAt: s.updated_at,
    last: formatRelative(s.updated_at),
    isMine: currentUserId ? s.user_id === currentUserId : true,
    shared: s.visibility === 'public' || s.visibility === 'group',
    pinned: pinned.has(s.id),
  }));
}

const SectionLabel = ({ children }: { children: React.ReactNode }) => (
  <div className="px-2.5 pt-3 pb-1 font-mono text-[9.5px] tracking-[0.14em] uppercase text-muted-foreground/60 font-semibold">
    {children}
  </div>
);

function SidebarItem({
  active,
  label,
  count,
  icon,
  onClick,
  nested,
}: {
  active?: boolean;
  label: string;
  count: number;
  icon?: React.ReactNode;
  onClick: () => void;
  nested?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-2 px-2.5 py-1.5 rounded-sm cursor-pointer text-[12px] text-left transition-colors',
        nested && 'pl-5',
        active ? 'bg-primary/10 text-foreground' : 'text-muted-foreground hover:bg-foreground/5',
      )}
    >
      {icon && <span className={cn('shrink-0', active ? 'text-primary' : 'text-muted-foreground')}>{icon}</span>}
      <span className="flex-1 truncate">{label}</span>
      <span className={cn('font-mono text-[10px] tabular-nums', active ? 'text-primary' : 'text-muted-foreground/70')}>
        {count}
      </span>
    </button>
  );
}

function QueryRow({
  item,
  selected,
  onHover,
  onSelect,
  onTogglePin,
  onEdit,
  onShare,
  onSchedule,
  onDelete,
}: {
  item: EnrichedQuery;
  selected: boolean;
  onHover: () => void;
  onSelect: () => void;
  onTogglePin: () => void;
  onEdit?: () => void;
  onShare?: () => void;
  onSchedule?: () => void;
  onDelete?: () => void;
}) {
  return (
    <div
      data-testid="saved-query-row"
      data-saved-query-id={item.id}
      onMouseEnter={onHover}
      onClick={onSelect}
      className={cn(
        'group px-3 py-2.5 rounded-sm cursor-pointer border border-transparent relative',
        selected ? 'bg-primary/8 border-primary/20' : 'hover:bg-foreground/[0.03]',
      )}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onTogglePin(); }}
          className={cn(
            'shrink-0 p-0.5 rounded transition-colors',
            item.pinned ? 'text-primary hover:text-primary/80' : 'text-muted-foreground/40 hover:text-muted-foreground opacity-0 group-hover:opacity-100',
            selected && 'opacity-100',
          )}
          title={item.pinned ? 'Unpin' : 'Pin'}
          aria-label={item.pinned ? 'Unpin query' : 'Pin query'}
        >
          <Bookmark className="w-[11px] h-[11px]" fill={item.pinned ? 'currentColor' : 'none'} />
        </button>
        <span className="text-[13px] text-foreground font-medium truncate flex-1">{item.name}</span>
        <div
          className={cn(
            'flex items-center gap-0.5 shrink-0 transition-opacity',
            selected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100',
          )}
        >
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onSelect(); }}
            className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
            title="Run"
            aria-label="Run query"
          >
            <Play className="w-[12px] h-[12px]" />
          </button>
          {onEdit && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onEdit(); }}
              className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
              title="Edit"
              aria-label="Edit query"
            >
              <Edit3 className="w-[12px] h-[12px]" />
            </button>
          )}
          {onShare && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onShare(); }}
              className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
              title="Share"
              aria-label="Share query"
            >
              <Share2 className="w-[12px] h-[12px]" />
            </button>
          )}
          {onSchedule && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onSchedule(); }}
              className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
              title="Schedule report"
              aria-label="Schedule report"
            >
              <CalendarClock className="w-[12px] h-[12px]" />
            </button>
          )}
          {onDelete && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onDelete(); }}
              className="p-1 rounded hover:bg-red-500/10 text-muted-foreground hover:text-red-400"
              title="Delete"
              aria-label="Delete query"
            >
              <Trash2 className="w-[12px] h-[12px]" />
            </button>
          )}
        </div>
      </div>
      {item.description && (
        <div className="text-[11.5px] text-muted-foreground truncate mb-1 pl-[1px]" data-testid="saved-query-description">
          {item.description}
        </div>
      )}
      <div className="font-mono text-[11px] text-foreground/70 truncate mb-1.5 pl-[1px]">{item.query}</div>
      <div className="flex items-center gap-2.5 text-[10.5px] text-muted-foreground font-mono">
        <span className="inline-flex items-center gap-1">
          <Clock className="w-[10px] h-[10px]" />
          {item.last}
        </span>
        <span className="w-0.5 h-0.5 rounded-full bg-muted-foreground/40" />
        <span className="text-muted-foreground/80">{item.logSource}</span>
        {item.shared && (
          <>
            <span className="w-0.5 h-0.5 rounded-full bg-muted-foreground/40" />
            <span className="text-amber-300/80">shared</span>
          </>
        )}
        <span className="w-0.5 h-0.5 rounded-full bg-muted-foreground/40" />
        <span className="text-muted-foreground/70 uppercase tracking-wide">{item.queryMode}</span>
      </div>
    </div>
  );
}

const EDIT_LABEL_CLS = 'block font-mono text-[10px] tracking-[0.14em] uppercase text-muted-foreground font-semibold mb-1';
const EDIT_FIELD_CLS = 'w-full px-2.5 bg-background border border-border rounded-md text-[12px] outline-none focus:border-primary/50';

/** Inline editor for one saved query's name, query and description (NAN-5695). */
function QueryEditForm({
  item,
  onSave,
  onCancel,
}: {
  item: EnrichedQuery;
  onSave: (changes: SavedQueryEdit) => Promise<unknown>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(item.name);
  const [query, setQuery] = useState(item.query);
  const [description, setDescription] = useState(item.description);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canSave = name.trim().length > 0 && query.trim().length > 0 && !saving;

  const save = async () => {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      await onSave({ name: name.trim(), query: query.trim(), description: description.trim() });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save the query');
      setSaving(false);
    }
  };

  return (
    <form
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => {
        e.stopPropagation();
        if (e.key === 'Escape') { e.preventDefault(); onCancel(); }
      }}
      onSubmit={(e) => { e.preventDefault(); void save(); }}
      className="px-3 py-2.5 rounded-sm border border-primary/30 bg-primary/[0.04] space-y-2"
      aria-label={`Edit ${item.name}`}
      data-testid="saved-query-edit-form"
    >
      <div>
        <label htmlFor={`sq-edit-name-${item.id}`} className={EDIT_LABEL_CLS}>Name</label>
        <input
          id={`sq-edit-name-${item.id}`}
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={cn(EDIT_FIELD_CLS, 'h-7')}
        />
      </div>
      <div>
        <label htmlFor={`sq-edit-query-${item.id}`} className={EDIT_LABEL_CLS}>Query</label>
        <textarea
          id={`sq-edit-query-${item.id}`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={3}
          spellCheck={false}
          className={cn(EDIT_FIELD_CLS, 'py-1.5 font-mono text-[11px] resize-y')}
        />
      </div>
      <div>
        <label htmlFor={`sq-edit-desc-${item.id}`} className={EDIT_LABEL_CLS}>
          Description <span className="text-muted-foreground/60 normal-case tracking-normal">(optional)</span>
        </label>
        <textarea
          id={`sq-edit-desc-${item.id}`}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={2}
          placeholder="Short explanation for your team"
          className={cn(EDIT_FIELD_CLS, 'py-1.5 resize-none')}
        />
      </div>
      {error && <div role="alert" className="text-[11px] text-red-400">{error}</div>}
      <div className="flex items-center justify-end gap-1.5">
        <button
          type="button"
          onClick={onCancel}
          disabled={saving}
          className="h-7 px-2.5 rounded-md border border-border text-[11.5px] text-muted-foreground hover:text-foreground hover:bg-foreground/5"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={!canSave}
          className="h-7 px-2.5 rounded-md bg-primary text-primary-foreground text-[11.5px] font-medium disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </form>
  );
}

export function SavedQueriesPalette({
  open,
  onOpenChange,
  savedSearches,
  sharedSearches = [],
  currentUserId,
  onSelectQuery,
  onUpdateQuery,
  onShareQuery,
  onDeleteQuery,
  onScheduleQuery,
}: SavedQueriesPaletteProps) {
  const [filter, setFilter] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<EnrichedQuery | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [scope, setScope] = useState<string>('all'); // 'all' | 'pinned' | 'mine' | 'shared' | 'recent' | `type:${st}`
  const [selIdx, setSelIdx] = useState(0);
  const [pinned, setPinned] = useState<Set<string>>(() => loadPinned());
  const inputRef = useRef<HTMLInputElement>(null);

  // Merge saved + shared, dedup by id, then enrich
  const all = useMemo(() => {
    const merged = new Map<string, SavedSearch>();
    for (const s of savedSearches) merged.set(s.id, s);
    for (const s of sharedSearches) if (!merged.has(s.id)) merged.set(s.id, s);
    return enrich(Array.from(merged.values()), pinned, currentUserId);
  }, [savedSearches, sharedSearches, pinned, currentUserId]);

  // Compute counts for sidebar badges
  const counts = useMemo(() => {
    const logSourceMap = new Map<string, number>();
    for (const q of all) logSourceMap.set(q.logSource, (logSourceMap.get(q.logSource) ?? 0) + 1);
    return {
      all: all.length,
      pinned: all.filter(q => q.pinned).length,
      mine: all.filter(q => q.isMine).length,
      shared: all.filter(q => q.shared).length,
      recent: Math.min(5, all.length),
      logSource: Array.from(logSourceMap.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([label, count]) => ({ id: label, label, count })),
    };
  }, [all]);

  // Apply scope + filter
  const filtered = useMemo(() => {
    let items = all;
    if (scope === 'pinned') items = items.filter(q => q.pinned);
    else if (scope === 'mine') items = items.filter(q => q.isMine);
    else if (scope === 'shared') items = items.filter(q => q.shared);
    else if (scope === 'recent') {
      items = [...items].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()).slice(0, 5);
    } else if (scope.startsWith('type:')) {
      const st = scope.slice(5);
      items = items.filter(q => q.logSource === st);
    }
    const f = filter.trim().toLowerCase();
    if (f) {
      items = items.filter(q =>
        q.name.toLowerCase().includes(f) ||
        q.query.toLowerCase().includes(f) ||
        q.description.toLowerCase().includes(f) ||
        q.logSource.toLowerCase().includes(f)
      );
    }
    return items;
  }, [all, scope, filter]);

  // Reset selection when results change
  useEffect(() => { setSelIdx(0); }, [filter, scope]);

  // Focus input + reset state when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 30);
      setFilter('');
      setSelIdx(0);
      setEditingId(null);
      setDeleteTarget(null);
      setDeleteError(null);
    }
  }, [open]);

  // Close on Escape — unless an edit or a delete confirmation owns the key.
  useEffect(() => {
    if (!open || editingId || deleteTarget) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onOpenChange, editingId, deleteTarget]);

  // ConfirmDialog closes itself on confirm (the shared pattern), so a failed
  // delete is reported in the palette, above the list.
  const confirmDelete = async () => {
    if (!deleteTarget || !onDeleteQuery) return;
    const target = deleteTarget;
    setDeleteTarget(null);
    setDeleteError(null);
    try {
      await onDeleteQuery(target.id);
      setPinned(prev => {
        if (!prev.has(target.id)) return prev;
        const next = new Set(prev);
        next.delete(target.id);
        savePinned(next);
        return next;
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'unknown error';
      setDeleteError(`Could not delete "${target.name}": ${reason}`);
    }
  };

  const togglePin = (id: string) => {
    setPinned(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      savePinned(next);
      return next;
    });
  };

  const runSelected = (q: EnrichedQuery) => {
    onSelectQuery(q.query, q.queryMode, q.timeRange);
    onOpenChange(false);
  };

  const onInputKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelIdx(i => Math.min(i + 1, filtered.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelIdx(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const sel = filtered[selIdx];
      if (sel) runSelected(sel);
    }
  };

  if (!open) return null;

  const selected = filtered[selIdx];

  return (
    <>
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[6vh] bg-black/50 backdrop-blur-[2px]"
      // Only a click on the backdrop itself closes the palette. React bubbles
      // clicks out of portals (the delete confirmation) through this tree, and
      // those must not close it: a failed delete reports its error here.
      onClick={(e) => {
        if (e.target === e.currentTarget && !deleteTarget) onOpenChange(false);
      }}
    >
      <div
        data-testid="saved-queries-palette"
        onClick={(e) => e.stopPropagation()}
        className="relative w-[860px] max-w-[90%] h-[540px] max-h-[85vh] bg-card border border-border rounded-xl shadow-[0_40px_100px_rgba(0,0,0,0.6)] overflow-hidden grid grid-cols-[220px_1fr]"
      >
        {/* Sidebar */}
        <div
          className="border-r border-border flex flex-col min-h-0 overflow-hidden"
          style={{ background: 'var(--panel)' }}
        >
          <div className="px-3 pt-3 pb-2 border-b border-border">
            <div className="font-mono text-[10px] tracking-[0.16em] uppercase text-muted-foreground font-semibold mb-1">
              <Term id="saved-query">Saved queries</Term>
            </div>
            <div className="text-[10.5px] text-muted-foreground/70">{all.length} total</div>
          </div>
          <div className="flex-1 overflow-y-auto py-1.5 scrollbar-thin px-1">
            <SectionLabel>Smart groups</SectionLabel>
            <SidebarItem active={scope === 'all'} label="All queries" count={counts.all} onClick={() => setScope('all')} />
            <SidebarItem active={scope === 'pinned'} label="Pinned" count={counts.pinned} icon={<Bookmark className="w-3 h-3" />} onClick={() => setScope('pinned')} />
            <SidebarItem active={scope === 'mine'} label="Mine" count={counts.mine} icon={<User className="w-3 h-3" />} onClick={() => setScope('mine')} />
            <SidebarItem active={scope === 'shared'} label="Shared with team" count={counts.shared} icon={<Users className="w-3 h-3" />} onClick={() => setScope('shared')} />
            <SidebarItem active={scope === 'recent'} label="Recently run" count={counts.recent} icon={<Clock className="w-3 h-3" />} onClick={() => setScope('recent')} />
            {counts.logSource.length > 0 && (
              <>
                <SectionLabel>Log source</SectionLabel>
                {counts.logSource.map(t => (
                  <SidebarItem
                    key={t.id}
                    active={scope === `type:${t.id}`}
                    label={t.label}
                    count={t.count}
                    onClick={() => setScope(`type:${t.id}`)}
                    nested
                  />
                ))}
              </>
            )}
          </div>
        </div>

        {/* Main */}
        <div className="flex flex-col min-h-0 overflow-hidden">
          <div className="relative border-b border-border">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-[14px] h-[14px] text-muted-foreground" />
            <input
              ref={inputRef}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={onInputKey}
              placeholder="Search saved queries by name, syntax, or log source…"
              className="w-full h-12 pl-10 pr-24 bg-transparent outline-none text-[13px] text-foreground placeholder:text-muted-foreground/70"
            />
            <div className="absolute right-3.5 top-1/2 -translate-y-1/2 font-mono text-[10px] text-muted-foreground flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded border border-border bg-foreground/5 text-muted-foreground">esc</kbd>
              {/* NAN-5778: the close lives in the header row, next to its esc hint,
                  so it can neither escape the palette nor paint over the hint. */}
              <button
                type="button"
                onClick={() => onOpenChange(false)}
                className="w-6 h-6 flex items-center justify-center rounded-md text-muted-foreground hover:bg-foreground/5 hover:text-foreground transition-colors"
                aria-label="Close"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {deleteError && (
            <div role="alert" className="mx-2 mt-2 px-2.5 py-1.5 rounded-sm border border-red-500/30 bg-red-500/5 text-[11px] text-red-400 flex items-center gap-2">
              <span className="flex-1 min-w-0 truncate">{deleteError}</span>
              <button type="button" onClick={() => setDeleteError(null)} aria-label="Dismiss" className="shrink-0 hover:text-red-300">
                <X className="w-3 h-3" />
              </button>
            </div>
          )}
          <div className="flex-1 overflow-y-auto scrollbar-thin p-2">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-16 text-muted-foreground">
                <Search className="w-6 h-6 opacity-40" />
                <div className="text-[12.5px] font-medium text-foreground/80">
                  {filter ? `No saved queries match "${filter}"` : 'No saved queries yet'}
                </div>
                <div className="text-[11px] text-muted-foreground/70">
                  {filter ? 'Try a different name, folder, or tag.' : 'Save a query from the search bar to keep it here.'}
                </div>
                {filter && (
                  <button
                    type="button"
                    onClick={() => setFilter('')}
                    className="mt-2 text-[11px] text-primary hover:text-primary/80 underline underline-offset-2"
                  >
                    Clear filter
                  </button>
                )}
              </div>
            ) : (
              filtered.map((q, i) => (
                editingId === q.id && onUpdateQuery ? (
                  <QueryEditForm
                    key={q.id}
                    item={q}
                    onCancel={() => setEditingId(null)}
                    onSave={async (changes) => {
                      await onUpdateQuery(q.id, changes);
                      setEditingId(null);
                    }}
                  />
                ) : (
                  <QueryRow
                    key={q.id}
                    item={q}
                    selected={i === selIdx}
                    onHover={() => setSelIdx(i)}
                    onSelect={() => runSelected(q)}
                    onTogglePin={() => togglePin(q.id)}
                    // NAN-5695: edit and delete are owner-only server-side, so
                    // they are offered only on the caller's own queries.
                    onEdit={onUpdateQuery && q.isMine ? () => setEditingId(q.id) : undefined}
                    onShare={onShareQuery ? () => onShareQuery(q.id) : undefined}
                    onSchedule={
                      onScheduleQuery
                        ? () => onScheduleQuery({ id: q.id, name: q.name, query: q.query })
                        : undefined
                    }
                    onDelete={
                      onDeleteQuery && q.isMine
                        ? () => { setDeleteError(null); setDeleteTarget(q); }
                        : undefined
                    }
                  />
                )
              ))
            )}
          </div>

          <div className="border-t border-border px-3 py-2 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-1">
                <kbd className="px-1 rounded border border-border bg-foreground/5">↑↓</kbd> navigate
              </span>
              <span className="inline-flex items-center gap-1">
                <kbd className="px-1 rounded border border-border bg-foreground/5">↵</kbd> run
              </span>
              <span className="inline-flex items-center gap-1">
                <kbd className="px-1 rounded border border-border bg-foreground/5">esc</kbd> close
              </span>
            </div>
            {selected && (
              <span className="text-muted-foreground/70">
                {selected.logSource} · {selected.queryMode}
              </span>
            )}
          </div>
        </div>

      </div>
    </div>

      {/* NAN-5695: delete confirmation, rendered outside the backdrop so its
          clicks never reach the backdrop's close handler. The studio layer
          sits above this palette's z-[100] overlay. */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}
        layer="studio"
        variant="danger"
        title="Delete saved query"
        description={
          <>
            Delete <span className="text-foreground font-medium">{deleteTarget?.name}</span>? Anyone it is shared
            with loses it too. This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        onConfirm={() => { void confirmDelete(); }}
      />
    </>
  );
}
