// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — left rule-picker rail. Folder tree grouped by `folderOf()` +
// sev dot + mode pill + search + Active/Archived tabs + New Rule button.

import React, { useMemo, useRef, useState } from 'react';
import {
  Archive,
  ArchiveRestore,
  ArrowDown,
  ArrowUp,
  Box,
  CircleCheck,
  ChevronRight,
  Cloud,
  Copy,
  Eye,
  Folder,
  FolderPlus,
  Globe,
  Pause,
  Play,
  Plus,
  Power,
  Search as SearchIcon,
  Shield,
  Trash2,
  User,
  X,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';
import { cn } from '@/lib/utils';
import type { DetectionRule } from '@/lib/api/types';
import {
  SEV_COLOR,
  MODE_META,
  displayMode,
  folderOf,
  folderKind,
  normalizeSeverity,
  type FolderKind,
} from './helpers';
import { FolderIconPicker } from './FolderIconPicker';
import { DEFAULT_FOLDER_ICON_SLUG, iconForSlug } from './folder-icons';

export interface RuleRailRowActions {
  onDuplicate?: (ruleId: string) => void;
  onArchive?: (ruleId: string) => void;
  onUnarchive?: (ruleId: string) => void;
  onDelete?: (ruleId: string) => void;
  onTogglePause?: (ruleId: string) => void;
  onPromote?: (ruleId: string) => void;
  onDemote?: (ruleId: string) => void;
  onSetMode?: (ruleId: string, mode: 'staging' | 'live' | 'alerting') => void;
  onViewMatches?: (ruleId: string) => void;
}

interface RuleRailProps {
  rules: DetectionRule[];
  selectedId: string | undefined;
  /** Rendered as an extra pinned row at the top of the Uncategorized folder. */
  draft?: { name: string; severity: string } | null;
  draftSelected?: boolean;
  onSelect: (id: string) => void;
  onCreateNew: () => void;
  /** Called when a rule is dragged onto a different folder header. */
  onMoveRule?: (ruleId: string, folder: string) => void;
  /** Per-row actions surfaced by right-click context menu. Omit to hide the menu. */
  rowActions?: RuleRailRowActions;
  loading?: boolean;
  /** Map of folder name → icon slug (NAN-730). Custom folders without a
      slug fall back to the generic folder glyph. Canonical folders ignore
      this map — they're product-curated. */
  folderSettings?: Record<string, string>;
  /** Called when the analyst sets/changes a custom folder's icon, either
      at create time (via "+ folder") or via right-click "Change icon…".
      Pass an empty slug or undefined to clear (folder reverts to default). */
  onSetFolderIcon?: (name: string, slug: string | undefined) => void;
}

// Normalize a folder string against the canonical five so "endpoint" and
// "Endpoint" collapse into the same group.
const CANONICAL_FOLDERS = ['Network', 'Identity', 'Endpoint', 'Cloud', 'Uncategorized'] as const;
function canonicalize(name: string): string {
  const lower = name.trim().toLowerCase();
  for (const c of CANONICAL_FOLDERS) {
    if (c.toLowerCase() === lower) return c;
  }
  return name;
}

// Mirrors the backend validator at
// nanosiem-core/src/models/detection_rule.rs:564 — alphanumeric, dash,
// underscore, ≤ 50 chars. We keep the frontend stricter (no leading dash,
// require length ≥ 1 after trim) so analysts get an immediate reject before
// the API would.
const CUSTOM_FOLDER_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$/;

function FolderIcon({ kind, slug }: { kind: FolderKind; slug?: string }) {
  // Canonical folders are product-curated — the kind icon always wins,
  // regardless of any folder_settings row a user may have set (NAN-730).
  if (kind === 'network') return <Globe className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />;
  if (kind === 'identity') return <User className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />;
  if (kind === 'endpoint') return <Box className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />;
  if (kind === 'cloud') return <Cloud className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />;
  // Custom folder — render the user's picked icon if set, else the generic
  // folder glyph (matches v1 behavior pre-NAN-730).
  const Component = iconForSlug(slug);
  return <Component className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />;
}

type RuleRowProps = {
  name: string;
  severity: string;
  modeKey: 'live' | 'staging' | 'paused' | 'unsaved';
  focused: boolean;
  onClick: () => void;
  onDragStart?: (e: React.DragEvent<HTMLButtonElement>) => void;
  draggable?: boolean;
};

// Renders the bare button. Forwarding all unknown props (incl. the
// onContextMenu that Radix's ContextMenuTrigger asChild merges in) is required
// for the shadcn ContextMenu wrapper in RuleRowWithContext to capture
// right-clicks on the row.
const RuleRow = React.forwardRef<
  HTMLButtonElement,
  RuleRowProps & React.ButtonHTMLAttributes<HTMLButtonElement>
>(function RuleRow({ name, severity, modeKey, focused, onClick, onDragStart, draggable, ...rest }, ref) {
  const sev = normalizeSeverity(severity);
  const mode = modeKey === 'unsaved' ? null : MODE_META[modeKey];
  return (
    <button
      ref={ref}
      onClick={onClick}
      type="button"
      draggable={draggable}
      onDragStart={onDragStart}
      className={cn(
        'w-full group flex items-center gap-2 px-2 py-1.5 rounded-md text-left transition-colors',
        focused ? 'bg-primary/10' : 'hover:bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)]',
        draggable && 'cursor-grab active:cursor-grabbing',
      )}
      {...rest}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_COLOR[sev] }} />
      <span className={cn('truncate text-[12px] font-mono', focused ? 'text-foreground' : 'text-foreground/80')}>
        {name}
      </span>
      {modeKey === 'unsaved' ? (
        <span className="ml-auto shrink-0 text-[9.5px] font-mono uppercase tracking-[0.08em] text-[var(--warning)]">
          unsaved
        </span>
      ) : mode ? (
        <span className={cn('ml-auto flex items-center gap-1 shrink-0 text-[9.5px] font-mono uppercase tracking-[0.08em]', mode.tone)}>
          <span className="w-1 h-1 rounded-full" style={{ background: mode.dotVar }} />
          {modeKey}
        </span>
      ) : null}
    </button>
  );
});

function RuleRowWithContext({
  rule,
  focused,
  draggable,
  onClick,
  onDragStart,
  actions,
}: {
  rule: DetectionRule;
  focused: boolean;
  draggable?: boolean;
  onClick: () => void;
  onDragStart?: (e: React.DragEvent<HTMLButtonElement>) => void;
  actions?: RuleRailRowActions;
}) {
  const row = (
    <RuleRow
      name={rule.name}
      severity={rule.severity}
      modeKey={displayMode(rule.mode)}
      focused={focused}
      onClick={onClick}
      draggable={draggable}
      onDragStart={onDragStart}
    />
  );

  if (!actions) return row;

  const paused = rule.mode === 'paused';
  const promotable = !paused && !rule.archived && (rule.mode === 'staging' || rule.mode === 'live');
  const demotable = !paused && !rule.archived && (rule.mode === 'live' || rule.mode === 'alerting');
  const showSetMode = Boolean(actions.onSetMode);

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{row}</ContextMenuTrigger>
      <ContextMenuContent className="w-52">
        {actions.onViewMatches && (
          <ContextMenuItem onClick={() => actions.onViewMatches?.(rule.id)}>
            <Eye className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            View matches
          </ContextMenuItem>
        )}
        {actions.onDuplicate && (
          <ContextMenuItem onClick={() => actions.onDuplicate?.(rule.id)}>
            <Copy className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Duplicate rule
          </ContextMenuItem>
        )}
        {(actions.onPromote || actions.onDemote || actions.onTogglePause || showSetMode) && <ContextMenuSeparator />}
        {actions.onPromote && promotable && (
          <ContextMenuItem onClick={() => actions.onPromote?.(rule.id)}>
            <ArrowUp className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Promote
          </ContextMenuItem>
        )}
        {actions.onDemote && demotable && (
          <ContextMenuItem onClick={() => actions.onDemote?.(rule.id)}>
            <ArrowDown className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Demote
          </ContextMenuItem>
        )}
        {actions.onTogglePause && !rule.archived && (
          <ContextMenuItem onClick={() => actions.onTogglePause?.(rule.id)}>
            {paused ? (
              <>
                <Play className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
                Resume
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
                Pause
              </>
            )}
          </ContextMenuItem>
        )}
        {showSetMode && (
          <ContextMenuSub>
            <ContextMenuSubTrigger>
              <Power className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
              Set mode
            </ContextMenuSubTrigger>
            <ContextMenuSubContent className="w-40">
              {(['staging', 'live', 'alerting'] as const).map((m) => (
                <ContextMenuItem
                  key={m}
                  onClick={() => actions.onSetMode?.(rule.id, m)}
                  disabled={rule.mode === m}
                >
                  <span className="capitalize">{m}</span>
                  {rule.mode === m && <CircleCheck className="w-3 h-3 ml-auto" strokeWidth={1.75} />}
                </ContextMenuItem>
              ))}
            </ContextMenuSubContent>
          </ContextMenuSub>
        )}
        {(actions.onArchive || actions.onUnarchive || actions.onDelete) && <ContextMenuSeparator />}
        {actions.onArchive && !rule.archived && (
          <ContextMenuItem onClick={() => actions.onArchive?.(rule.id)}>
            <Archive className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Archive
          </ContextMenuItem>
        )}
        {actions.onUnarchive && rule.archived && (
          <ContextMenuItem onClick={() => actions.onUnarchive?.(rule.id)}>
            <ArchiveRestore className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Unarchive
          </ContextMenuItem>
        )}
        {actions.onDelete && (
          <ContextMenuItem
            onClick={() => actions.onDelete?.(rule.id)}
            className="text-[var(--destructive,_#F87171)] focus:text-[var(--destructive,_#F87171)]"
          >
            <Trash2 className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Delete
          </ContextMenuItem>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}

export function RuleRail({ rules, selectedId, draft, draftSelected, onSelect, onCreateNew, onMoveRule, rowActions, loading, folderSettings, onSetFolderIcon }: RuleRailProps) {
  const [tab, setTab] = useState<'active' | 'archived'>('active');
  const [q, setQ] = useState('');
  const [openFolders, setOpenFolders] = useState<Record<string, boolean>>({});
  const [dragOverFolder, setDragOverFolder] = useState<string | null>(null);
  // User-created empty folders. Persists in component state until a rule lands
  // in one (at which point it's discoverable via `rules[].folder`). Empty
  // folders self-evict on next render once their rule count drops to zero —
  // intentional: keeps state self-cleaning without a rename/delete UI.
  const [pendingFolders, setPendingFolders] = useState<string[]>([]);
  const [folderInput, setFolderInput] = useState<string | null>(null);
  const [folderInputError, setFolderInputError] = useState<string | null>(null);
  const [folderInputIcon, setFolderInputIcon] = useState<string>(DEFAULT_FOLDER_ICON_SLUG);
  const folderInputRef = useRef<HTMLInputElement | null>(null);
  // Right-click "Change icon…" target for custom folders (NAN-730).
  const [iconEditFolder, setIconEditFolder] = useState<string | null>(null);
  // Right-click "Delete folder" confirmation target (NAN-732 follow-up).
  const [deleteFolderName, setDeleteFolderName] = useState<string | null>(null);

  const { folders, counts } = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const archivedWanted = tab === 'archived';
    const byFolder = new Map<string, DetectionRule[]>();

    // Seed the five canonical categories from the design ref so the folder
    // structure stays discoverable even before any rules land in them. Extra
    // categories derived from rule metadata get appended alphabetically.
    const CANONICAL = ['Network', 'Identity', 'Endpoint', 'Cloud', 'Uncategorized'];
    for (const name of CANONICAL) byFolder.set(name, []);

    for (const rule of rules) {
      const isArchived = Boolean(rule.archived);
      if (isArchived !== archivedWanted) continue;
      if (needle && !rule.name.toLowerCase().includes(needle)) continue;
      const folder = canonicalize(folderOf(rule));
      const list = byFolder.get(folder) ?? [];
      list.push(rule);
      byFolder.set(folder, list);
    }

    // Merge pending (just-created, still-empty) custom folders so they appear
    // in the rail before any rule lands in them. Skip ones whose name now
    // collides with a rule-backed folder (case-insensitive) — at that point
    // they're no longer pending.
    const existingLower = new Set(Array.from(byFolder.keys(), (n) => n.toLowerCase()));
    for (const name of pendingFolders) {
      if (!existingLower.has(name.toLowerCase())) {
        byFolder.set(name, []);
        existingLower.add(name.toLowerCase());
      }
    }
    // Also seed folders that are server-persisted via folder_settings but
    // have no rules yet (NAN-732). Without this, creating a folder + reload
    // before adding a rule made the folder vanish.
    if (folderSettings) {
      for (const name of Object.keys(folderSettings)) {
        if (!existingLower.has(name.toLowerCase())) {
          byFolder.set(name, []);
          existingLower.add(name.toLowerCase());
        }
      }
    }

    const canonicalSet = new Set(CANONICAL);
    const names = Array.from(byFolder.keys()).sort((a, b) => {
      const aC = canonicalSet.has(a);
      const bC = canonicalSet.has(b);
      if (aC && bC) return CANONICAL.indexOf(a) - CANONICAL.indexOf(b);
      if (aC) return -1;
      if (bC) return 1;
      return a.localeCompare(b);
    });

    return {
      folders: names.map((name) => ({
        name,
        kind: folderKind(name),
        children: (byFolder.get(name) ?? []).sort((a, b) => a.name.localeCompare(b.name)),
      })),
      counts: { total: rules.length, folders: names.length },
    };
  }, [rules, q, tab, pendingFolders, folderSettings]);

  // Dismiss the inline icon picker on outside click / Esc. Document-level
  // handlers because the panel lives inside ScrollArea and clicks anywhere
  // else in the rail (or outside it) should close it.
  React.useEffect(() => {
    if (iconEditFolder === null) return;
    const onPointerDown = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target) return;
      if (target.closest(`[data-folder-icon-panel="${iconEditFolder}"]`)) return;
      setIconEditFolder(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIconEditFolder(null);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [iconEditFolder]);

  // Drop pending entries once they're either rule-backed OR known to the
  // server via folder_settings (NAN-732). The pendingFolders state exists
  // only to give instant feedback while the create API call is in flight.
  React.useEffect(() => {
    if (pendingFolders.length === 0) return;
    const knownLower = new Set<string>([
      ...rules.map((r) => folderOf(r).toLowerCase()),
      ...Object.keys(folderSettings ?? {}).map((n) => n.toLowerCase()),
    ]);
    const stillPending = pendingFolders.filter((n) => !knownLower.has(n.toLowerCase()));
    if (stillPending.length !== pendingFolders.length) setPendingFolders(stillPending);
  }, [rules, pendingFolders, folderSettings]);

  const startCreateFolder = () => {
    setFolderInputError(null);
    setFolderInput('');
    setFolderInputIcon(DEFAULT_FOLDER_ICON_SLUG);
    // Defer focus to next paint so the input is mounted.
    requestAnimationFrame(() => folderInputRef.current?.focus());
  };

  const cancelCreateFolder = () => {
    setFolderInput(null);
    setFolderInputError(null);
    setFolderInputIcon(DEFAULT_FOLDER_ICON_SLUG);
  };

  const submitCreateFolder = () => {
    const raw = (folderInput ?? '').trim();
    if (!raw) {
      cancelCreateFolder();
      return;
    }
    if (!CUSTOM_FOLDER_RE.test(raw)) {
      setFolderInputError('Letters, numbers, dash, underscore. Up to 50 chars.');
      return;
    }
    const lower = raw.toLowerCase();
    // Reject collisions with canonical or already-known folders.
    const existing = new Set([
      ...CANONICAL_FOLDERS.map((c) => c.toLowerCase()),
      ...rules.map((r) => folderOf(r).toLowerCase()),
      ...pendingFolders.map((n) => n.toLowerCase()),
    ]);
    if (existing.has(lower)) {
      setFolderInputError('Folder already exists.');
      return;
    }
    setPendingFolders((prev) => [...prev, raw]);
    setOpenFolders((prev) => ({ ...prev, [raw]: true }));
    // Always persist a folder_settings row on create, even when the icon is
    // the default — the row's existence is the persistence signal that lets
    // the folder survive a reload without a rule attached. NAN-732.
    onSetFolderIcon?.(raw, folderInputIcon || DEFAULT_FOLDER_ICON_SLUG);
    setFolderInput(null);
    setFolderInputError(null);
    setFolderInputIcon(DEFAULT_FOLDER_ICON_SLUG);
  };

  const toggleFolder = (name: string, defaultOpen: boolean) => {
    setOpenFolders((prev) => ({ ...prev, [name]: !(prev[name] ?? defaultOpen) }));
  };

  return (
    <aside className="flex flex-col h-full bg-[var(--panel)] border-r border-border min-w-0">
      <div className="px-3 pt-3 pb-2 border-b border-border">
        {/* Active / Archived segmented control — matches the rule-editor
            mock: chunky outer container with subtle border, the active
            segment is highlighted with a primary-tinted border + text.
            Custom radio pair instead of shadcn Tabs so the active state's
            visual weight (border + color) lands on the segment itself
            rather than on a thin underline. */}
        <div className="flex h-9 rounded-md border border-border bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] p-1 gap-1" role="tablist" aria-label="Rule list filter">
          {(['active', 'archived'] as const).map((key) => {
            const active = tab === key;
            const label = key === 'active' ? 'Active rules' : 'Archived';
            return (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setTab(key)}
                className={cn(
                  'flex-1 inline-flex items-center justify-center rounded-[5px] text-[11px] font-mono font-semibold uppercase tracking-[0.1em] transition-colors',
                  active
                    ? 'bg-[color-mix(in_srgb,var(--primary)_18%,transparent)] text-[var(--primary)]'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {label}
              </button>
            );
          })}
        </div>
        <div className="flex items-center gap-1.5 mt-2.5">
          <Button
            variant="outline"
            size="sm"
            className="flex-1 h-7 text-[11px] justify-start px-2 gap-1.5"
            onClick={onCreateNew}
          >
            <Plus className="w-3 h-3" strokeWidth={2} />
            New Rule
          </Button>
        </div>
        <div className="mt-2 relative">
          <SearchIcon className="w-3 h-3 text-muted-foreground absolute left-2 top-1/2 -translate-y-1/2" strokeWidth={2} />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter rules…"
            className="h-7 pl-7 pr-2 text-[11.5px] font-mono"
          />
        </div>
      </div>

      <ScrollArea className="flex-1 min-h-0">
        <div className="px-2 py-2 space-y-0.5">
          {draft && (
            <div className="mb-1.5">
              <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground px-1.5 pb-1">
                Draft
              </div>
              <RuleRow
                name={draft.name || 'Untitled Rule'}
                severity={draft.severity}
                modeKey="unsaved"
                focused={!!draftSelected}
                onClick={() => {}}
              />
            </div>
          )}

          {loading && (
            <div className="px-2 py-6 text-center text-[11px] text-muted-foreground">Loading…</div>
          )}

          {!loading && folders.length === 0 && (
            <div className="px-2 py-6 text-center text-[11px] text-muted-foreground">
              {tab === 'archived' ? 'No archived rules' : q ? 'No matches' : 'No rules yet'}
            </div>
          )}

          {folders.map((folder) => {
            const isOpen = openFolders[folder.name] ?? folder.children.some((r) => r.id === selectedId);
            const isDropTarget = dragOverFolder === folder.name;
            const isCustom = folder.kind === 'folder' && folder.name !== 'Uncategorized';
            const canEditIcon = isCustom && !!onSetFolderIcon;
            return (
              <div
                key={folder.name}
                onDragOver={
                  onMoveRule
                    ? (e) => {
                        e.preventDefault();
                        e.dataTransfer.dropEffect = 'move';
                        if (dragOverFolder !== folder.name) setDragOverFolder(folder.name);
                      }
                    : undefined
                }
                onDragLeave={
                  onMoveRule
                    ? (e) => {
                        // Only clear when leaving the whole folder block, not an inner child.
                        if (!(e.currentTarget as HTMLElement).contains(e.relatedTarget as Node)) {
                          setDragOverFolder((f) => (f === folder.name ? null : f));
                        }
                      }
                    : undefined
                }
                onDrop={
                  onMoveRule
                    ? (e) => {
                        e.preventDefault();
                        setDragOverFolder(null);
                        const ruleId = e.dataTransfer.getData('application/x-nano-rule-id');
                        if (!ruleId) return;
                        const current = rules.find((r) => r.id === ruleId);
                        if (current && canonicalize(folderOf(current)) === folder.name) return;
                        onMoveRule(ruleId, folder.name === 'Uncategorized' ? '' : folder.name);
                      }
                    : undefined
                }
              >
                {(() => {
                  const headerButton = (
                    <button
                      type="button"
                      onClick={() => toggleFolder(folder.name, folder.children.some((r) => r.id === selectedId))}
                      className={cn(
                        'w-full flex items-center gap-1.5 px-1.5 py-1 rounded-md text-foreground/80 transition-colors',
                        isDropTarget
                          ? 'bg-[color-mix(in_srgb,var(--primary)_15%,transparent)] ring-1 ring-[var(--primary)]/40'
                          : 'hover:bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)]',
                      )}
                    >
                      <ChevronRight
                        className={cn('w-3 h-3 text-muted-foreground transition-transform shrink-0', isOpen && 'rotate-90')}
                        strokeWidth={2}
                      />
                      <FolderIcon kind={folder.kind} slug={folderSettings?.[folder.name]} />
                      <span className="text-[12.5px] font-medium">{folder.name}</span>
                      <span className="ml-auto text-[10px] font-mono text-muted-foreground">{folder.children.length}</span>
                    </button>
                  );
                  if (!canEditIcon) return headerButton;
                  // Custom folder with icon-edit perms — right-click for
                  // "Change icon…" / "Delete folder". The icon picker is
                  // rendered INLINE (sibling below the header) rather than
                  // in a Popover. We tried Popover + PopoverAnchor + the
                  // dual-asChild ContextMenu/Popover composition twice and
                  // hit a flash-then-auto-close race we couldn't tame
                  // (Radix DismissableLayer interpreting the ContextMenu's
                  // close cycle as an interact-outside on the just-mounted
                  // popover). Inline panel sidesteps Radix entirely.
                  return (
                    <ContextMenu>
                      <ContextMenuTrigger asChild>{headerButton}</ContextMenuTrigger>
                      <ContextMenuContent className="w-44">
                        <ContextMenuItem
                          onSelect={() => setIconEditFolder(folder.name)}
                        >
                          <Folder className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
                          Change icon…
                        </ContextMenuItem>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          onSelect={() => setDeleteFolderName(folder.name)}
                          className="text-[var(--destructive)] focus:text-[var(--destructive)]"
                        >
                          <Trash2 className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
                          Delete folder
                        </ContextMenuItem>
                      </ContextMenuContent>
                    </ContextMenu>
                  );
                })()}
                {/* Inline icon-picker panel — rendered below the header
                    when iconEditFolder matches this folder. Clicking an
                    icon picks it and closes the panel; clicking outside
                    is handled by the document-level dismiss handler at
                    the rail root. */}
                {canEditIcon && iconEditFolder === folder.name && (
                  <div
                    data-folder-icon-panel={folder.name}
                    className="ml-5 mt-1 mb-1 rounded-md border border-border bg-card px-2 py-2 space-y-1.5"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/70 flex-1">
                        Icon for {folder.name}
                      </span>
                      <button
                        type="button"
                        onClick={() => setIconEditFolder(null)}
                        className="h-5 w-5 inline-flex items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)]"
                        title="Close"
                        aria-label="Close icon picker"
                      >
                        <X className="w-3 h-3" strokeWidth={2} />
                      </button>
                    </div>
                    <FolderIconPicker
                      value={folderSettings?.[folder.name] ?? DEFAULT_FOLDER_ICON_SLUG}
                      onChange={(slug) => {
                        // Picker change = upsert with the new slug, even
                        // when it's the default — analyst expects the
                        // folder to persist (NAN-732).
                        onSetFolderIcon?.(folder.name, slug);
                        setIconEditFolder(null);
                      }}
                    />
                  </div>
                )}
                {isOpen && (
                  <div className="ml-2.5 pl-1.5 border-l border-border mt-0.5 mb-1.5 space-y-0.5">
                    {folder.children.map((rule) => (
                      <RuleRowWithContext
                        key={rule.id}
                        rule={rule}
                        focused={rule.id === selectedId}
                        onClick={() => onSelect(rule.id)}
                        draggable={!!onMoveRule}
                        onDragStart={
                          onMoveRule
                            ? (e) => {
                                e.dataTransfer.effectAllowed = 'move';
                                e.dataTransfer.setData('application/x-nano-rule-id', rule.id);
                              }
                            : undefined
                        }
                        actions={rowActions}
                      />
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          {/* Create-folder affordance — empty custom folders self-evict on
              next render once their rule count is zero, so we don't need
              rename/delete UI for v1 (NAN-729). */}
          {!loading && (
            <div className="mt-2 px-1">
              {folderInput === null ? (
                <button
                  type="button"
                  onClick={startCreateFolder}
                  className="w-full inline-flex items-center gap-1.5 h-7 px-1.5 rounded-md text-[11px] text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] transition-colors"
                >
                  <FolderPlus className="w-3.5 h-3.5" strokeWidth={1.75} />
                  New folder
                </button>
              ) : (
                <div className="rounded-md border border-border bg-card px-1.5 py-1.5 space-y-1">
                  <div className="flex items-center gap-1.5">
                    <FolderPlus className="w-3.5 h-3.5 text-muted-foreground shrink-0" strokeWidth={1.75} />
                    <Input
                      ref={folderInputRef}
                      value={folderInput}
                      onChange={(e) => {
                        setFolderInput(e.target.value);
                        if (folderInputError) setFolderInputError(null);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          submitCreateFolder();
                        } else if (e.key === 'Escape') {
                          e.preventDefault();
                          cancelCreateFolder();
                        }
                      }}
                      placeholder="folder name"
                      maxLength={50}
                      className="h-6 px-1.5 text-[11.5px] font-mono"
                    />
                    <button
                      type="button"
                      onClick={cancelCreateFolder}
                      className="h-5 w-5 inline-flex items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)]"
                      title="Cancel"
                      aria-label="Cancel"
                    >
                      <X className="w-3 h-3" strokeWidth={2} />
                    </button>
                  </div>
                  {folderInputError && (
                    <div className="text-[10px] font-mono text-[var(--destructive)] pl-5">
                      {folderInputError}
                    </div>
                  )}
                  {/* Icon picker — gated on the parent providing a setter
                      (NAN-730). When omitted, the rail still creates the
                      folder but the icon defaults to the generic glyph. */}
                  {onSetFolderIcon && (
                    <div className="pl-5 pt-1.5">
                      <FolderIconPicker value={folderInputIcon} onChange={setFolderInputIcon} />
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {folders.length > 0 && !loading && (
            <div className="mt-3 px-2 text-[10px] font-mono text-muted-foreground/70 leading-relaxed">
              Drag rules between folders to re-organize.
            </div>
          )}
        </div>
      </ScrollArea>

      <div className="border-t border-border px-3 py-2 flex items-center justify-between text-[10.5px] font-mono text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Shield className="w-3 h-3" strokeWidth={1.75} />
          {counts.total} rule{counts.total === 1 ? '' : 's'} · {counts.folders} folder{counts.folders === 1 ? '' : 's'}
        </span>
      </div>

      {/* Delete-folder confirm dialog (NAN-732 follow-up). Folder rows
          are derived from rules + folder_settings; deleting drops the
          settings row, and any rules still in the folder get moved to
          Uncategorized so the folder really disappears. */}
      <AlertDialog
        open={deleteFolderName !== null}
        onOpenChange={(o) => { if (!o) setDeleteFolderName(null); }}
      >
        <AlertDialogContent>
          {(() => {
            const target = deleteFolderName ?? '';
            const ruleCount = rules.filter(
              (r) => folderOf(r).toLowerCase() === target.toLowerCase(),
            ).length;
            return (
              <>
                <AlertDialogHeader>
                  <AlertDialogTitle>Delete folder "{target}"?</AlertDialogTitle>
                  <AlertDialogDescription>
                    {ruleCount === 0
                      ? 'This folder has no rules. Deleting removes its icon override and the folder itself.'
                      : `This folder contains ${ruleCount} rule${ruleCount === 1 ? '' : 's'}. Deleting moves ${ruleCount === 1 ? 'it' : 'them'} to Uncategorized and removes the folder.`}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={async () => {
                      const name = target;
                      // Move rules out first so the folder really vanishes.
                      // Each move is its own API call — small batch in the
                      // common case (analysts maintain folders as they go).
                      if (ruleCount > 0 && onMoveRule) {
                        const targets = rules.filter(
                          (r) => folderOf(r).toLowerCase() === name.toLowerCase(),
                        );
                        await Promise.all(targets.map((r) => Promise.resolve(onMoveRule(r.id, ''))));
                      }
                      // Drop the icon override (also removes the
                      // folder_settings row that was the persistence signal).
                      onSetFolderIcon?.(name, undefined);
                      setDeleteFolderName(null);
                    }}
                    className="bg-[var(--destructive)] text-white hover:bg-[var(--destructive)]/90"
                  >
                    Delete folder
                  </AlertDialogAction>
                </AlertDialogFooter>
              </>
            );
          })()}
        </AlertDialogContent>
      </AlertDialog>
    </aside>
  );
}
