// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — editor top bar: name + mode pill + UNSAVED badge + view toggle +
// "View matches" + "Test rule" + overflow menu + Save. Meta-chip strip renders
// underneath in read-only mode for this first PR (popover-driven editing comes
// in PR 2).

import { useRef, useState } from 'react';
import {
  ArrowLeft,
  ArrowUp,
  ArrowDown,
  Save,
  Play,
  Focus,
  Terminal,
  List as ListIcon,
  Share2,
  MoreHorizontal,
  Copy,
  KeyRound,
  Clock,
  ChevronDown,
  Folder,
  FolderPlus,
  X,
  AlertCircle,
  Users,
  Undo2,
  WandSparkles,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Separator } from '@/components/ui/separator';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import { MODE_META, SEV_COLOR, SEV_LABEL, cronHuman, displayMode, normalizeSeverity } from './helpers';
import { iconForSlug } from './folder-icons';

export type ViewMode = 'code' | 'flow' | 'form';

interface Metadata {
  title?: string;
  severity?: string;
  mode?: string;
  schedule?: string;
  mitre_tactics?: string;
  mitre_techniques?: string;
  tags?: string;
  folder?: string;
}

// Mirrors the backend validator at
// nanosiem-core/src/models/detection_rule.rs:564 — alphanumeric + dash +
// underscore, ≤ 50 chars, must start with an alphanumeric.
const META_CUSTOM_FOLDER_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$/;

interface EditorTopBarProps {
  metadata: Metadata;
  /** Whether this editor is for a new rule (no ruleId yet). */
  isNewMode: boolean;
  /** Current mode coming from the API rule (so the pill reflects saved state, not draft). */
  apiMode?: string;
  archived?: boolean;
  dirty: boolean;
  saving: boolean;
  valid: boolean;
  viewMode: ViewMode;
  onViewMode: (v: ViewMode) => void;
  onBack: () => void;
  onSave: () => void;
  onDiscard?: () => void;
  onFormat?: () => void;
  onOpenTest?: () => void;
  onViewMatches?: () => void;
  onDuplicate?: () => void;
  onTogglePause?: () => void;
  onPromote?: () => void;
  onDemote?: () => void;
  onArchive?: () => void;
  onUnarchive?: () => void;
  onDelete?: () => void;
  onOpenTune?: () => void;
  /** Disabled when FLOW/FORM lenses ship in later PRs. */
  enabledLenses?: ReadonlySet<ViewMode>;
  /** All folders the user can pick from in the meta-row folder chip
      (canonical + any folder currently used by a rule). When omitted the
      chip falls back to the canonical five plus the rule's current folder. */
  availableFolders?: string[];
  /** Called when the user picks (or creates) a folder via the meta-row chip.
      Empty string means "Uncategorized" (clear the folder field). When this
      is omitted, the chip renders read-only. */
  onFolderChange?: (folder: string) => void;
  /** Map of folder name → icon slug (NAN-730). Threaded into FolderChip so
      custom folders show their picked icon both in the trigger and the
      dropdown rows. Canonical folders ignore this map. */
  folderSettings?: Record<string, string>;
}

function ModePill({ mode }: { mode: string }) {
  const display = displayMode(mode);
  const meta = MODE_META[display];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 h-5 rounded-[3px] text-[10px] font-mono font-semibold tracking-[0.08em]',
        meta.tone,
      )}
      style={{
        background:
          display === 'live'
            ? 'color-mix(in srgb, var(--success) 15%, transparent)'
            : display === 'staging'
              ? 'color-mix(in srgb, var(--primary) 15%, transparent)'
              : 'color-mix(in srgb, var(--foreground) 10%, transparent)',
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: meta.dotVar }} />
      {meta.label}
    </span>
  );
}

function SevChip({ severity }: { severity: string }) {
  const sev = normalizeSeverity(severity);
  return (
    <span
      className="inline-flex items-center h-5 px-1.5 rounded-[3px] text-[9.5px] font-mono font-semibold tracking-[0.1em] uppercase"
      style={{
        background: `color-mix(in srgb, ${SEV_COLOR[sev]} 18%, transparent)`,
        color: SEV_COLOR[sev],
      }}
    >
      {SEV_LABEL[sev]}
    </span>
  );
}

// Folder chip — interactive when `onChange` is set, otherwise a plain text
// chip. Lists canonical + custom folders + a "Create new folder" affordance.
// Saving is "fire-and-forget" via the parent's `onChange`; the parent owns
// API persistence (currently mirrors RuleRail.onMoveRule).
function FolderChip({
  current,
  availableFolders,
  onChange,
  folderSettings,
}: {
  current?: string;
  availableFolders: string[];
  onChange?: (folder: string) => void;
  /** Map of folder name → icon slug (NAN-730). Used to render the picked
      icon inline next to each folder option, including the trigger. */
  folderSettings?: Record<string, string>;
}) {
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const display = current?.trim() || 'Uncategorized';
  const interactive = !!onChange;
  // Resolve the trigger icon: canonical folders keep `Folder`; custom
  // folders pick from folderSettings (falls back to generic Folder).
  const TriggerIcon = (() => {
    if (!current?.trim()) return Folder;
    const lower = current.trim().toLowerCase();
    const canonical = ['network', 'identity', 'endpoint', 'cloud', 'uncategorized'];
    if (canonical.includes(lower)) return Folder;
    return iconForSlug(folderSettings?.[current]);
  })();

  // Stable, sorted list — canonical first in their canonical order, custom
  // alphabetically below.
  const CANONICAL = ['Network', 'Identity', 'Endpoint', 'Cloud', 'Uncategorized'];
  const canonicalSet = new Set(CANONICAL.map((c) => c.toLowerCase()));
  const customFolders = availableFolders
    .filter((f) => !canonicalSet.has(f.toLowerCase()))
    .sort((a, b) => a.localeCompare(b));

  const startCreate = () => {
    setError(null);
    setDraft('');
    setCreating(true);
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  const cancelCreate = () => {
    setCreating(false);
    setError(null);
    setDraft('');
  };

  const submitCreate = () => {
    const raw = draft.trim();
    if (!raw) {
      cancelCreate();
      return;
    }
    if (!META_CUSTOM_FOLDER_RE.test(raw)) {
      setError('Letters, numbers, dash, underscore. Up to 50 chars.');
      return;
    }
    if (!onChange) return;
    onChange(raw);
    setOpen(false);
    cancelCreate();
  };

  const select = (folder: string) => {
    if (!onChange) return;
    // Send empty string to clear (folder cleared = "Uncategorized").
    onChange(folder === 'Uncategorized' ? '' : folder);
    setOpen(false);
    cancelCreate();
  };

  if (!interactive) {
    return (
      <span className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground whitespace-nowrap">
        <TriggerIcon className="w-3 h-3" strokeWidth={1.75} />
        <span className="text-[10px] font-mono uppercase tracking-[0.08em]">folder</span>
        <span className="text-[11px] font-mono text-foreground">{display}</span>
      </span>
    );
  }

  return (
    <Popover open={open} onOpenChange={(o) => { setOpen(o); if (!o) cancelCreate(); }}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_4%,transparent)] transition-colors whitespace-nowrap"
          title="Change folder"
        >
          <TriggerIcon className="w-3 h-3" strokeWidth={1.75} />
          <span className="text-[10px] font-mono uppercase tracking-[0.08em]">folder</span>
          <span className="text-[11px] font-mono text-foreground">{display}</span>
          <ChevronDown className="w-3 h-3 text-muted-foreground/70" strokeWidth={1.75} />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[220px] p-1" align="start" sideOffset={4}>
        <div className="px-2 pt-1.5 pb-1 font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/70">
          Built-in
        </div>
        {CANONICAL.map((name) => {
          const isActive = (current?.trim().toLowerCase() ?? '') === name.toLowerCase()
            || (!current?.trim() && name === 'Uncategorized');
          return (
            <button
              key={name}
              type="button"
              onClick={() => select(name)}
              className={cn(
                'w-full text-left flex items-center gap-1.5 h-7 px-2 rounded-sm text-[12px] transition-colors',
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_4%,transparent)]',
              )}
            >
              <Folder className="w-3 h-3 text-muted-foreground" strokeWidth={1.75} />
              <span className="font-mono">{name}</span>
            </button>
          );
        })}
        {customFolders.length > 0 && (
          <>
            <div className="px-2 pt-2 pb-1 font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/70">
              Custom
            </div>
            {customFolders.map((name) => {
              const isActive = (current?.trim().toLowerCase() ?? '') === name.toLowerCase();
              const RowIcon = iconForSlug(folderSettings?.[name]);
              return (
                <button
                  key={name}
                  type="button"
                  onClick={() => select(name)}
                  className={cn(
                    'w-full text-left flex items-center gap-1.5 h-7 px-2 rounded-sm text-[12px] transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_4%,transparent)]',
                  )}
                >
                  <RowIcon className="w-3 h-3 text-muted-foreground" strokeWidth={1.75} />
                  <span className="font-mono">{name}</span>
                </button>
              );
            })}
          </>
        )}
        <div className="border-t border-border mt-1 pt-1">
          {creating ? (
            <div className="px-1 pb-1 space-y-1">
              <div className="flex items-center gap-1.5">
                <FolderPlus className="w-3 h-3 text-muted-foreground shrink-0" strokeWidth={1.75} />
                <Input
                  ref={inputRef}
                  value={draft}
                  onChange={(e) => {
                    setDraft(e.target.value);
                    if (error) setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      submitCreate();
                    } else if (e.key === 'Escape') {
                      e.preventDefault();
                      cancelCreate();
                    }
                  }}
                  placeholder="folder name"
                  maxLength={50}
                  className="h-6 px-1.5 text-[11.5px] font-mono"
                />
                <button
                  type="button"
                  onClick={cancelCreate}
                  className="h-5 w-5 inline-flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                  aria-label="Cancel"
                >
                  <X className="w-3 h-3" strokeWidth={2} />
                </button>
              </div>
              {error && (
                <div className="text-[10px] font-mono text-[var(--destructive)] pl-5">
                  {error}
                </div>
              )}
            </div>
          ) : (
            <button
              type="button"
              onClick={startCreate}
              className="w-full text-left inline-flex items-center gap-1.5 h-7 px-2 rounded-sm text-[12px] text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_4%,transparent)] transition-colors"
            >
              <FolderPlus className="w-3 h-3" strokeWidth={1.75} />
              <span className="font-mono">New folder…</span>
            </button>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function MetaChipStrip({
  metadata,
  availableFolders,
  onFolderChange,
  folderSettings,
}: {
  metadata: Metadata;
  availableFolders?: string[];
  onFolderChange?: (folder: string) => void;
  folderSettings?: Record<string, string>;
}) {
  const tactics = (metadata.mitre_tactics || '').split(',').map((s) => s.trim()).filter(Boolean);
  const techniques = (metadata.mitre_techniques || '').split(',').map((s) => s.trim()).filter(Boolean);
  const tags = (metadata.tags || '').split(',').map((s) => s.trim()).filter(Boolean);
  const sched = cronHuman(metadata.schedule);

  return (
    <div className="h-9 flex items-center px-4 gap-2 border-t border-border/40 bg-background/60 overflow-x-auto">
      <span className="text-[9.5px] font-mono text-muted-foreground uppercase tracking-[0.12em] pr-1">Meta</span>

      <span className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground whitespace-nowrap">
        <span className="text-[10px] font-mono uppercase tracking-[0.08em]">sev</span>
        <SevChip severity={metadata.severity || 'medium'} />
      </span>
      <Separator orientation="vertical" className="h-4" />

      <span className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground whitespace-nowrap">
        <span className="text-[10px] font-mono uppercase tracking-[0.08em]">mode</span>
        <span className="text-[11px] font-mono text-foreground">{metadata.mode || 'staging'}</span>
      </span>
      <Separator orientation="vertical" className="h-4" />

      <FolderChip
        current={metadata.folder}
        availableFolders={availableFolders ?? []}
        onChange={onFolderChange}
        folderSettings={folderSettings}
      />
      <Separator orientation="vertical" className="h-4" />

      <span className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground whitespace-nowrap">
        <Clock className="w-3 h-3" strokeWidth={1.75} />
        <span className="text-[10px] font-mono uppercase tracking-[0.08em]">schedule</span>
        <span className="text-[11px] font-mono text-foreground">{sched}</span>
      </span>
      <Separator orientation="vertical" className="h-4" />

      {tactics.length > 0 && (
        <>
          <span className="inline-flex items-center gap-1 h-6 px-1.5 rounded-[4px] text-muted-foreground whitespace-nowrap">
            <span className="text-[10px] font-mono uppercase tracking-[0.08em]">mitre</span>
            <span className="font-mono text-[11px] text-foreground">{tactics[0]}</span>
            {techniques[0] && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span className="font-mono text-[11px] text-foreground">{techniques[0]}</span>
              </>
            )}
            {techniques.length > 1 && (
              <span className="font-mono text-[10px] text-muted-foreground">+{techniques.length - 1}</span>
            )}
          </span>
          <Separator orientation="vertical" className="h-4" />
        </>
      )}

      <div className="flex-1 min-w-0" />

      {tags.length > 0 && (
        <div className="flex items-center gap-1 shrink-0">
          {tags.slice(0, 3).map((t) => (
            <span
              key={t}
              className="font-mono text-[10px] text-muted-foreground px-1.5 h-5 rounded-[3px]"
              style={{ background: 'color-mix(in srgb, var(--foreground) 4%, transparent)' }}
            >
              #{t}
            </span>
          ))}
          {tags.length > 3 && <span className="font-mono text-[10px] text-muted-foreground">+{tags.length - 3}</span>}
        </div>
      )}
    </div>
  );
}

export function EditorTopBar({
  metadata,
  isNewMode,
  apiMode,
  archived,
  dirty,
  saving,
  valid,
  viewMode,
  onViewMode,
  onBack,
  onSave,
  onDiscard,
  onFormat,
  onOpenTest,
  onViewMatches,
  onDuplicate,
  onTogglePause,
  onPromote,
  onDemote,
  onArchive,
  onUnarchive,
  onDelete,
  onOpenTune,
  enabledLenses,
  availableFolders,
  onFolderChange,
  folderSettings,
}: EditorTopBarProps) {
  const lenses: ReadonlySet<ViewMode> = enabledLenses ?? new Set<ViewMode>(['code']);
  const title = metadata.title || (isNewMode ? 'untitled_rule' : '…');
  const effectiveMode = isNewMode ? 'staging' : apiMode || metadata.mode || 'staging';
  const paused = effectiveMode === 'paused';
  // Promote advances staging → live → alerting; Demote walks it back. Paused
  // and archived rules can't be promoted/demoted (resume/unarchive first).
  const promotable = !paused && !archived && (effectiveMode === 'staging' || effectiveMode === 'live');
  const demotable = !paused && !archived && (effectiveMode === 'live' || effectiveMode === 'alerting');
  const promoteTarget = effectiveMode === 'staging' ? 'live' : 'alerting';
  const demoteTarget = effectiveMode === 'alerting' ? 'live' : 'staging';

  return (
    <div className="border-b border-border bg-background shrink-0">
      <div className="h-12 flex items-center px-4 gap-3">
        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={onBack} aria-label="Back">
          <ArrowLeft className="w-3.5 h-3.5" strokeWidth={1.75} />
        </Button>

        <div className="flex items-center gap-2 min-w-0 flex-1">
          <div className="text-[14px] font-mono font-semibold text-foreground truncate">{title}</div>
          {!isNewMode && <ModePill mode={effectiveMode} />}
          {archived && (
            <span className="inline-flex items-center h-5 px-1.5 rounded-[3px] text-[10px] font-mono font-semibold tracking-[0.08em] uppercase bg-muted text-muted-foreground">
              ARCHIVED
            </span>
          )}
          {dirty && (
            <span
              className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] text-[10px] font-mono font-semibold tracking-[0.08em] text-[var(--warning)]"
              style={{ background: 'color-mix(in srgb, var(--warning) 15%, transparent)' }}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--warning)]" />
              UNSAVED
            </span>
          )}
          {isNewMode && (
            <span
              className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] text-[10px] font-mono font-semibold tracking-[0.08em] text-[var(--primary)]"
              style={{ background: 'color-mix(in srgb, var(--primary) 15%, transparent)' }}
            >
              DRAFT
            </span>
          )}
        </div>

        <div
          className="inline-flex items-center rounded-md border border-border p-0.5 text-muted-foreground shrink-0"
          style={{ background: 'color-mix(in srgb, var(--foreground) 4%, transparent)' }}
        >
          {(['code', 'flow', 'form'] as ViewMode[]).map((m) => {
            const enabled = lenses.has(m);
            const active = viewMode === m;
            const Icon = m === 'code' ? Terminal : m === 'flow' ? Share2 : ListIcon;
            return (
              <button
                key={m}
                type="button"
                onClick={() => enabled && onViewMode(m)}
                disabled={!enabled}
                className={cn(
                  'h-6 px-2 rounded-[3px] text-[10.5px] font-mono font-semibold tracking-[0.08em] uppercase transition-colors inline-flex items-center gap-1',
                  active
                    ? 'bg-[color-mix(in_srgb,var(--primary)_18%,transparent)] text-[var(--primary)]'
                    : enabled
                      ? 'hover:text-foreground'
                      : 'opacity-40 cursor-not-allowed',
                )}
                title={!enabled ? `${m.toUpperCase()} view coming soon` : undefined}
              >
                <Icon className={cn('w-3 h-3', m === 'flow' && 'rotate-90')} strokeWidth={1.75} />
                {m}
              </button>
            );
          })}
        </div>

        <Separator orientation="vertical" className="h-6" />

        {onViewMatches && (
          <Button variant="outline" size="sm" className="h-7 text-[11.5px] px-2.5 gap-1.5" onClick={onViewMatches}>
            <Focus className="w-3 h-3" strokeWidth={1.75} />
            Matches
          </Button>
        )}
        {onOpenTest && (
          <Button variant="outline" size="sm" className="h-7 text-[11.5px] px-2.5 gap-1.5" onClick={onOpenTest}>
            <Play className="w-3 h-3" strokeWidth={1.75} />
            Test rule
          </Button>
        )}

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-7 w-7">
              <MoreHorizontal className="w-3.5 h-3.5" strokeWidth={1.75} />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-[200px]">
            <DropdownMenuLabel>Rule actions</DropdownMenuLabel>
            {onDuplicate && (
              <DropdownMenuItem onClick={onDuplicate}>
                <Copy className="w-3.5 h-3.5" strokeWidth={1.75} />
                Duplicate rule
              </DropdownMenuItem>
            )}
            {onFormat && (
              <DropdownMenuItem onClick={onFormat}>
                <WandSparkles className="w-3.5 h-3.5" strokeWidth={1.75} />
                Format query
              </DropdownMenuItem>
            )}
            {onDiscard && (
              <DropdownMenuItem onClick={onDiscard} disabled={!dirty}>
                <Undo2 className="w-3.5 h-3.5" strokeWidth={1.75} />
                Discard changes
              </DropdownMenuItem>
            )}
            {onOpenTune && (
              <DropdownMenuItem onClick={onOpenTune}>
                <WandSparkles className="w-3.5 h-3.5" strokeWidth={1.75} />
                AI tune rule
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Lifecycle</DropdownMenuLabel>
            {onPromote && promotable && (
              <DropdownMenuItem onClick={onPromote}>
                <ArrowUp className="w-3.5 h-3.5" strokeWidth={1.75} />
                Promote to {promoteTarget}
              </DropdownMenuItem>
            )}
            {onDemote && demotable && (
              <DropdownMenuItem onClick={onDemote}>
                <ArrowDown className="w-3.5 h-3.5" strokeWidth={1.75} />
                Demote to {demoteTarget}
              </DropdownMenuItem>
            )}
            {onTogglePause && (
              <DropdownMenuItem onClick={onTogglePause}>
                {paused ? (
                  <>
                    <KeyRound className="w-3.5 h-3.5" strokeWidth={1.75} />
                    Resume rule
                  </>
                ) : (
                  <>
                    <Clock className="w-3.5 h-3.5" strokeWidth={1.75} />
                    Pause rule
                  </>
                )}
              </DropdownMenuItem>
            )}
            {onArchive && !archived && (
              <DropdownMenuItem onClick={onArchive} className="text-[var(--destructive,_#F87171)]">
                <X className="w-3.5 h-3.5" strokeWidth={1.75} />
                Archive rule
              </DropdownMenuItem>
            )}
            {onUnarchive && archived && (
              <DropdownMenuItem onClick={onUnarchive}>
                <Users className="w-3.5 h-3.5" strokeWidth={1.75} />
                Unarchive rule
              </DropdownMenuItem>
            )}
            {onDelete && (
              <DropdownMenuItem onClick={onDelete} className="text-[var(--destructive,_#F87171)]">
                <AlertCircle className="w-3.5 h-3.5" strokeWidth={1.75} />
                Delete forever
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <Button
          onClick={onSave}
          disabled={!dirty || !valid || saving}
          className={cn('h-7 text-[11.5px] px-3 gap-1.5', !dirty && 'opacity-60')}
        >
          <Save className="w-3 h-3" strokeWidth={1.75} />
          {saving ? 'Saving…' : dirty ? (isNewMode ? 'Create rule' : 'Save rule') : 'Saved'}
        </Button>
      </div>

      <MetaChipStrip
        metadata={metadata}
        availableFolders={availableFolders}
        onFolderChange={onFolderChange}
        folderSettings={folderSettings}
      />
    </div>
  );
}
