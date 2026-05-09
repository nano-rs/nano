// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 — header strip, toolbar, table, row, and per-row action.
// Port of design-ref/shadcn/repos-view.jsx (header) and repos-table.jsx.

import {
  Box,
  Clock,
  Download,
  GitBranch,
  GitCommit,
  RefreshCw,
  Search as SearchIcon,
} from 'lucide-react';
import { SiGithub } from '@icons-pack/react-simple-icons';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Chk, FilterPills, SeverityDot, StatusChip } from './chips';
import type { CategoryCount, RepoRuleView, RepoView } from './helpers';

// ------------------------------------------------------------------
// Header strip — title + active-repo pill above the three panes
// ------------------------------------------------------------------

interface HeaderProps {
  repo: RepoView | null;
  onSyncNow: () => void;
  onOpenHistory: () => void;
  syncing: boolean;
}

export function ReposHeader({ repo, onSyncNow, onOpenHistory, syncing }: HeaderProps) {
  return (
    <div className="shrink-0 border-b border-border bg-card/30 px-5 py-3.5 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0">
        <Box className="w-[18px] h-[18px] text-foreground/70" strokeWidth={1.5} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">
            Rule repositories
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px">
            beta
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
          Track detections from Git. Sync upstream rules, preview diffs, remap sources, and import — bulk
          or one-by-one. Local edits are preserved; drift is surfaced when upstream changes.
        </div>
      </div>

      {repo && (
        <div className="hidden md:flex items-center gap-2.5 rounded-lg border border-border bg-card pl-3 pr-1 py-1 shrink-0">
          <SiGithub className="w-[13px] h-[13px] text-foreground/70" />
          <div className="flex flex-col">
            <div className="font-mono text-[11px] text-foreground truncate">{repo.slug}</div>
            <div className="text-[10px] text-muted-foreground font-mono flex items-center gap-1">
              <GitBranch className="w-[9px] h-[9px]" strokeWidth={1.5} />
              {repo.branch} · {repo.lastCommit.sha}
            </div>
          </div>
          <div className="w-px h-7 bg-border mx-1" />
          <button
            type="button"
            onClick={onOpenHistory}
            className="h-[26px] px-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[10.5px] font-mono flex items-center gap-1"
          >
            <Clock className="w-[11px] h-[11px]" strokeWidth={1.5} />
            {repo.lastSync.relative}
          </button>
          <button
            type="button"
            onClick={onSyncNow}
            disabled={syncing}
            className={cn(
              'h-[26px] px-2 rounded-md text-[10.5px] font-mono flex items-center gap-1 border',
              syncing
                ? 'border-border bg-foreground/5 text-muted-foreground cursor-not-allowed'
                : 'border-border bg-card hover:bg-muted text-foreground/70 hover:text-foreground',
            )}
          >
            <RefreshCw className={cn('w-[11px] h-[11px]', syncing && 'animate-spin')} strokeWidth={1.5} />
            {syncing ? 'Syncing…' : 'Sync now'}
          </button>
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------
// Middle pane toolbar — search, bulk-select summary
// ------------------------------------------------------------------

interface ToolbarProps {
  selectedCount: number;
  totalShown: number;
  query: string;
  onQueryChange: (q: string) => void;
  onBulkImport: () => void;
  onBulkClear: () => void;
}

export function ReposToolbar({
  selectedCount,
  totalShown,
  query,
  onQueryChange,
  onBulkImport,
  onBulkClear,
}: ToolbarProps) {
  return (
    <div className="flex items-center gap-2 px-3.5 h-[42px] border-b border-border bg-card/30 shrink-0">
      {selectedCount > 0 ? (
        <>
          <span className="text-[12px] text-foreground font-medium">
            <span className="font-mono tabular-nums">{selectedCount}</span> selected
          </span>
          <span className="text-[11px] text-muted-foreground">of {totalShown}</span>
          <button
            type="button"
            onClick={onBulkImport}
            className="h-[26px] px-2.5 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1"
          >
            <Download className="w-[11px] h-[11px]" strokeWidth={2} />
            Import {selectedCount}
          </button>
          <button
            type="button"
            onClick={onBulkClear}
            className="h-[26px] px-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px]"
          >
            Clear
          </button>
        </>
      ) : (
        <>
          <span className="text-[12px] text-foreground font-medium">Rules</span>
          <span className="text-[10.5px] font-mono tabular-nums text-muted-foreground">
            {totalShown}
          </span>
        </>
      )}

      <span className="flex-1" />

      <div className="relative">
        <SearchIcon className="w-[12px] h-[12px] text-muted-foreground absolute left-2 top-1/2 -translate-y-1/2" />
        <input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search rules, MITRE, author…"
          className="h-[26px] pl-6 pr-2 rounded-md border border-border bg-card text-[12px] placeholder:text-muted-foreground focus:outline-none focus:border-primary w-[220px]"
        />
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Filter pills row
// ------------------------------------------------------------------

export function FilterRow({
  categories,
  activeId,
  onActivate,
}: {
  categories: CategoryCount[];
  activeId: CategoryCount['id'];
  onActivate: (id: CategoryCount['id']) => void;
}) {
  return (
    <div className="px-3.5 py-2 border-b border-border bg-card/30 flex items-center gap-2">
      <FilterPills categories={categories} activeId={activeId} onActivate={onActivate} />
    </div>
  );
}

// ------------------------------------------------------------------
// Main rule table
// ------------------------------------------------------------------

interface TableProps {
  rules: RepoRuleView[];
  selected: Set<string>;
  selectedRuleId: string | null;
  onToggleSelect: (id: string) => void;
  onToggleSelectAll: (sel: boolean) => void;
  onSelectRule: (id: string) => void;
  onAction: (rule: RepoRuleView) => void;
}

export function ReposTable({
  rules,
  selected,
  selectedRuleId,
  onToggleSelect,
  onToggleSelectAll,
  onSelectRule,
  onAction,
}: TableProps) {
  const eligible = rules.filter((r) => r.status !== 'DELETED');
  const allSel = eligible.length > 0 && eligible.every((r) => selected.has(r.id));
  const someSel = selected.size > 0 && !allSel;

  return (
    <div
      className="flex-1 min-h-0 overflow-auto"
      style={{ containerType: 'inline-size' }}
    >
      <table className="w-full text-[12px] tabular-nums" style={{ tableLayout: 'fixed' }}>
        <thead className="sticky top-0 bg-card border-b border-border z-10">
          <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
            <th className="py-2 pl-3 w-[28px]">
              <Chk
                checked={allSel}
                indeterminate={someSel}
                onChange={() => onToggleSelectAll(!allSel)}
                ariaLabel="Select all rules"
              />
            </th>
            <th className="py-2 pl-1 text-left font-medium w-[82px]">Status</th>
            <th className="py-2 pl-1 text-left font-medium">Rule</th>
            <th className="py-2 pl-1 text-left font-medium w-[140px] @max-[820px]:hidden">Source</th>
            <th className="py-2 pl-1 text-left font-medium w-[78px] @max-[640px]:hidden">Sev</th>
            <th className="py-2 pl-1 text-left font-medium w-[110px] @max-[980px]:hidden">MITRE</th>
            <th className="py-2 pl-1 text-left font-medium w-[100px] @max-[1140px]:hidden">Commit</th>
            <th className="py-2 pl-1 pr-3 w-[80px]" />
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <RepoRuleRow
              key={r.id}
              rule={r}
              selected={selected.has(r.id)}
              active={selectedRuleId === r.id}
              onToggleSelect={() => onToggleSelect(r.id)}
              onSelect={() => onSelectRule(r.id)}
              onAction={() => onAction(r)}
            />
          ))}
          {rules.length === 0 && (
            <tr>
              <td colSpan={8} className="py-8 text-center">
                <div className="flex flex-col items-center gap-1.5 text-muted-foreground">
                  <SearchIcon className="w-5 h-5" strokeWidth={1.5} />
                  <div className="text-[12.5px] font-medium text-foreground">No rules match these filters</div>
                  <div className="text-[11px]">Try a different category, source, or clear your search.</div>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

interface RowProps {
  rule: RepoRuleView;
  selected: boolean;
  active: boolean;
  onToggleSelect: () => void;
  onSelect: () => void;
  onAction: () => void;
}

function RepoRuleRow({ rule, selected, active, onToggleSelect, onSelect, onAction }: RowProps) {
  const deleted = rule.status === 'DELETED';
  const remapped = rule.source !== rule.destSource;
  return (
    <tr
      onClick={onSelect}
      className={cn(
        'border-b border-border/60 cursor-pointer transition',
        active
          ? 'bg-primary/[0.06]'
          : selected
            ? 'bg-foreground/[0.03]'
            : 'hover:bg-foreground/[0.02]',
        deleted && 'opacity-70',
      )}
    >
      <td className="py-2 pl-3" onClick={(e) => e.stopPropagation()}>
        <Chk
          checked={selected}
          onChange={onToggleSelect}
          disabled={deleted}
          ariaLabel={`Select ${rule.name}`}
        />
      </td>
      <td className="py-2 pl-1">
        <StatusChip status={rule.status} />
      </td>
      <td className="py-2 pl-1 pr-3 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="hidden @max-[640px]:inline-block shrink-0">
            <SeverityDot sev={rule.severity} />
          </span>
          <div className="font-mono text-[12px] text-foreground truncate">{rule.name}</div>
        </div>
        <div className="text-[10.5px] text-muted-foreground truncate">{rule.desc}</div>
      </td>
      <td className="py-2 pl-1 min-w-0 @max-[820px]:hidden">
        <span
          className={cn(
            'font-mono text-[10.5px] rounded px-1.5 py-[2px] border inline-block max-w-full truncate align-middle',
            remapped
              ? 'border-warning/40 text-warning bg-warning/5'
              : 'border-border text-foreground/70 bg-background',
          )}
        >
          {rule.source}
        </span>
      </td>
      <td className="py-2 pl-1 @max-[640px]:hidden">
        <SeverityDot sev={rule.severity} />
      </td>
      <td className="py-2 pl-1 @max-[980px]:hidden">
        <div className="flex flex-wrap gap-1">
          {rule.mitre.slice(0, 2).map((m) => (
            <span
              key={m}
              className="font-mono text-[9.5px] text-foreground/70 border border-border rounded px-1 py-px"
            >
              {m}
            </span>
          ))}
          {rule.mitre.length > 2 && (
            <span className="font-mono text-[9.5px] text-muted-foreground">
              +{rule.mitre.length - 2}
            </span>
          )}
        </div>
      </td>
      <td className="py-2 pl-1 @max-[1140px]:hidden">
        <div className="flex items-center gap-1.5">
          <GitCommit className="w-[11px] h-[11px] text-muted-foreground" strokeWidth={1.5} />
          <span className="font-mono text-[10.5px] text-foreground/70">{rule.commit}</span>
        </div>
        <div className="text-[10px] text-muted-foreground truncate">{rule.updated}</div>
      </td>
      <td className="py-2 pl-1 pr-3" onClick={(e) => e.stopPropagation()}>
        <RowAction rule={rule} onAction={onAction} />
      </td>
    </tr>
  );
}

function RowAction({ rule, onAction }: { rule: RepoRuleView; onAction: () => void }) {
  if (rule.status === 'IMPORTED') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={onAction}
            className="h-[22px] px-2 rounded-md border border-border bg-card hover:bg-muted text-[10.5px] font-mono text-foreground/70"
          >
            Open
          </button>
        </TooltipTrigger>
        <TooltipContent>Already imported — open in editor</TooltipContent>
      </Tooltip>
    );
  }
  if (rule.status === 'DELETED') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={onAction}
            className="h-[22px] px-2 rounded-md border border-destructive/30 text-[10.5px] font-mono text-destructive hover:bg-destructive/5"
          >
            Remove
          </button>
        </TooltipTrigger>
        <TooltipContent>Remove from your library</TooltipContent>
      </Tooltip>
    );
  }
  if (rule.status === 'DRIFT') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={onAction}
            className="h-[22px] px-2 rounded-md border border-destructive/30 bg-destructive/5 text-[10.5px] font-mono text-destructive hover:bg-destructive/10"
          >
            Resolve
          </button>
        </TooltipTrigger>
        <TooltipContent>Resolve drift — merge or discard local changes</TooltipContent>
      </Tooltip>
    );
  }
  if (rule.status === 'UPDATED') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={onAction}
            className="h-[22px] px-2 rounded-md border border-warning/30 bg-warning/10 text-[10.5px] font-mono text-warning hover:bg-warning/15"
          >
            Update
          </button>
        </TooltipTrigger>
        <TooltipContent>Update to latest version</TooltipContent>
      </Tooltip>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onAction}
          className="h-[22px] px-2 rounded-md bg-primary text-primary-foreground text-[10.5px] font-mono font-semibold hover:bg-primary/90"
        >
          Import
        </button>
      </TooltipTrigger>
      <TooltipContent>Import into your rule library</TooltipContent>
    </Tooltip>
  );
}
