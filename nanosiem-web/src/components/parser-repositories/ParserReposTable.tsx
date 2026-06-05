// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — header strip, toolbar, filter row, table, row, and per-row action.
// Port of design-ref/shadcn/log-repos-view.jsx (header) and log-repos-table.jsx.

import type { ReactNode } from 'react';
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
import { CategoryChip, Chk, FilterPills, StatusChip, TransportChip } from './chips';
import type { CategoryCount, ParserRepoView, RepoParserView } from './helpers';

// ------------------------------------------------------------------
// Header strip — title + active-repo pill above the three panes
// ------------------------------------------------------------------

interface HeaderProps {
  repo: ParserRepoView | null;
  onSyncNow: () => void;
  onOpenHistory: () => void;
  syncing: boolean;
  /**
   * Air-gap mode (NAN-1226): when provided, replaces the egress "Sync now"
   * control with an offline bundle-sync affordance.
   */
  airgapSlot?: ReactNode;
}

export function ReposHeader({ repo, onSyncNow, onOpenHistory, syncing, airgapSlot }: HeaderProps) {
  return (
    <div className="shrink-0 border-b border-border bg-card/30 px-5 py-3.5 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0">
        <Box className="w-[18px] h-[18px] text-foreground/70" strokeWidth={1.5} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">
            Parser repositories
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px">
            beta
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[760px]">
          Parser libraries synced from Git. Preview the VRL, inspect the normalized schema, and
          import into a Source Config as a new log source — linked to upstream (auto-update) or
          forked (edit locally; we'll flag drift).
        </div>
      </div>

      {airgapSlot ? (
        <div className="flex items-center shrink-0">{airgapSlot}</div>
      ) : (
        repo && (
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
              <RefreshCw
                className={cn('w-[11px] h-[11px]', syncing && 'animate-spin')}
                strokeWidth={1.5}
              />
              {syncing ? 'Syncing…' : 'Sync now'}
            </button>
          </div>
        )
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
          <span className="text-[12px] text-foreground font-medium">Parsers</span>
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
          placeholder="Search parsers, vendors, source types…"
          className="h-[26px] pl-6 pr-2 rounded-md border border-border bg-card text-[12px] placeholder:text-muted-foreground focus:outline-none focus:border-primary w-[240px]"
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
// Main parser table
// ------------------------------------------------------------------

interface TableProps {
  parsers: RepoParserView[];
  selected: Set<string>;
  selectedParserId: string | null;
  onToggleSelect: (id: string) => void;
  onToggleSelectAll: (sel: boolean) => void;
  onSelectParser: (id: string) => void;
  onAction: (parser: RepoParserView) => void;
  /** NAN-974 — current category tab, used for tab-specific empty-state copy. */
  activeCat?: 'all' | 'updated' | 'available' | 'imported' | 'drift' | 'deleted';
}

/** NAN-974 — tab-specific empty-state copy. */
function parserEmptyStateCopy(activeCat: TableProps['activeCat']): { title: string; hint: string } {
  switch (activeCat) {
    case 'updated':
      return { title: 'No upstream updates', hint: 'Your imported parsers match the upstream HEAD.' };
    case 'available':
      return { title: 'Nothing new to import', hint: 'All upstream parsers are already imported.' };
    case 'imported':
      return { title: 'No parsers imported yet', hint: 'Click Import on any parser above to add it to your tenant.' };
    case 'drift':
      return { title: 'No local drift', hint: 'All imported parsers match their upstream version.' };
    case 'deleted':
      return { title: 'No removals tracked', hint: 'No upstream parsers have been removed since the last sync.' };
    default:
      return { title: 'No parsers match these filters', hint: 'Try a different category, or clear your search.' };
  }
}

export function ReposTable({
  parsers,
  selected,
  selectedParserId,
  onToggleSelect,
  onToggleSelectAll,
  onSelectParser,
  onAction,
  activeCat,
}: TableProps) {
  const eligible = parsers.filter((p) => p.status !== 'DELETED' && p.status !== 'IMPORTED');
  const allSel = eligible.length > 0 && eligible.every((p) => selected.has(p.id));
  const someSel = selected.size > 0 && !allSel;
  const empty = parserEmptyStateCopy(activeCat);

  return (
    <div className="flex-1 min-h-0 overflow-auto" style={{ containerType: 'inline-size' }}>
      <table className="w-full text-[12px] tabular-nums" style={{ tableLayout: 'fixed' }}>
        <thead className="sticky top-0 bg-card border-b border-border z-10">
          <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
            <th className="py-2 pl-3 w-[28px]">
              <Chk
                checked={allSel}
                indeterminate={someSel}
                onChange={() => onToggleSelectAll(!allSel)}
                ariaLabel="Select all parsers"
              />
            </th>
            <th className="py-2 pl-1 text-left font-medium w-[88px]">Status</th>
            <th className="py-2 pl-1 text-left font-medium">Parser</th>
            <th className="py-2 pl-1 text-left font-medium w-[78px] @max-[820px]:hidden">Category</th>
            <th className="py-2 pl-1 text-left font-medium w-[74px] @max-[900px]:hidden">Transport</th>
            <th className="py-2 pl-1 text-left font-medium w-[74px] @max-[680px]:hidden">Version</th>
            <th className="py-2 pl-1 text-left font-medium w-[100px] @max-[1060px]:hidden">Commit</th>
            <th className="py-2 pl-1 pr-3 w-[80px]" />
          </tr>
        </thead>
        <tbody>
          {parsers.map((p) => (
            <ParserRow
              key={p.id}
              parser={p}
              selected={selected.has(p.id)}
              active={selectedParserId === p.id}
              onToggleSelect={() => onToggleSelect(p.id)}
              onSelect={() => onSelectParser(p.id)}
              onAction={() => onAction(p)}
            />
          ))}
          {parsers.length === 0 && (
            <tr>
              <td colSpan={8} className="py-8 text-center">
                <div className="flex flex-col items-center gap-1.5 text-muted-foreground">
                  <SearchIcon className="w-5 h-5" strokeWidth={1.5} />
                  <div className="text-[12.5px] font-medium text-foreground">{empty.title}</div>
                  <div className="text-[11px]">{empty.hint}</div>
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
  parser: RepoParserView;
  selected: boolean;
  active: boolean;
  onToggleSelect: () => void;
  onSelect: () => void;
  onAction: () => void;
}

function ParserRow({ parser, selected, active, onToggleSelect, onSelect, onAction }: RowProps) {
  const deleted = parser.status === 'DELETED';
  const imported = parser.status === 'IMPORTED';

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
          disabled={deleted || imported}
          ariaLabel={`Select ${parser.name}`}
        />
      </td>
      <td className="py-2 pl-1">
        <StatusChip status={parser.status} />
      </td>
      <td className="py-2 pl-1 pr-3 min-w-0">
        <div className="flex items-center gap-2 min-w-0 flex-wrap">
          <div className="font-mono text-[12px] text-foreground truncate">{parser.name}</div>
          {parser.importMode === 'forked' && (
            <span
              className="shrink-0 font-mono text-[9px] uppercase tracking-wider text-muted-foreground border border-border rounded px-1 py-px"
              title="Imported as a fork"
            >
              fork
            </span>
          )}
          {parser.importMode === 'linked' && parser.status !== 'AVAILABLE' && (
            <span
              className="shrink-0 font-mono text-[9px] uppercase tracking-wider text-success border border-success/30 bg-success/5 rounded px-1 py-px"
              title="Linked to upstream"
            >
              linked
            </span>
          )}
        </div>
        <div className="text-[10.5px] text-muted-foreground truncate">
          {[parser.vendor, parser.product].filter(Boolean).join(' · ')}
          {(parser.vendor || parser.product) && parser.desc && parser.desc !== '—' ? ' — ' : ''}
          {parser.desc !== '—' ? parser.desc : ''}
        </div>
        {/* Inline metadata when columns hidden */}
        <div className="hidden @max-[1060px]:flex items-center gap-1.5 flex-wrap mt-1">
          <span className="hidden @max-[820px]:inline-block">
            <CategoryChip cat={parser.category} />
          </span>
          <span className="hidden @max-[900px]:inline-block">
            <TransportChip t={parser.transport} />
          </span>
          <span className="flex items-center gap-1 font-mono text-[9.5px] text-muted-foreground">
            <GitCommit className="w-[9px] h-[9px]" strokeWidth={1.5} />
            {parser.commit}
            <span className="text-muted-foreground/70">· {parser.updated}</span>
          </span>
        </div>
      </td>
      <td className="py-2 pl-1 @max-[820px]:hidden">
        <CategoryChip cat={parser.category} />
      </td>
      <td className="py-2 pl-1 @max-[900px]:hidden">
        <TransportChip t={parser.transport} />
      </td>
      <td className="py-2 pl-1 @max-[680px]:hidden">
        <VersionCell parser={parser} />
      </td>
      <td className="py-2 pl-1 @max-[1060px]:hidden">
        <div className="flex items-center gap-1.5">
          <GitCommit className="w-[11px] h-[11px] text-muted-foreground" strokeWidth={1.5} />
          <span className="font-mono text-[10.5px] text-foreground/70">{parser.commit}</span>
        </div>
        <div className="text-[10px] text-muted-foreground truncate">{parser.updated}</div>
      </td>
      <td className="py-2 pl-1 pr-3" onClick={(e) => e.stopPropagation()}>
        <RowAction parser={parser} onAction={onAction} />
      </td>
    </tr>
  );
}

function VersionCell({ parser }: { parser: RepoParserView }) {
  if (parser.status === 'UPDATED' && parser.upstreamVersion && parser.version) {
    return (
      <span className="font-mono text-[10.5px]">
        <span className="text-muted-foreground line-through mr-1">v{parser.version}</span>
        <span className="text-warning">v{parser.upstreamVersion}</span>
      </span>
    );
  }
  if (parser.status === 'DRIFT' && parser.upstreamVersion) {
    return (
      <span className="font-mono text-[10.5px]">
        <span className="text-foreground/70">v{parser.version}</span>
        <span className="text-muted-foreground mx-0.5">·</span>
        <span className="text-destructive">v{parser.upstreamVersion}</span>
      </span>
    );
  }
  return (
    <span className="font-mono text-[10.5px] text-foreground/70">
      {parser.version ? `v${parser.version}` : '—'}
    </span>
  );
}

function RowAction({ parser, onAction }: { parser: RepoParserView; onAction: () => void }) {
  if (parser.status === 'IMPORTED') {
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
        <TooltipContent>Already imported — open the log source</TooltipContent>
      </Tooltip>
    );
  }
  if (parser.status === 'DELETED') {
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
  if (parser.status === 'DRIFT') {
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
        <TooltipContent>Resolve drift — merge upstream into your fork</TooltipContent>
      </Tooltip>
    );
  }
  if (parser.status === 'UPDATED') {
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
        <TooltipContent>Update linked copy to latest version</TooltipContent>
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
      <TooltipContent>Import as a draft log source</TooltipContent>
    </Tooltip>
  );
}
