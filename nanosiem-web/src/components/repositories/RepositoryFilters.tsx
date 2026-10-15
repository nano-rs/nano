// SPDX-License-Identifier: AGPL-3.0-or-later

import { ChevronDown } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import type { ImportStatusFilter } from './repository-filters';

interface Props {
  importStatus: ImportStatusFilter;
  onImportStatusChange: (status: ImportStatusFilter) => void;
  importCounts: { all: number; imported: number; notImported: number };
  sourceCounts: Map<string, number>;
  selectedSourceTypes: ReadonlySet<string>;
  onSourceTypesChange: (sources: Set<string>) => void;
  onClear: () => void;
  hasFilters: boolean;
}

const statusLabels: Record<ImportStatusFilter, string> = {
  all: 'All',
  imported: 'Imported',
  'not-imported': 'Not imported',
};

export function RepositoryFilters({
  importStatus,
  onImportStatusChange,
  importCounts,
  sourceCounts,
  selectedSourceTypes,
  onSourceTypesChange,
  onClear,
  hasFilters,
}: Props) {
  const statusOptions: { id: ImportStatusFilter; count: number }[] = [
    { id: 'all', count: importCounts.all },
    { id: 'imported', count: importCounts.imported },
    { id: 'not-imported', count: importCounts.notImported },
  ];
  const triggerClass = 'h-[26px] px-2 rounded-md border border-border bg-card text-[11px] text-foreground/80 hover:bg-muted flex items-center gap-1.5';
  return (
    <div className="px-3.5 py-1.5 border-b border-border bg-card/30 flex items-center gap-2 flex-wrap">
      <DropdownMenu>
        <DropdownMenuTrigger className={triggerClass}>
          Import: <span className="font-mono text-foreground">{statusLabels[importStatus]}</span>
          <ChevronDown className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="min-w-[170px]">
          {statusOptions.map(({ id, count }) => (
            <DropdownMenuItem key={id} onSelect={() => onImportStatusChange(id)} className="text-[11px] flex justify-between gap-3">
              {statusLabels[id]}
              <span className="font-mono tabular-nums text-muted-foreground">{count}</span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <DropdownMenu>
        <DropdownMenuTrigger className={triggerClass}>
          Source type: <span className="font-mono text-foreground max-w-[130px] truncate">
            {selectedSourceTypes.size === 0 ? 'All' : selectedSourceTypes.size === 1 ? [...selectedSourceTypes][0] : `${selectedSourceTypes.size} selected`}
          </span>
          <ChevronDown className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="max-h-[300px] min-w-[210px] overflow-y-auto">
          {[...sourceCounts].sort(([a], [b]) => a.localeCompare(b)).map(([source, count]) => (
            <DropdownMenuCheckboxItem
              key={source}
              checked={selectedSourceTypes.has(source)}
              onSelect={(event) => event.preventDefault()}
              onCheckedChange={(checked) => {
                const next = new Set(selectedSourceTypes);
                if (checked) next.add(source);
                else next.delete(source);
                onSourceTypesChange(next);
              }}
              className="text-[11px] font-mono flex justify-between gap-3"
            >
              <span className="truncate">{source}</span>
              <span className="tabular-nums text-muted-foreground">{count}</span>
            </DropdownMenuCheckboxItem>
          ))}
          {sourceCounts.size === 0 && <div className="px-2 py-1.5 text-[11px] text-muted-foreground">No source types</div>}
        </DropdownMenuContent>
      </DropdownMenu>
      {hasFilters && (
        <button type="button" onClick={onClear} className="h-[26px] px-2 text-[11px] text-muted-foreground hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
