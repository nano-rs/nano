// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — toolbar sub-components: SegmentedSev severity pill + TacticChips.

import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { SEV_META, TACTIC_CHIPS, type SeverityKey } from './helpers';

type SevFilter = 'all' | SeverityKey;

interface SegmentedSevProps {
  value: SevFilter;
  onChange: (v: SevFilter) => void;
}

const SEV_SEGMENTS: Array<{ id: SevFilter; label: string; color?: string }> = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical', color: SEV_META.critical.color },
  { id: 'high', label: 'High', color: SEV_META.high.color },
  { id: 'medium', label: 'Medium', color: SEV_META.medium.color },
  { id: 'low', label: 'Low', color: SEV_META.low.color },
];

export function SegmentedSev({ value, onChange }: SegmentedSevProps) {
  return (
    <div
      className="inline-flex items-center gap-px p-0.5 rounded-md border border-border bg-[var(--panel)]"
    >
      {SEV_SEGMENTS.map((o) => (
        <button
          key={o.id}
          type="button"
          onClick={() => onChange(o.id)}
          className={cn(
            'h-6 px-2 rounded-[3px] text-[11px] flex items-center gap-1.5 transition-colors',
            value === o.id
              ? 'bg-foreground/8 text-foreground font-medium'
              : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5',
          )}
        >
          {o.color && (
            <span className="w-[5px] h-[5px] rounded-full" style={{ background: o.color }} />
          )}
          {o.label}
        </button>
      ))}
    </div>
  );
}

interface FilterSelectProps<T extends string> {
  label: string;
  value: T;
  options: Array<{ id: T; label: string }>;
  onChange: (v: T) => void;
}

export function FilterSelect<T extends string>({ label, value, options, onChange }: FilterSelectProps<T>) {
  const current = options.find((o) => o.id === value)?.label || 'All';
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-2 bg-transparent">
        <span className="text-muted-foreground">{label}</span>
        <span className="text-foreground">{current}</span>
        <ChevronDown className="w-3 h-3 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-[180px]">
        {options.map((o) => (
          <DropdownMenuItem
            key={o.id}
            onSelect={() => onChange(o.id)}
            className={cn('text-[11.5px]', value === o.id && 'bg-foreground/5')}
          >
            {o.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface TacticChipsProps {
  value: string;
  onChange: (v: string) => void;
}

export function TacticChips({ value, onChange }: TacticChipsProps) {
  return (
    <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-thin pb-1 -mb-1">
      {TACTIC_CHIPS.map((t) => (
        <button
          key={t}
          type="button"
          onClick={() => onChange(t)}
          className={cn(
            'h-7 px-2.5 rounded-md text-[11.5px] whitespace-nowrap border transition-colors shrink-0',
            value === t
              ? 'bg-primary/10 border-primary/30 text-primary'
              : 'border-border text-foreground hover:bg-foreground/5 hover:text-foreground',
          )}
        >
          {t}
        </button>
      ))}
    </div>
  );
}
