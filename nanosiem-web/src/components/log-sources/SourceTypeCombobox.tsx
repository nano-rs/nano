// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo } from 'react';
import { Check, ChevronsUpDown, CircleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { cn } from '@/lib/utils';
import type { LogSource } from '@/lib/api';

interface SourceTypeComboboxProps {
  value: string;
  onChange: (value: string) => void;
  logSources: LogSource[];
  placeholder?: string;
  disabled?: boolean;
}

export function SourceTypeCombobox({
  value,
  onChange,
  logSources,
  placeholder = 'Select a parser...',
  disabled,
}: SourceTypeComboboxProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');

  // Build options from log sources: each source_type and match_value becomes an option
  const options = useMemo(() => {
    const seen = new Set<string>();
    const result: { sourceType: string; parserName: string; isMatchValue: boolean }[] = [];

    for (const ls of logSources) {
      // Primary: the log source's source_type
      if (ls.source_type && !seen.has(ls.source_type)) {
        seen.add(ls.source_type);
        result.push({ sourceType: ls.source_type, parserName: ls.name, isMatchValue: false });
      }
      // Also include match_values (these are what the router actually matches on)
      for (const mv of ls.match_values ?? []) {
        if (!seen.has(mv)) {
          seen.add(mv);
          result.push({ sourceType: mv, parserName: ls.name, isMatchValue: true });
        }
      }
    }

    return result.sort((a, b) => a.sourceType.localeCompare(b.sourceType));
  }, [logSources]);

  // Find the matching option for display
  const selectedOption = options.find((o) => o.sourceType === value);
  const isUnmatched = value && !selectedOption;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn(
            'w-full h-8 justify-between font-normal text-[12px] bg-card',
            !value && 'text-muted-foreground'
          )}
          disabled={disabled}
        >
          <span className="truncate">
            {value ? (
              <span className="flex items-center gap-2">
                <code className="text-[10.5px] font-mono bg-muted px-1 py-0.5 rounded">
                  {value}
                </code>
                {selectedOption && (
                  <span className="text-[10.5px] text-muted-foreground">
                    {selectedOption.parserName}
                  </span>
                )}
                {isUnmatched && (
                  <span className="flex items-center gap-1 text-[10.5px] text-yellow-500">
                    <CircleAlert className="h-3 w-3" />
                    no parser
                  </span>
                )}
              </span>
            ) : (
              placeholder
            )}
          </span>
          <ChevronsUpDown className="ml-2 h-3 w-3 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[--radix-popover-trigger-width] p-0" align="start">
        <Command shouldFilter={false}>
          <CommandInput
            placeholder="Search parsers…"
            value={search}
            onValueChange={setSearch}
            className="h-8 text-[12px]"
          />
          <CommandList>
            <CommandEmpty>
              {search ? (
                <button
                  className="w-full px-2 py-1.5 text-[12px] text-left hover:bg-accent rounded cursor-pointer"
                  onClick={() => {
                    onChange(search);
                    setOpen(false);
                    setSearch('');
                  }}
                >
                  Use custom value:{' '}
                  <code className="font-mono text-[10.5px] bg-muted px-1 rounded">
                    {search}
                  </code>
                </button>
              ) : (
                <span className="text-[11.5px]">No parsers found.</span>
              )}
            </CommandEmpty>
            <CommandGroup
              heading="Deployed parsers"
              className="[&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.12em]"
            >
              {options
                .filter((o) =>
                  !search ||
                  o.sourceType.toLowerCase().includes(search.toLowerCase()) ||
                  o.parserName.toLowerCase().includes(search.toLowerCase())
                )
                .map((option) => (
                  <CommandItem
                    key={option.sourceType}
                    value={option.sourceType}
                    onSelect={() => {
                      onChange(option.sourceType);
                      setOpen(false);
                      setSearch('');
                    }}
                    className="text-[12px] py-1"
                  >
                    <Check
                      className={cn(
                        'mr-2 h-3 w-3',
                        value === option.sourceType ? 'opacity-100' : 'opacity-0'
                      )}
                    />
                    <div className="flex flex-col min-w-0">
                      <span className="font-mono text-[12px] text-foreground truncate">
                        {option.sourceType}
                      </span>
                      <span className="text-[10.5px] text-muted-foreground truncate">
                        {option.parserName}
                      </span>
                    </div>
                  </CommandItem>
                ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
