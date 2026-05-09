// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef } from 'react';
import type { AutocompleteOption } from '@/lib/query-autocomplete';

interface QueryAutocompleteDropdownProps {
  options: AutocompleteOption[];
  selectedIndex: number;
  context: 'command' | 'field' | 'source_type' | 'function' | 'table_wildcard' | null;
  onSelect: (value: string) => void;
  onClose: () => void;
  cursorPosition?: { top: number; left: number };
}

export function QueryAutocompleteDropdown({
  options,
  selectedIndex,
  context,
  onSelect,
  onClose: _onClose,
  cursorPosition,
}: QueryAutocompleteDropdownProps) {
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Scroll selected item into view when selection changes
  useEffect(() => {
    if (dropdownRef.current) {
      const selectedElement = dropdownRef.current.children[selectedIndex] as HTMLElement;
      if (selectedElement) {
        selectedElement.scrollIntoView({ block: 'nearest' });
      }
    }
  }, [selectedIndex]);

  const getContextLabel = () => {
    switch (context) {
      case 'source_type':
        return `Available source types (${options.length})`;
      case 'field':
        return `Available fields (${options.length})`;
      case 'command':
        return `Pipe commands (${options.length})`;
      case 'function':
        return `Eval functions (${options.length})`;
      case 'table_wildcard':
        return `Table options (${options.length})`;
      default:
        return `Suggestions (${options.length})`;
    }
  };

  // Calculate position - if cursorPosition is provided, use it; otherwise default to top
  const style = cursorPosition
    ? {
        position: 'absolute' as const,
        top: `${cursorPosition.top + 20}px`,
        left: `${Math.max(16, cursorPosition.left)}px`,
        zIndex: 50,
      }
    : {
        position: 'absolute' as const,
        top: 'calc(100% + 4px)',
        left: '0',
        right: '0',
        zIndex: 50,
      };

  return (
    <div 
      style={style}
      className="bg-card border border-border rounded-xl shadow-lg overflow-hidden flex flex-col max-w-2xl">
      <div className="px-3 py-1.5 text-xs text-muted-foreground border-b border-border bg-muted/50 flex-shrink-0">
        {getContextLabel()}
      </div>
      <div ref={dropdownRef} className="overflow-y-auto max-h-64">
        {options.map((option, idx) => {
          const isSelected = idx === selectedIndex;
          return (
            <div
              key={`${option.value}-${idx}`}
              className={`px-3 py-2 cursor-pointer transition-colors ${
                isSelected 
                  ? 'bg-primary/20 text-primary' 
                  : 'text-foreground hover:bg-accent/50'
              }`}
              onMouseDown={() => onSelect(option.value)}
              title={option.description}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-mono">{option.value}</div>
                  {option.description && (
                    <div className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                      {option.description}
                    </div>
                  )}
                </div>
                {option.category && (
                  <div className="flex-shrink-0">
                    <span className="text-xs px-1.5 py-0.5 rounded bg-accent/50 text-muted-foreground">
                      {option.category}
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <div className="border-t border-border px-3 py-1.5 text-xs text-muted-foreground flex-shrink-0">
        ↑↓ navigate • Enter/Tab select • Esc dismiss
      </div>
    </div>
  );
}
