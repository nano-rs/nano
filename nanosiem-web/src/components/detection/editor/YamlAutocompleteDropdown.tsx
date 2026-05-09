// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useRef, useEffect } from 'react';
import { X, Search } from 'lucide-react';
import type { AutocompleteSuggestion } from '@/lib/yaml-autocomplete';

interface YamlAutocompleteDropdownProps {
  suggestion: AutocompleteSuggestion;
  selectedIndex: number;
  onSelect: (value: string) => void;
  onClose: () => void;
}

export function YamlAutocompleteDropdown({
  suggestion,
  selectedIndex,
  onSelect,
  onClose,
}: YamlAutocompleteDropdownProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);
  
  // Determine if this is a searchable field (MITRE fields have many options)
  const isSearchable = suggestion?.field?.startsWith('mitre_') && suggestion.options.length > 10;
  
  // Filter options based on search query
  const filteredOptions = useMemo(() => {
    if (!suggestion || !searchQuery.trim()) {
      return suggestion?.options || [];
    }
    
    const query = searchQuery.toLowerCase();
    return suggestion.options.filter(option => 
      option.value.toLowerCase().includes(query) ||
      option.label.toLowerCase().includes(query) ||
      (option.description && option.description.toLowerCase().includes(query))
    );
  }, [suggestion, searchQuery]);
  
  // Focus search input when dropdown opens for searchable fields
  useEffect(() => {
    if (isSearchable && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isSearchable, suggestion?.field]);
  
  // Reset search when field changes
  useEffect(() => {
    setSearchQuery('');
  }, [suggestion?.field]);

  if (!suggestion || suggestion.options.length === 0) {
    return null;
  }

  return (
    <div
      className="absolute bg-card border border-border rounded-lg shadow-xl z-10 min-w-[320px] max-w-[450px]"
      style={{
        top: `${(suggestion.position.line + 2) * 20 + 16}px`,
        left: '16px',
      }}
    >
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <span className="text-xs text-muted-foreground font-medium">{suggestion.field}</span>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-primary transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      
      {/* Search input for MITRE fields */}
      {isSearchable && (
        <div className="px-2 py-2 border-b border-border">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search tactics or techniques..."
              className="w-full pl-8 pr-3 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-1 focus:ring-primary"
              onKeyDown={(e) => {
                // Prevent dropdown keyboard navigation from interfering
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                  e.stopPropagation();
                }
              }}
            />
          </div>
          {searchQuery && (
            <div className="text-xs text-muted-foreground mt-1 px-1">
              {filteredOptions.length} of {suggestion.options.length} results
            </div>
          )}
        </div>
      )}
      
      <div className="p-1 max-h-[300px] overflow-y-auto">
        {filteredOptions.length === 0 ? (
          <div className="px-3 py-4 text-sm text-muted-foreground text-center">
            No matches found for "{searchQuery}"
          </div>
        ) : (
          filteredOptions.map((option, index) => (
            <button
              key={option.value}
              onClick={() => onSelect(option.value)}
              className={`w-full text-left px-3 py-2 text-sm transition-colors ${
                index === selectedIndex
                  ? 'bg-primary text-primary-foreground rounded-md'
                  : 'text-foreground hover:bg-accent rounded-md'
              }`}
            >
              <div className="font-medium">{option.label}</div>
              {option.description && (
                <div className={`text-xs mt-0.5 ${
                  index === selectedIndex ? 'text-blue-100' : 'text-muted-foreground'
                }`}>
                  {option.description}
                </div>
              )}
            </button>
          ))
        )}
      </div>
      <div className="border-t border-border px-3 py-1.5 text-xs text-muted-foreground">
        {isSearchable ? 'Type to search • ' : ''}↑↓ navigate • Enter/Tab select • Esc dismiss
      </div>
    </div>
  );
}
