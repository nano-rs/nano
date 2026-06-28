// SPDX-License-Identifier: AGPL-3.0-or-later

import { useRef, useCallback, useEffect, useState, useMemo } from 'react';
import { Clock, Pin, Search, X, Settings2, Trash2, Info } from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import type { SearchHistoryEntry } from '@/hooks/useSearchHistory';
import { formatRelativeCompact } from '@/lib/date-utils';
import { SearchQueryEditor, type SearchQueryEditorRef } from '@/components/editor';
import type { EditorView } from '@codemirror/view';
import { setAutocompleteTimeRange } from '@/lib/query-autocomplete';

const NL_HINT_DISMISSED_KEY = 'nanosiem-nl-hint-dismissed';

interface SavedSearchSuggestion {
  id: string;
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
}

interface SearchQueryInputProps {
  query: string;
  onQueryChange: (query: string) => void;
  queryMode: 'piped' | 'sql';
  onSearch: () => void;
  onAiSearch?: () => void;
  aiMode?: boolean;
  // History typeahead
  searchHistory?: SearchHistoryEntry[];
  historyEnabled?: boolean;
  onToggleHistoryEnabled?: (enabled: boolean) => void;
  onClearAllHistory?: () => void;
  savedSearches?: SavedSearchSuggestion[];
  pinnedSearchIds?: string[];
  onSelectHistoryItem?: (query: string, mode: 'piped' | 'sql') => void;
  timeRange?: { start: string; end: string };
}



export function SearchQueryInput({
  query,
  onQueryChange,
  queryMode,
  onSearch,
  onAiSearch,
  aiMode,
  searchHistory = [],
  historyEnabled,
  onToggleHistoryEnabled,
  onClearAllHistory,
  savedSearches = [],
  pinnedSearchIds = [],
  onSelectHistoryItem,
  timeRange,
}: SearchQueryInputProps) {
  const editorRef = useRef<SearchQueryEditorRef>(null);
  const historyDropdownRef = useRef<HTMLDivElement>(null);

  // Sync time range to shared autocomplete module for source type queries
  useEffect(() => {
    setAutocompleteTimeRange(timeRange);
  }, [timeRange]);

  // History typeahead state
  const [showHistorySuggestions, setShowHistorySuggestions] = useState(false);
  const [selectedHistoryIndex, setSelectedHistoryIndex] = useState(0);
  const [historyLimit, setHistoryLimit] = useState(50);
  const [historyFilter, setHistoryFilter] = useState('');
  const historyFilterRef = useRef<HTMLInputElement>(null);

  // Auto-suggest preference (localStorage toggle from Settings)
  // Listen for storage changes so toggling in Settings takes effect immediately
  const [autoSuggest, setAutoSuggest] = useState(() =>
    localStorage.getItem('nanosiem-auto-autocomplete') !== 'false'
  );
  useEffect(() => {
    const onStorage = () => {
      setAutoSuggest(localStorage.getItem('nanosiem-auto-autocomplete') !== 'false');
    };
    window.addEventListener('storage', onStorage);
    // Also poll on focus in case same-tab changes (storage event only fires cross-tab)
    const onFocus = () => onStorage();
    window.addEventListener('focus', onFocus);
    return () => {
      window.removeEventListener('storage', onStorage);
      window.removeEventListener('focus', onFocus);
    };
  }, []);

  // Natural language hint state
  const [isFocused, setIsFocused] = useState(false);
  const [nlHintDismissed, setNlHintDismissed] = useState(() => {
    return localStorage.getItem(NL_HINT_DISMISSED_KEY) === 'true';
  });

  const dismissNlHint = useCallback(() => {
    setNlHintDismissed(true);
    localStorage.setItem(NL_HINT_DISMISSED_KEY, 'true');
  }, []);

  // Reset history limit/filter when dropdown closes, focus filter when it opens
  useEffect(() => {
    if (!showHistorySuggestions) {
      setHistoryLimit(50);
      setHistoryFilter('');
    } else {
      // Focus the filter input when dropdown opens
      setTimeout(() => historyFilterRef.current?.focus(), 0);
    }
  }, [showHistorySuggestions]);

  // Combined and filtered history suggestions (pinned saved searches first, then recent history)
  const { historySuggestions, hasMoreHistory, totalHistoryCount } = useMemo(() => {
    const suggestions: Array<{
      type: 'pinned' | 'saved' | 'history';
      id: string;
      query: string;
      mode: 'piped' | 'sql';
      name?: string;
      timestamp?: Date;
    }> = [];

    const filterLower = historyFilter.toLowerCase().trim();
    const isFiltering = filterLower.length > 0;

    // Add pinned saved searches first
    const pinnedSaved = savedSearches.filter(s => pinnedSearchIds.includes(s.id));
    for (const s of pinnedSaved) {
      if (!isFiltering || s.query.toLowerCase().includes(filterLower) || s.name.toLowerCase().includes(filterLower)) {
        suggestions.push({
          type: 'pinned',
          id: s.id,
          query: s.query,
          mode: s.query_mode,
          name: s.name,
        });
      }
    }

    // Add all matching history (we'll limit display later)
    for (const h of searchHistory) {
      // Skip if this query is already in suggestions (from saved)
      if (suggestions.some(s => s.query === h.query)) continue;
      if (!isFiltering || h.query.toLowerCase().includes(filterLower)) {
        suggestions.push({
          type: 'history',
          id: h.id,
          query: h.query,
          mode: h.queryMode,
          timestamp: h.timestamp,
        });
      }
    }

    const total = suggestions.length;
    const limited = suggestions.slice(0, historyLimit);
    return {
      historySuggestions: limited,
      hasMoreHistory: total > historyLimit,
      totalHistoryCount: total,
    };
  }, [historyFilter, searchHistory, savedSearches, pinnedSearchIds, historyLimit]);

  const loadMoreHistory = useCallback(() => {
    setHistoryLimit(prev => prev + 20);
  }, []);


  // Scroll selected history item into view
  useEffect(() => {
    if (showHistorySuggestions && historyDropdownRef.current) {
      const selectedElement = historyDropdownRef.current.children[selectedHistoryIndex] as HTMLElement;
      if (selectedElement) {
        selectedElement.scrollIntoView({ block: 'nearest' });
      }
    }
  }, [selectedHistoryIndex, showHistorySuggestions]);

  // Reset history selection when suggestions change
  useEffect(() => {
    setSelectedHistoryIndex(0);
  }, [historySuggestions]);

  const placeholder = queryMode === 'piped'
    ? 'Search logs… try source_type=syslog or status=500'
    : 'SELECT … FROM logs';

  // Show hint when focused and not dismissed (and no dropdowns open)
  const showNlHint = isFocused && !nlHintDismissed && !showHistorySuggestions && !aiMode;

  // Retro hunts scan every event in the selected time range (no narrow-window
  // shortcut), so surface that the moment a `| retro` command is typed — it tells
  // analysts to widen the window deliberately AND keep it reasonable (NAN-1587).
  const showRetroHint = useMemo(
    () => queryMode === 'piped' && /\|\s*retro\b/i.test(query),
    [queryMode, query]
  );

  // Handle keyboard events from CodeMirror - return true to prevent CodeMirror from handling
  // Autocomplete keyboard navigation is now handled by CodeMirror's autocompletion extension
  const handleEditorKeyDown = useCallback((event: KeyboardEvent, _view: EditorView): boolean => {
    // Down arrow at start of input or empty field triggers history
    if (event.key === 'ArrowDown' && !showHistorySuggestions) {
      const pos = editorRef.current?.getCursorPosition() || 0;
      const isEmpty = query.trim() === '';
      const atStart = pos === 0;

      if ((isEmpty || atStart) && historySuggestions.length > 0) {
        setShowHistorySuggestions(true);
        setSelectedHistoryIndex(0);
        return true;
      }
    }

    // History suggestions navigation
    if (showHistorySuggestions && historySuggestions.length > 0) {
      if (event.key === 'ArrowDown') {
        setSelectedHistoryIndex(Math.min(selectedHistoryIndex + 1, historySuggestions.length - 1));
        return true;
      } else if (event.key === 'ArrowUp') {
        setSelectedHistoryIndex(Math.max(selectedHistoryIndex - 1, 0));
        return true;
      } else if (event.key === 'Enter' && !event.shiftKey && !event.metaKey) {
        const selected = historySuggestions[selectedHistoryIndex];
        if (selected) {
          const cleanQuery = selected.query.trim();
          if (onSelectHistoryItem) {
            onSelectHistoryItem(cleanQuery, selected.mode);
          } else {
            onQueryChange(cleanQuery);
          }
          setShowHistorySuggestions(false);
          return true;
        }
      } else if (event.key === 'Escape') {
        setShowHistorySuggestions(false);
        return true;
      } else if (event.key === 'Tab' && !event.shiftKey) {
        setShowHistorySuggestions(false);
        return false; // Let CodeMirror autocomplete handle Tab
      }
    }

    // Cmd+Shift+Enter = AI search (explicit shortcut)
    if (event.key === 'Enter' && event.metaKey && event.shiftKey && onAiSearch) {
      onAiSearch();
      return true;
    }

    return false;
  }, [
    showHistorySuggestions,
    query,
    historySuggestions,
    selectedHistoryIndex,
    onSelectHistoryItem,
    onQueryChange,
    onAiSearch,
  ]);

  // Handle Enter/submit from CodeMirror
  const handleSubmit = useCallback(() => {
    setShowHistorySuggestions(false);
    if (aiMode && onAiSearch) {
      onAiSearch();
    } else {
      onSearch();
    }
  }, [aiMode, onAiSearch, onSearch]);

  // Handle focus
  const handleFocus = useCallback(() => {
    setIsFocused(true);
  }, []);

  // Handle blur
  const handleBlur = useCallback(() => {
    setIsFocused(false);
    // Don't close history if focus moved to the history filter input
    // (editor blur fires after 150ms delay - check at that point)
    if (historyFilterRef.current && historyFilterRef.current.contains(document.activeElement)) return;
    setShowHistorySuggestions(false);
  }, []);

  // Handle value changes — autocomplete is now handled by CodeMirror extension
  const handleChange = useCallback((value: string) => {
    onQueryChange(value);
  }, [onQueryChange]);

  return (
    <div className="flex-1 flex flex-col">
      {/* Natural language hint - slides in above input */}
      <div className={`overflow-hidden transition-all duration-300 ease-out ${
        showNlHint ? 'max-h-8 opacity-100 mb-1.5' : 'max-h-0 opacity-0 mb-0'
      }`}>
        <div className="flex items-center gap-1.5 px-1 text-xs text-muted-foreground">
          <PivtIcon className="h-3 w-3 flex-shrink-0" style={{ color: 'var(--ai)' }} />
          <span>Try natural language like</span>
          <span className="italic" style={{ color: 'var(--ai)' }}>"show me failed logins from yesterday"</span>
          <button
            className="p-0.5 rounded hover:bg-accent transition-colors flex-shrink-0"
            onClick={dismissNlHint}
            onMouseDown={(e) => e.preventDefault()}
          >
            <X className="h-3 w-3 text-muted-foreground/50 hover:text-muted-foreground" />
          </button>
        </div>
      </div>

      <div className="relative">
        <div className={`search-console-input-shell relative border rounded-md min-h-[34px] resize-y overflow-hidden transition-colors duration-300 ease-out ${
          aiMode
            ? 'pt-1.5 bg-ai-bg-subtle border-ai-border ring-1 ring-ai/25 focus-within:border-ai focus-within:ring-ai/35'
            : 'bg-background border-border focus-within:border-primary/50 focus-within:ring-1 focus-within:ring-primary/25'
        }`}>
        <SearchQueryEditor
          ref={editorRef}
          value={query}
          onChange={handleChange}
          placeholder={placeholder}
          aiMode={aiMode}
          sqlMode={queryMode === 'sql'}
          onKeyDown={handleEditorKeyDown}

          onFocus={handleFocus}
          onBlur={handleBlur}
          onSubmit={handleSubmit}
          onTabPress={() => setShowHistorySuggestions(false)}
          autocomplete={queryMode === 'sql' ? false : (autoSuggest ? 'auto' : 'manual')}
        />
        {/* Keyboard hint overlay — always visible. Left kbd flips purple
            in NL mode ("⌘↵ translate & run"); history hint stays neutral. */}
        <div className="pointer-events-none select-none absolute top-1.5 right-2.5 hidden md:flex items-center gap-1 text-[10px]">
          {aiMode ? (
            <>
              <kbd className="px-1 py-0.5 bg-ai-bg border border-ai-border rounded-[3px] font-mono text-[9.5px] leading-none text-ai">⌘↵</kbd>
              <span className="text-ai/80">translate &amp; run</span>
            </>
          ) : (
            <>
              <kbd className="px-1 py-0.5 bg-foreground/5 border border-border rounded-[3px] font-mono text-[9.5px] leading-none text-muted-foreground">⌘↵</kbd>
              <span className="text-muted-foreground/60">run</span>
            </>
          )}
          <span className="text-muted-foreground/40 mx-0.5">·</span>
          <kbd className="px-1 py-0.5 bg-foreground/5 border border-border rounded-[3px] font-mono text-[9.5px] leading-none text-muted-foreground">↓</kbd>
          <span className="text-muted-foreground/60">history</span>
        </div>
        </div>
        {/* NATURAL LANGUAGE badge — sibling of the shell (so it can poke
            above the shell's rounded border without being clipped by the
            shell's overflow-hidden). */}
        {aiMode && (
          <div className="absolute -top-[9px] left-3 pointer-events-none inline-flex items-center gap-1 px-1.5 py-[2px] rounded-[4px] text-[9px] font-mono font-semibold tracking-[0.1em] uppercase bg-card text-ai border border-ai-border z-10">
            <span aria-hidden className="text-[11px] leading-none font-normal -mt-px">+</span>
            Natural language
          </div>
        )}
      {/* History suggestions dropdown — shadcn redesign (NAN-374).
          Nested inside the relative input wrapper so `top-full` anchors
          directly under the input shell, not the outer search card. */}
      {showHistorySuggestions && (historySuggestions.length > 0 || historyFilter.length > 0) && (
        <div className="search-console-dropdown search-console-history absolute top-full left-0 right-0 -mt-px bg-popover border border-border-2 rounded-[8px] shadow-[0_20px_60px_rgba(0,0,0,0.5)] z-[100] overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
          {/* Header: mono uppercase label + kbd hints */}
          <div className="px-3 py-2 border-b border-border font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/80 font-semibold flex items-center gap-2">
            <Clock className="w-[11px] h-[11px]" />
            <span>Search history</span>
            <span className="ml-auto normal-case tracking-normal font-medium text-muted-foreground/60 flex items-center gap-1">
              <kbd className="px-1 py-0.5 bg-foreground/5 border border-border rounded-[3px] text-[9.5px] leading-none">↑↓</kbd>
              <span>navigate</span>
              <span className="text-muted-foreground/40 mx-0.5">·</span>
              <kbd className="px-1 py-0.5 bg-foreground/5 border border-border rounded-[3px] text-[9.5px] leading-none">↵</kbd>
              <span>select</span>
              <span className="text-muted-foreground/40 mx-0.5">·</span>
              <kbd className="px-1 py-0.5 bg-foreground/5 border border-border rounded-[3px] text-[9.5px] leading-none">esc</kbd>
              <span>close</span>
            </span>
            <button
              className="ml-1 p-0.5 rounded hover:bg-foreground/10 transition-colors"
              onMouseDown={(e) => {
                e.preventDefault();
                setShowHistorySuggestions(false);
                editorRef.current?.focus();
              }}
              aria-label="Close history"
            >
              <X className="h-3 w-3 text-muted-foreground/60 hover:text-muted-foreground" />
            </button>
          </div>
          {/* Filter row */}
          <div className="px-3 py-2 border-b border-border flex items-center gap-2">
            <Search className="h-3.5 w-3.5 text-muted-foreground/70 flex-shrink-0" />
            <input
              ref={historyFilterRef}
              type="text"
              value={historyFilter}
              onChange={(e) => setHistoryFilter(e.target.value)}
              placeholder="Filter history…"
              className="flex-1 bg-transparent text-[12.5px] text-foreground placeholder:text-muted-foreground/50 outline-none"
              onBlur={() => {
                setTimeout(() => {
                  const dropdown = historyDropdownRef.current?.parentElement;
                  if (dropdown?.contains(document.activeElement)) return;
                  setShowHistorySuggestions(false);
                }, 150);
              }}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  setSelectedHistoryIndex(Math.min(selectedHistoryIndex + 1, historySuggestions.length - 1));
                } else if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  setSelectedHistoryIndex(Math.max(selectedHistoryIndex - 1, 0));
                } else if (e.key === 'Enter') {
                  e.preventDefault();
                  const selected = historySuggestions[selectedHistoryIndex];
                  if (selected) {
                    const cleanQuery = selected.query.trim();
                    if (onSelectHistoryItem) {
                      onSelectHistoryItem(cleanQuery, selected.mode);
                    } else {
                      onQueryChange(cleanQuery);
                    }
                    setShowHistorySuggestions(false);
                    editorRef.current?.focus();
                  }
                } else if (e.key === 'Escape') {
                  e.preventDefault();
                  setShowHistorySuggestions(false);
                  editorRef.current?.focus();
                }
              }}
            />
          </div>
          {/* List */}
          <div ref={historyDropdownRef} className="overflow-y-auto max-h-80 py-1">
            {historySuggestions.length === 0 && historyFilter.length > 0 && (
              <div className="px-3 py-6 text-center font-mono text-[11px] text-muted-foreground/70">
                No matches for "{historyFilter}"
              </div>
            )}
            {historySuggestions.map((item, idx) => {
              const isSelected = idx === selectedHistoryIndex;
              return (
                <div
                  key={`${item.type}-${item.id}`}
                  className={`mx-1 px-2 py-1.5 rounded-[5px] cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-primary/10'
                      : 'hover:bg-foreground/5'
                  }`}
                  title={item.query}
                  onMouseDown={() => {
                    const cleanQuery = item.query.trim();
                    if (onSelectHistoryItem) {
                      onSelectHistoryItem(cleanQuery, item.mode);
                    } else {
                      onQueryChange(cleanQuery);
                    }
                    setShowHistorySuggestions(false);
                  }}
                >
                  <div className="flex items-center gap-2 font-mono">
                    {item.type === 'pinned' ? (
                      <Pin className={`w-[11px] h-[11px] shrink-0 ${isSelected ? 'text-primary' : 'text-primary/70'}`} />
                    ) : (
                      <Search className={`w-[11px] h-[11px] shrink-0 ${isSelected ? 'text-primary' : 'text-muted-foreground/70'}`} />
                    )}
                    <div className="flex-1 min-w-0">
                      {item.name && (
                        <div className="text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground/70 truncate mb-0.5" title={item.name}>{item.name}</div>
                      )}
                      <span className={`block truncate text-[11.5px] ${isSelected ? 'text-primary' : 'text-foreground/85'}`}>
                        {item.query}
                      </span>
                    </div>
                    {item.timestamp && (
                      <span className="text-[10.5px] text-muted-foreground/60 shrink-0 ml-2">
                        {formatRelativeCompact(item.timestamp)}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
            {hasMoreHistory && (
              <div
                className="mx-1 mt-1 px-2 py-1.5 rounded-[5px] text-center cursor-pointer hover:bg-foreground/5 transition-colors"
                onMouseDown={(e) => {
                  e.preventDefault();
                  loadMoreHistory();
                }}
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground">
                  Load more ({totalHistoryCount - historySuggestions.length} remaining)
                </span>
              </div>
            )}
          </div>
          {/* Footer: count left, actions right */}
          <div className="px-3 py-2 border-t border-border font-mono text-[10px] text-muted-foreground flex items-center justify-between gap-2">
            <span>
              {totalHistoryCount} {totalHistoryCount === 1 ? 'entry' : 'entries'}
              {hasMoreHistory && ` · showing ${historySuggestions.length}`}
            </span>
            <div className="flex items-center gap-3">
              {onToggleHistoryEnabled && (
                <button
                  className="flex items-center gap-1 uppercase tracking-[0.12em] hover:text-foreground transition-colors"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    onToggleHistoryEnabled(!historyEnabled);
                  }}
                >
                  <Settings2 className="h-3 w-3" />
                  {historyEnabled ? 'Disable' : 'Enable'}
                </button>
              )}
              {onClearAllHistory && searchHistory.length > 0 && (
                <button
                  className="flex items-center gap-1 uppercase tracking-[0.12em] text-destructive/70 hover:text-destructive transition-colors"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    onClearAllHistory();
                    setShowHistorySuggestions(false);
                    editorRef.current?.focus();
                  }}
                >
                  <Trash2 className="h-3 w-3" />
                  Clear all
                </button>
              )}
            </div>
          </div>
        </div>
      )}
      </div>

      {/* Retro full-scan notice (NAN-1587): retro evaluates the indicator against
          every event in the selected time range — make the cost model explicit so
          analysts widen the window on purpose and keep it reasonable. */}
      <div className={`overflow-hidden transition-all duration-300 ease-out ${
        showRetroHint ? 'max-h-16 opacity-100 mt-1.5' : 'max-h-0 opacity-0 mt-0'
      }`}>
        <div className="flex items-start gap-1.5 px-1 text-[11px] text-muted-foreground">
          <Info className="h-3 w-3 flex-shrink-0 mt-px text-brand" />
          <span>
            <span className="text-foreground font-medium">Retro hunt</span> scans every event in the selected time range.
            Keep the window tight (a few days) for fast results — very wide ranges may time out.
          </span>
        </div>
      </div>
    </div>
  );
}
