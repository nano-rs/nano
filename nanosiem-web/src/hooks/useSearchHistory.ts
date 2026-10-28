// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useCallback, useEffect, useRef } from 'react';
import { api } from '@/lib/api';
import type { TimeRangeValue } from '@/hooks/use-api';
import { getAccessToken } from '@/lib/auth-token';
import { requestCredentials } from '@/lib/request-credentials';
import { invalidateFieldUsageCache } from '@/lib/query-autocomplete';

export interface SearchHistoryEntry {
  id: string;
  query: string;
  queryMode: 'piped' | 'sql';
  timeRange: TimeRangeValue;
  timestamp: Date;
}

interface ApiHistoryEntry {
  id: string;
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string;
  time_range_start?: string;
  time_range_end?: string;
  created_at: string;
}

interface ListHistoryResponse {
  entries: ApiHistoryEntry[];
  history_enabled: boolean;
}

const API_BASE = import.meta.env.VITE_API_URL ?? '';

function getAuthHeaders(): HeadersInit {
  const token = getAccessToken();
  if (token) {
    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }
  return { 'Content-Type': 'application/json' };
}

function apiEntryToLocal(entry: ApiHistoryEntry): SearchHistoryEntry {
  let timeRange: TimeRangeValue;
  
  if (entry.time_range_type === 'preset' && entry.time_range_preset) {
    timeRange = { type: 'preset', preset: entry.time_range_preset };
  } else if (entry.time_range_start && entry.time_range_end) {
    timeRange = {
      type: 'custom',
      start: new Date(entry.time_range_start),
      end: new Date(entry.time_range_end),
    };
  } else {
    timeRange = { type: 'preset', preset: 'Last 24 hours' };
  }

  return {
    id: entry.id,
    query: entry.query,
    queryMode: entry.query_mode as 'piped' | 'sql',
    timeRange,
    timestamp: new Date(entry.created_at),
  };
}

export function useSearchHistory({ enabled = true }: { enabled?: boolean } = {}) {
  const [searchHistory, setSearchHistory] = useState<SearchHistoryEntry[]>([]);
  const [historyEnabled, setHistoryEnabled] = useState(enabled);
  const [isLoading, setIsLoading] = useState(enabled);
  const firstSearchCompletion = useRef<Promise<unknown> | null>(null);

  // Fetch history from API
  const fetchHistory = useCallback(async () => {
    if (!enabled) {
      setSearchHistory([]);
      setHistoryEnabled(false);
      setIsLoading(false);
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/api/search/history`, {
        headers: getAuthHeaders(),
        credentials: requestCredentials('/api/search/history', getAuthHeaders()),
      });
      
      if (response.ok) {
        const data: ListHistoryResponse = await response.json();
        setSearchHistory(data.entries.map(apiEntryToLocal));
        setHistoryEnabled(data.history_enabled);
      }
    } catch (err) {
      console.error('Failed to fetch search history:', err);
    } finally {
      setIsLoading(false);
    }
  }, [enabled]);

  // Load history on mount
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const toggleHistoryEnabled = useCallback(async (nextEnabled: boolean) => {
    if (!enabled) return;
    try {
      const response = await fetch(`${API_BASE}/api/search/history/settings`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        credentials: requestCredentials('/api/search/history', getAuthHeaders()),
        body: JSON.stringify({ enabled: nextEnabled }),
      });
      
      if (response.ok) {
        setHistoryEnabled(nextEnabled);
      }
    } catch (err) {
      console.error('Failed to toggle history:', err);
    }
  }, [enabled]);

  const clearSearchHistory = useCallback(async () => {
    if (!enabled) return;
    try {
      const response = await fetch(`${API_BASE}/api/search/history`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
        credentials: requestCredentials('/api/search/history', getAuthHeaders()),
      });
      
      if (response.ok) {
        setSearchHistory([]);
        invalidateFieldUsageCache();
      }
    } catch (err) {
      console.error('Failed to clear history:', err);
    }
  }, [enabled]);

  const deleteHistoryEntry = useCallback(async (id: string) => {
    if (!enabled) return;
    try {
      const response = await fetch(`${API_BASE}/api/search/history/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
        credentials: requestCredentials('/api/search/history', getAuthHeaders()),
      });
      
      if (response.ok) {
        setSearchHistory(prev => prev.filter(h => h.id !== id));
        invalidateFieldUsageCache();
      }
    } catch (err) {
      console.error('Failed to delete history entry:', err);
    }
  }, [enabled]);

  const completeFirstSearch = useCallback(async () => {
    // Persist only the step flag, with no query or time-range data. Share the
    // request across runs on this page and allow a later run to retry errors.
    firstSearchCompletion.current ??= api.onboarding.completeStep({ step: 'first_searches' })
      .catch(() => { firstSearchCompletion.current = null; });
    await firstSearchCompletion.current;
  }, []);

  const addToSearchHistory = useCallback(async (entry: Omit<SearchHistoryEntry, 'id' | 'timestamp'>) => {
    if (!enabled) return;
    if (!historyEnabled) {
      // Running a query still completes First Search when history is disabled.
      await completeFirstSearch();
      return;
    }
    
    // Build request body
    const body: Record<string, unknown> = {
      query: entry.query,
      query_mode: entry.queryMode,
      time_range_type: entry.timeRange.type,
    };

    if (entry.timeRange.type === 'preset') {
      body.time_range_preset = entry.timeRange.preset;
    } else if (entry.timeRange.type === 'custom' && entry.timeRange.start && entry.timeRange.end) {
      body.time_range_start = entry.timeRange.start.toISOString();
      body.time_range_end = entry.timeRange.end.toISOString();
    }

    try {
      const response = await fetch(`${API_BASE}/api/search/history`, {
        method: 'POST',
        headers: getAuthHeaders(),
        credentials: requestCredentials('/api/search/history', getAuthHeaders()),
        body: JSON.stringify(body),
      });
      
      if (response.ok) {
        const newEntry: ApiHistoryEntry = await response.json();
        const localEntry = apiEntryToLocal(newEntry);
        // The server dropped its cached ranking for us; drop ours so the
        // fields just searched show under "Recent (you)" right away.
        invalidateFieldUsageCache();
        
        // Add to front, dedupe by checking if already exists
        setSearchHistory(prev => {
          const filtered = prev.filter(h => h.id !== localEntry.id);
          return [localEntry, ...filtered];
        });
      } else {
        // The first run can race the initial history-settings GET, or history
        // can be disabled in another tab. A refused history write must not
        // leave First Search unchecked after a query was run.
        await completeFirstSearch();
      }
    } catch (err) {
      console.error('Failed to add to history:', err);
    }
  }, [enabled, historyEnabled, completeFirstSearch]);

  const refreshHistory = useCallback(() => {
    fetchHistory();
  }, [fetchHistory]);

  return {
    searchHistory,
    historyEnabled,
    isLoading,
    toggleHistoryEnabled,
    clearSearchHistory,
    deleteHistoryEntry,
    addToSearchHistory,
    refreshHistory,
  };
}
