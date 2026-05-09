// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useCallback, useEffect } from 'react';
import type { TimeRangeValue } from '@/hooks/use-api';
import { getAccessToken } from '@/lib/auth-token';

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

export function useSearchHistory() {
  const [searchHistory, setSearchHistory] = useState<SearchHistoryEntry[]>([]);
  const [historyEnabled, setHistoryEnabled] = useState(true);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch history from API
  const fetchHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/search/history`, {
        headers: getAuthHeaders(),
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
  }, []);

  // Load history on mount
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const toggleHistoryEnabled = useCallback(async (enabled: boolean) => {
    try {
      const response = await fetch(`${API_BASE}/api/search/history/settings`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ enabled }),
      });
      
      if (response.ok) {
        setHistoryEnabled(enabled);
      }
    } catch (err) {
      console.error('Failed to toggle history:', err);
    }
  }, []);

  const clearSearchHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/search/history`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      
      if (response.ok) {
        setSearchHistory([]);
      }
    } catch (err) {
      console.error('Failed to clear history:', err);
    }
  }, []);

  const deleteHistoryEntry = useCallback(async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/search/history/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      
      if (response.ok) {
        setSearchHistory(prev => prev.filter(h => h.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete history entry:', err);
    }
  }, []);

  const addToSearchHistory = useCallback(async (entry: Omit<SearchHistoryEntry, 'id' | 'timestamp'>) => {
    if (!historyEnabled) return;
    
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
        body: JSON.stringify(body),
      });
      
      if (response.ok) {
        const newEntry: ApiHistoryEntry = await response.json();
        const localEntry = apiEntryToLocal(newEntry);
        
        // Add to front, dedupe by checking if already exists
        setSearchHistory(prev => {
          const filtered = prev.filter(h => h.id !== localEntry.id);
          return [localEntry, ...filtered];
        });
      }
    } catch (err) {
      console.error('Failed to add to history:', err);
    }
  }, [historyEnabled]);

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
