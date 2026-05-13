// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Recent Activity Hook
 *
 * Fetches and records user's recently viewed items for the "Continue Working" feature.
 * Aggregates data from multiple sources:
 * - Recent detections, alerts, cases, dashboards (from API)
 * - Recent searches (from search history API)
 * - Active notebooks (from notebook tabs API)
 */

import { useState, useEffect, useCallback } from 'react';
import { api, RecentActivityItem, RecentItemType, NotebookTabWithDetails } from '@/lib/api';
import { getAccessToken } from '@/lib/auth-token';

export interface UnifiedRecentItem {
  type: 'search' | 'notebook' | RecentItemType;
  id: string;
  title: string;
  subtitle?: string;
  metadata: Record<string, unknown>;
  accessedAt: Date;
  url: string;
}

interface SearchHistoryEntry {
  id: string;
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string | null;
  time_range_start?: string | null;
  time_range_end?: string | null;
  created_at: string;
}

interface UseRecentActivityOptions {
  limit?: number;
  includeSearches?: boolean;
  includeNotebooks?: boolean;
}

interface UseRecentActivityResult {
  items: UnifiedRecentItem[];
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
}

// Fetch search history directly (API client method)
async function fetchSearchHistory(limit: number): Promise<SearchHistoryEntry[]> {
  try {
    const response = await fetch(`${import.meta.env.VITE_API_URL ?? ''}/api/search/history?limit=${limit}`, {
      headers: getAuthHeaders(),
    });
    if (response.ok) {
      const data = await response.json();
      return data.entries || [];
    }
  } catch {
    // Ignore errors
  }
  return [];
}

function getAuthHeaders(): HeadersInit {
  const token = getAccessToken();
  if (token) {
    return {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }
  return { 'Content-Type': 'application/json' };
}

/**
 * Hook to fetch recent activity from all sources
 */
export function useRecentActivity(options: UseRecentActivityOptions = {}): UseRecentActivityResult {
  const { limit = 10, includeSearches = true, includeNotebooks = true } = options;

  const [items, setItems] = useState<UnifiedRecentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchActivity = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      // Fetch from all sources in parallel
      const [recentActivity, searchHistory, notebookTabs] = await Promise.all([
        api.getRecentActivity({ limit: limit * 2 }).catch(() => ({ items: [] })),
        includeSearches
          ? fetchSearchHistory(5)
          : Promise.resolve([]),
        includeNotebooks
          ? api.listTabs().catch(() => [])
          : Promise.resolve([]),
      ]);

      const unified: UnifiedRecentItem[] = [];

      // Add recent activity items (detections, alerts, cases, dashboards)
      for (const item of recentActivity.items) {
        unified.push({
          type: item.item_type,
          id: item.item_id,
          title: item.title,
          subtitle: getSubtitle(item),
          metadata: item.metadata,
          accessedAt: new Date(item.accessed_at),
          url: getItemUrl(item),
        });
      }

      // Add search history
      for (const entry of searchHistory) {
        unified.push({
          type: 'search',
          id: entry.id,
          title: truncateQuery(entry.query),
          subtitle: formatTimeRangePreset(entry.time_range_preset),
          metadata: {
            query: entry.query,
            queryMode: entry.query_mode,
            timeRangeType: entry.time_range_type,
            timeRangePreset: entry.time_range_preset,
          },
          accessedAt: new Date(entry.created_at),
          url: buildSearchUrl(entry),
        });
      }

      // Add notebook tabs (most recent first)
      const tabs: NotebookTabWithDetails[] = notebookTabs;
      const sortedTabs = [...tabs].sort(
        (a, b) => new Date(b.last_accessed_at).getTime() - new Date(a.last_accessed_at).getTime()
      );
      for (const tab of sortedTabs.slice(0, 3)) {
        unified.push({
          type: 'notebook',
          id: tab.notebook_id,
          title: tab.notebook_title || 'Untitled Notebook',
          subtitle: tab.is_pinned ? 'Pinned' : undefined,
          metadata: { isPinned: tab.is_pinned, isActive: tab.is_active },
          accessedAt: new Date(tab.last_accessed_at),
          url: `/notebooks?id=${tab.notebook_id}`,
        });
      }

      // Sort all items by access time (most recent first) and limit
      unified.sort((a, b) => b.accessedAt.getTime() - a.accessedAt.getTime());
      setItems(unified.slice(0, limit));
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch recent activity'));
    } finally {
      setIsLoading(false);
    }
  }, [limit, includeSearches, includeNotebooks]);

  useEffect(() => {
    fetchActivity();
  }, [fetchActivity]);

  return { items, isLoading, error, refresh: fetchActivity };
}

/**
 * Hook to record activity when viewing an item
 */
export function useRecordActivity() {
  const recordView = useCallback(
    async (
      itemType: RecentItemType,
      itemId: string,
      itemTitle?: string,
      itemMetadata?: Record<string, unknown>
    ) => {
      try {
        await api.recordActivity({
          item_type: itemType,
          item_id: itemId,
          item_title: itemTitle,
          item_metadata: itemMetadata,
        });
      } catch (err) {
        // Activity tracking shouldn't break the app, but errors must be visible —
        // a silent warn is how the typeid mismatch (NAN-776) hid for so long.
        console.error(`recordActivity failed for ${itemType} ${itemId}:`, err);
      }
    },
    []
  );

  return { recordView };
}

// Helper functions

function getSubtitle(item: RecentActivityItem): string | undefined {
  const meta = item.metadata;
  switch (item.item_type) {
    case 'detection':
      return meta.severity ? `${meta.severity} severity` : undefined;
    case 'alert':
      return meta.rule_name ? String(meta.rule_name) : undefined;
    case 'case':
      return meta.case_number ? `CASE-${meta.case_number}` : undefined;
    case 'dashboard':
      return meta.panel_count ? `${meta.panel_count} panels` : undefined;
    default:
      return undefined;
  }
}

function getItemUrl(item: RecentActivityItem): string {
  switch (item.item_type) {
    case 'detection':
      return `/rules/${item.item_id}`;
    case 'alert':
      return `/alerts?selected=${item.item_id}`;
    case 'case':
      return `/cases/${item.item_id}`;
    case 'dashboard':
      return `/dashboards/${item.item_id}`;
    default:
      return '/';
  }
}

function truncateQuery(query: string, maxLength = 50): string {
  if (query.length <= maxLength) return query;
  return query.slice(0, maxLength - 3) + '...';
}

function formatTimeRangePreset(preset?: string | null): string {
  if (!preset) return 'Custom range';
  const labels: Record<string, string> = {
    last_15_minutes: 'Last 15m',
    last_hour: 'Last 1h',
    last_4_hours: 'Last 4h',
    last_24_hours: 'Last 24h',
    last_7_days: 'Last 7d',
    last_30_days: 'Last 30d',
  };
  return labels[preset] || preset;
}

function buildSearchUrl(entry: {
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string | null;
  time_range_start?: string | null;
  time_range_end?: string | null;
}): string {
  const params = new URLSearchParams();
  params.set('q', entry.query);
  if (entry.query_mode === 'sql') params.set('mode', 'sql');
  if (entry.time_range_preset) params.set('range', entry.time_range_preset);
  return `/search?${params.toString()}`;
}
