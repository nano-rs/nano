// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hook for managing recently viewed dashboards in localStorage
 * Stores up to 10 most recently viewed dashboard IDs
 */

import { useState, useEffect, useCallback } from 'react';

const STORAGE_KEY = 'nanosiem_recently_viewed_dashboards';
const MAX_RECENT_DASHBOARDS = 10;

export interface RecentDashboard {
  id: string;
  viewedAt: string; // ISO timestamp
}

/**
 * Get recently viewed dashboards from localStorage
 */
function getStoredDashboards(): RecentDashboard[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    // Validate structure
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is RecentDashboard =>
        typeof item === 'object' &&
        item !== null &&
        typeof item.id === 'string' &&
        typeof item.viewedAt === 'string'
    );
  } catch {
    return [];
  }
}

/**
 * Save recently viewed dashboards to localStorage
 */
function saveStoredDashboards(dashboards: RecentDashboard[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(dashboards));
  } catch {
    // Ignore storage errors (e.g., quota exceeded)
  }
}

/**
 * Hook for managing recently viewed dashboards
 */
export function useRecentlyViewedDashboards() {
  const [recentDashboards, setRecentDashboards] = useState<RecentDashboard[]>([]);

  // Load from localStorage on mount
  useEffect(() => {
    setRecentDashboards(getStoredDashboards());
  }, []);

  /**
   * Add a dashboard to the recently viewed list
   * Moves it to the front if already present, limits to MAX_RECENT_DASHBOARDS
   */
  const addRecentDashboard = useCallback((dashboardId: string) => {
    setRecentDashboards(prev => {
      // Remove existing entry for this dashboard (if any)
      const filtered = prev.filter(d => d.id !== dashboardId);
      
      // Add to front with current timestamp
      const updated: RecentDashboard[] = [
        { id: dashboardId, viewedAt: new Date().toISOString() },
        ...filtered,
      ].slice(0, MAX_RECENT_DASHBOARDS);
      
      // Persist to localStorage
      saveStoredDashboards(updated);
      
      return updated;
    });
  }, []);

  /**
   * Remove a dashboard from the recently viewed list
   * Useful when a dashboard is deleted
   */
  const removeRecentDashboard = useCallback((dashboardId: string) => {
    setRecentDashboards(prev => {
      const updated = prev.filter(d => d.id !== dashboardId);
      saveStoredDashboards(updated);
      return updated;
    });
  }, []);

  /**
   * Clear all recently viewed dashboards
   */
  const clearRecentDashboards = useCallback(() => {
    setRecentDashboards([]);
    saveStoredDashboards([]);
  }, []);

  /**
   * Get the IDs of recently viewed dashboards
   */
  const recentDashboardIds = recentDashboards.map(d => d.id);

  return {
    recentDashboards,
    recentDashboardIds,
    addRecentDashboard,
    removeRecentDashboard,
    clearRecentDashboards,
  };
}
