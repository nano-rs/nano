// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hook for managing recently viewed dashboards in localStorage
 * Stores up to 10 most recently viewed dashboard IDs
 */

import { useState, useEffect, useCallback } from 'react';

const STORAGE_KEY = 'nanosiem_recently_viewed_dashboards';
const MAX_RECENT_DASHBOARDS = 10;
// DSH48: same-tab change signal. `storage` events only fire in OTHER tabs, so a
// custom event keeps co-mounted hook instances (e.g. the Dashboards list and a
// mounted DashboardView) in sync when one of them writes.
const CHANGE_EVENT = 'nanosiem:recent-dashboards-changed';

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
  // DSH48: notify other hook instances in this tab to re-read. Deferred to a
  // microtask because this runs inside a `setRecentDashboards` updater — a
  // synchronous dispatch would setState on a sibling instance mid-render.
  try {
    queueMicrotask(() => window.dispatchEvent(new CustomEvent(CHANGE_EVENT)));
  } catch {
    // Ignore (non-browser env / no microtask support)
  }
}

/**
 * Hook for managing recently viewed dashboards
 */
export function useRecentlyViewedDashboards() {
  const [recentDashboards, setRecentDashboards] = useState<RecentDashboard[]>([]);

  // Load from localStorage on mount, then keep this instance reconciled with
  // writes from sibling instances (same tab via CHANGE_EVENT) and other tabs
  // (native `storage` event) — DSH48.
  useEffect(() => {
    const resync = () => setRecentDashboards(getStoredDashboards());
    resync();
    window.addEventListener(CHANGE_EVENT, resync);
    window.addEventListener('storage', resync);
    return () => {
      window.removeEventListener(CHANGE_EVENT, resync);
      window.removeEventListener('storage', resync);
    };
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
