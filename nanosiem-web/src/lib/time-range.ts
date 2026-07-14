// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Time ranges: the canonical preset list and how a range resolves to concrete
 * {start, end} timestamps.
 *
 * Lifted out of hooks/use-api.ts (which pulls in the API client and React) so
 * the desktop app can share the resolution logic without dragging a `fetch`-based
 * client into a webview that isn't allowed to make network calls. Both apps must
 * agree on what "Last 24 hours" or "Previous week" means.
 */

import type { TimeRange } from '@/lib/api/types';

/**
 * Preset labels are load-bearing: saved searches persist them as strings, and
 * toApiTimeRange switches on them. Add, don't rename.
 */
export const TIME_RANGE_PRESETS = [
  {
    label: 'Relative',
    presets: [
      { label: 'Last 5 minutes', short: '5m', value: 'Last 5 minutes' },
      { label: 'Last 15 minutes', short: '15m', value: 'Last 15 minutes' },
      { label: 'Last 30 minutes', short: '30m', value: 'Last 30 minutes' },
      { label: 'Last hour', short: '1h', value: 'Last hour' },
      { label: 'Last 4 hours', short: '4h', value: 'Last 4 hours' },
      { label: 'Last 12 hours', short: '12h', value: 'Last 12 hours' },
      { label: 'Last 24 hours', short: '24h', value: 'Last 24 hours' },
      { label: 'Last 7 days', short: '7d', value: 'Last 7 days' },
      { label: 'Last 30 days', short: '30d', value: 'Last 30 days' },
      { label: 'Last 90 days', short: '90d', value: 'Last 90 days' },
    ],
  },
  {
    label: 'Absolute',
    presets: [
      { label: 'Today', short: 'Today', value: 'Today' },
      { label: 'Yesterday', short: 'Yesterday', value: 'Yesterday' },
      { label: 'This week', short: 'This week', value: 'This week' },
      { label: 'Previous week', short: 'Prev week', value: 'Previous week' },
      { label: 'All time', short: 'All time', value: 'All time' },
    ],
  },
] as const;

export interface TimeRangeValue {
  type: 'preset' | 'custom';
  preset?: string;
  start?: Date;
  end?: Date;
  refreshedAt?: number; // Timestamp to force refresh when re-selecting same preset
}

// Utility to convert frontend types to API types
export function toApiTimeRange(range: string | TimeRangeValue): TimeRange {
  // Handle new TimeRangeValue format
  if (typeof range === 'object') {
    if (range.type === 'custom' && range.start && range.end) {
      return {
        start: range.start.toISOString(),
        end: range.end.toISOString(),
      };
    }
    // Fall through to preset handling
    range = range.preset || 'Last 24 hours';
  }

  const now = new Date();
  let start: Date;

  switch (range) {
    case 'Last 5 minutes':
      start = new Date(now.getTime() - 5 * 60 * 1000);
      break;
    case 'Last 15 minutes':
      start = new Date(now.getTime() - 15 * 60 * 1000);
      break;
    case 'Last 30 minutes':
      start = new Date(now.getTime() - 30 * 60 * 1000);
      break;
    case 'Last hour':
      start = new Date(now.getTime() - 60 * 60 * 1000);
      break;
    case 'Last 4 hours':
      start = new Date(now.getTime() - 4 * 60 * 60 * 1000);
      break;
    case 'Last 12 hours':
      start = new Date(now.getTime() - 12 * 60 * 60 * 1000);
      break;
    case 'Last 24 hours':
      start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case 'Today': {
      const today = new Date(now);
      today.setHours(0, 0, 0, 0);
      start = today;
      break;
    }
    case 'Yesterday': {
      const yesterday = new Date(now);
      yesterday.setDate(yesterday.getDate() - 1);
      yesterday.setHours(0, 0, 0, 0);
      const yesterdayEnd = new Date(yesterday);
      yesterdayEnd.setHours(23, 59, 59, 999);
      return {
        start: yesterday.toISOString(),
        end: yesterdayEnd.toISOString(),
      };
    }
    case 'Last 7 days':
      start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case 'Last 30 days':
      start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case 'Last 90 days':
      start = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      break;
    case 'This week': {
      const thisWeekStart = new Date(now);
      const dayOfWeek = thisWeekStart.getDay();
      const diff = dayOfWeek === 0 ? 6 : dayOfWeek - 1; // Monday as start of week
      thisWeekStart.setDate(thisWeekStart.getDate() - diff);
      thisWeekStart.setHours(0, 0, 0, 0);
      start = thisWeekStart;
      break;
    }
    case 'Previous week': {
      const prevWeekEnd = new Date(now);
      const dayOfWeek = prevWeekEnd.getDay();
      const diff = dayOfWeek === 0 ? 6 : dayOfWeek - 1;
      prevWeekEnd.setDate(prevWeekEnd.getDate() - diff - 1);
      prevWeekEnd.setHours(23, 59, 59, 999);
      const prevWeekStart = new Date(prevWeekEnd);
      prevWeekStart.setDate(prevWeekStart.getDate() - 6);
      prevWeekStart.setHours(0, 0, 0, 0);
      return {
        start: prevWeekStart.toISOString(),
        end: prevWeekEnd.toISOString(),
      };
    }
    case 'All time':
      // Use a very old date for "all time"
      start = new Date('2020-01-01T00:00:00.000Z');
      break;
    default:
      start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }

  return {
    start: start.toISOString(),
    end: now.toISOString(),
  };
}
