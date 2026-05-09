// SPDX-License-Identifier: AGPL-3.0-or-later

import type { SerializedTimeRange } from '@/lib/api';
import type { TimeRangeValue } from '@/hooks/use-api';

export const DEFAULT_DASHBOARD_TIME_RANGE: TimeRangeValue = {
  type: 'preset',
  preset: 'Last 24 hours',
};

export function hydrateDashboardTimeRange(
  saved: SerializedTimeRange | undefined,
): TimeRangeValue {
  if (!saved) return DEFAULT_DASHBOARD_TIME_RANGE;
  if (saved.type === 'custom') {
    const start = new Date(saved.start);
    const end = new Date(saved.end);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return DEFAULT_DASHBOARD_TIME_RANGE;
    }
    return { type: 'custom', start, end };
  }
  return { type: 'preset', preset: saved.preset };
}

export function serializeDashboardTimeRange(
  range: TimeRangeValue,
): SerializedTimeRange | undefined {
  if (range.type === 'custom' && range.start && range.end) {
    return {
      type: 'custom',
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    };
  }
  if (range.type === 'preset' && range.preset) {
    return { type: 'preset', preset: range.preset };
  }
  return undefined;
}
