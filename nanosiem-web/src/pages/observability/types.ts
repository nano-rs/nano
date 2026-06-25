// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared prop contract for the Observability console tabs (NAN-1536).
 *
 * The shell (`ObservabilityConsole`) owns the time range + drill-in navigation
 * and passes them down. Surface agents fill the tab bodies against this
 * contract — the shell wiring is fixed.
 */

import type { TimeRangeValue } from '@/hooks/use-api';
import type { TimeRange } from '@/lib/api/types';

/** The set of console tabs shipped this pass. */
export type ObservabilityTab =
  | 'services'
  | 'traces'
  | 'metrics'
  | 'infrastructure'
  | 'rum'
  | 'synthetics'
  | 'alerts'
  | 'slos';

/** Props every tab body receives from the shell. */
export interface ObservabilityTabProps {
  /** Active time range, as the picker value (preset or absolute). */
  timeRange: TimeRangeValue;
  /** The same range resolved to absolute {start,end} RFC3339 for API calls. */
  apiTimeRange: TimeRange;
  /** Drill into a single service's detail view. */
  onOpenService: (service: string) => void;
  /** Drill into a single trace's waterfall. */
  onOpenTrace: (traceId: string) => void;
}
