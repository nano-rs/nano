// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub. AnalyzeView is the meloD-backed AI summary panel
// shown alongside search results. Renders nothing in open builds; the
// SearchResults re-export is dropped in Task #15.

import type { TimeRangeValue } from '@/hooks/use-api';

interface AnalyzeViewProps {
  query: string;
  queryMode: string;
  results: Array<{ fields: Record<string, unknown> }>;
  totalCount: number;
  timeRange: TimeRangeValue;
  histogram?: Array<{ time: string; count: number }>;
  /** Called when the back button is clicked — swap the view back to results. */
  onBack: () => void;
  /** Called when a suggested-query card's Run button is clicked. Replaces
      the current query and re-runs the search in place. */
  onRunQuery?: (query: string) => void;
}

export function AnalyzeView(_props: AnalyzeViewProps) {
  return null;
}
export default AnalyzeView;
