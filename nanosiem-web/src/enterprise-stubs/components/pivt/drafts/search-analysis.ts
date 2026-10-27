// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for pivt's search analysis (NAN-4589). Open builds have no
// pivt panel and no meloD, and Search hides the Analyze button without meloD,
// so registration and starts are inert.

import type { TimeRange } from '@/lib/api/types';
import type { TimeRangeValue } from '@/lib/time-range';

export interface SearchAnalysisContext {
  query: string;
  queryMode: string;
  dataset?: string;
  timeRange: TimeRangeValue;
  range: TimeRange;
  results: Record<string, unknown>[];
  totalCount: number;
  histogram?: Array<{ time: string; count: number }>;
}

export type SearchAnalysisSource = () => SearchAnalysisContext | { unavailable: string };

export const MAX_ANALYZE_ROWS = 2_000;

export const NO_SEARCH_TO_ANALYZE =
  'There are no search results to analyze. Run a search, then click Analyze or send @summarize.';

export function registerSearchAnalysisSource(get: SearchAnalysisSource): () => void {
  void get;
  return () => {};
}

export async function startSearchAnalysis(focus: string): Promise<void> {
  void focus;
}
