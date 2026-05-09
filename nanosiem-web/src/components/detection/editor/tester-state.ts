// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useRef, useEffect } from 'react';
import type { TimeRangeValue } from '@/hooks/use-api';
import type { SearchResponse } from '@/lib/api/types';

export interface TesterState {
  panelQuery: string;
  setPanelQuery: (q: string | ((prev: string) => string)) => void;
  timeRange: TimeRangeValue;
  setTimeRange: (tr: TimeRangeValue) => void;
  searchResponse: SearchResponse | null;
  setSearchResponse: (r: SearchResponse | null) => void;
  hasSearched: boolean;
  setHasSearched: (v: boolean) => void;
  searchError: string | null;
  setSearchError: (e: string | null) => void;
}

export function useTesterState(ruleQuery: string): TesterState {
  const [panelQuery, setPanelQuery] = useState(ruleQuery);
  const prevRuleQueryRef = useRef(ruleQuery);

  // Sync panelQuery when ruleQuery changes (rule loaded/switched)
  // Only sync if user hasn't manually diverged from the previous rule query
  useEffect(() => {
    const prev = prevRuleQueryRef.current;
    prevRuleQueryRef.current = ruleQuery;
    setPanelQuery(current => current === prev ? ruleQuery : current);
  }, [ruleQuery]);
  const [timeRange, setTimeRange] = useState<TimeRangeValue>({
    type: 'preset',
    preset: 'Last 24 hours',
  });
  const [searchResponse, setSearchResponse] = useState<SearchResponse | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  return {
    panelQuery,
    setPanelQuery,
    timeRange,
    setTimeRange,
    searchResponse,
    setSearchResponse,
    hasSearched,
    setHasSearched,
    searchError,
    setSearchError,
  };
}
