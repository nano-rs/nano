// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Play,
  RefreshCw,
  ArrowUpToLine,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { QueryEditor } from '@/components/editor';
import { useSearch, toApiTimeRange } from '@/hooks/use-api';
import { DetectionTestResults } from './DetectionTestResults';
import { toast } from 'sonner';
import type { TesterState } from './tester-state';

interface RuleTesterInlineProps {
  ruleQuery: string;
  alertMode: 'grouped' | 'per_event';
  lookbackMinutes?: number | null;
  state: TesterState;
  onApplyQuery: (query: string) => void;
}

export function RuleTesterInline({
  ruleQuery,
  alertMode,
  lookbackMinutes,
  state,
  onApplyQuery,
}: RuleTesterInlineProps) {
  const { mutate: search, loading: isSearching } = useSearch();

  const queryDiverged = state.panelQuery !== ruleQuery;

  const handleRunTest = useCallback(async () => {
    const trimmed = state.panelQuery.trim();
    if (!trimmed) {
      toast.error('Query is empty');
      return;
    }

    state.setSearchError(null);
    state.setHasSearched(true);

    const apiTimeRange = toApiTimeRange(state.timeRange);

    try {
      const result = await search({
        query: trimmed,
        time_range: apiTimeRange,
        limit: 500,
        table_view: true,
        priority: 'interactive',
        skip_field_stats: true,
      });

      state.setSearchResponse(result);
    } catch (err: unknown) {
      const msg = (err as Error).message || 'Search failed';
      state.setSearchError(msg);
      state.setSearchResponse(null);
    }
  }, [state.panelQuery, state.timeRange, search]);

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Query editor row */}
      <div className="flex-shrink-0 border-b border-border/50 bg-muted/20">
        <div className="overflow-auto px-3 pt-3 pb-2">
          <QueryEditor
            value={state.panelQuery}
            onChange={state.setPanelQuery}
            placeholder="Enter nPL query..."
            minHeight={48}
            maxHeight={120}
            onSubmit={handleRunTest}
          />
        </div>

        {/* Controls row */}
        <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
          <DateTimeRangePicker
            value={state.timeRange}
            onChange={state.setTimeRange}
            className="h-7 text-xs rounded-lg border"
            align="start"
            defaultMode="presets"
            maxRangeDays={14}
          />

          <Button
            size="sm"
            className="h-7 text-xs bg-primary hover:bg-primary/90"
            onClick={handleRunTest}
            disabled={isSearching || !state.panelQuery.trim()}
          >
            {isSearching
              ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
              : <Play className="w-3.5 h-3.5 mr-1" />
            }
            Run
          </Button>

          <Badge variant="outline" className="text-[10px] border-border/50 text-muted-foreground">
            {alertMode === 'grouped' ? 'Grouped' : 'Per Event'}
          </Badge>

          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs text-muted-foreground hover:text-foreground"
              onClick={() => {
                state.setPanelQuery(ruleQuery);
                toast.success('Query synced from rule');
              }}
              title="Sync query from rule editor"
            >
              <RefreshCw className="w-3.5 h-3.5 mr-1" />
              Sync
            </Button>

            {queryDiverged && (
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs text-primary hover:text-primary/80"
                onClick={() => {
                  onApplyQuery(state.panelQuery);
                  toast.success('Query applied to rule');
                }}
                title="Apply this query back to the rule editor"
              >
                <ArrowUpToLine className="w-3.5 h-3.5 mr-1" />
                Apply
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Error display */}
      {state.searchError && (
        <div className="px-3 py-2 bg-red-500/10 border-b border-red-500/20 flex-shrink-0">
          <p className="text-xs text-red-400 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            {state.searchError}
          </p>
        </div>
      )}

      {/* Results */}
      <DetectionTestResults
        response={state.searchResponse}
        isSearching={isSearching}
        hasSearched={state.hasSearched}
        alertMode={alertMode}
        lookbackMinutes={lookbackMinutes}
      />
    </div>
  );
}

export default RuleTesterInline;
