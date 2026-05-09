// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VariableControls Component
 *
 * Renders input controls for dashboard variables in the dashboard toolbar.
 * Supports dropdown (static options), text input, and query-based (dynamic) variables.
 */

import { useState, useEffect, useCallback } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Search } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2 } from 'lucide-react';
import { api, type DashboardVariable, type TimeRange } from '@/lib/api';

export interface VariableControlsProps {
  variables: DashboardVariable[];
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
  timeRange: TimeRange;
}

interface QueryOptionsCache {
  [variableName: string]: {
    options: string[];
    loading: boolean;
    error?: string;
  };
}

export function VariableControls({
  variables,
  values,
  onChange,
  timeRange,
}: VariableControlsProps) {
  const [queryCache, setQueryCache] = useState<QueryOptionsCache>({});
  // Local state for text inputs - only apply on Enter or button click
  const [textValues, setTextValues] = useState<Record<string, string>>({});
  // Track if any text value has pending changes
  const [hasPendingChanges, setHasPendingChanges] = useState(false);

  // Sync textValues with external values on mount and when values change
  useEffect(() => {
    setTextValues(values);
    setHasPendingChanges(false);
  }, [values]);

  // Fetch options for query-type variables
  const fetchQueryOptions = useCallback(async (variable: DashboardVariable) => {
    if (!variable.query || !variable.queryField) return;

    setQueryCache(prev => ({
      ...prev,
      [variable.name]: { options: [], loading: true },
    }));

    try {
      const response = await api.panelQuery({
        query: variable.query,
        query_mode: 'piped',
        time_range: timeRange,
      });

      // Extract unique values from the specified field
      const options = new Set<string>();
      for (const row of response.results) {
        const value = row[variable.queryField];
        if (value !== undefined && value !== null) {
          options.add(String(value));
        }
      }

      // NAN-710: if 0 options came back from a non-empty result set AND the
      // requested field is actually missing from the response shape, surface
      // a diagnostic. The most likely cause is the AI agent (or a hand-edited
      // dashboard) used the display label as `queryField` instead of the
      // actual snake_case column name. Distinguishing "field absent" from
      // "field present but all values null" prevents a misleading error on
      // the rare all-null case.
      //
      // ClickHouse returns identically-shaped rows so the first row's keys
      // are authoritative — no need to walk the whole response.
      if (options.size === 0 && response.results.length > 0) {
        const availableFields = Object.keys(response.results[0] ?? {}).sort();
        if (!availableFields.includes(variable.queryField)) {
          setQueryCache(prev => ({
            ...prev,
            [variable.name]: {
              options: [],
              loading: false,
              error: `field "${variable.queryField}" not found — available: ${availableFields.join(', ')}`,
            },
          }));
          return;
        }
        // Field is present but every value was null/undefined — fall through
        // to the regular empty-dropdown path. Genuinely empty data, not an
        // authoring error.
      }

      setQueryCache(prev => ({
        ...prev,
        [variable.name]: {
          options: Array.from(options).sort(),
          loading: false,
        },
      }));
    } catch (err) {
      setQueryCache(prev => ({
        ...prev,
        [variable.name]: {
          options: [],
          loading: false,
          error: err instanceof Error ? err.message : 'Failed to load options',
        },
      }));
    }
  }, [timeRange]);

  // Fetch query options on mount and when time range changes
  useEffect(() => {
    for (const variable of variables) {
      if (variable.type === 'query') {
        fetchQueryOptions(variable);
      }
    }
  }, [variables, timeRange, fetchQueryOptions]);

  // Handler for dropdown/query changes - applies immediately
  const handleChange = (name: string, value: string) => {
    onChange({ ...values, [name]: value });
  };

  // Handler for text input changes - only updates local state
  const handleTextChange = useCallback((name: string, value: string) => {
    setTextValues(prev => ({ ...prev, [name]: value }));
    setHasPendingChanges(true);
  }, []);

  // Apply text input changes - triggered by button or Enter key
  const applyTextChanges = useCallback(() => {
    // Merge text values with existing dropdown/query values
    onChange({ ...values, ...textValues });
    setHasPendingChanges(false);
  }, [onChange, values, textValues]);

  // Handle Enter key in text inputs
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      applyTextChanges();
    }
  }, [applyTextChanges]);

  // Check if there are any text type variables
  const hasTextVariables = variables.some(v => v.type === 'text');

  if (variables.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-3 flex-wrap">
      {variables.map(variable => (
        <div key={variable.name} className="flex items-center gap-1.5">
          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold whitespace-nowrap">
            {variable.label}
          </Label>

          {variable.type === 'text' && (
            <Input
              value={textValues[variable.name] || ''}
              onChange={e => handleTextChange(variable.name, e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={variable.defaultValue || '*'}
              className="h-[26px] w-[150px] text-[12px]"
            />
          )}

          {variable.type === 'dropdown' && (
            <Select
              value={values[variable.name] || variable.defaultValue || ''}
              onValueChange={value => handleChange(variable.name, value)}
            >
              <SelectTrigger className="h-[26px] w-[150px] text-[12px]">
                <SelectValue placeholder={`— any —`} />
              </SelectTrigger>
              <SelectContent>
                {variable.options?.map(option => (
                  <SelectItem key={option} value={option} className="text-[12px]">
                    {option}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}

          {variable.type === 'query' && (
            <>
              {queryCache[variable.name]?.loading ? (
                <div className="h-[26px] w-[150px] flex items-center justify-center bg-foreground/[0.03] border border-border rounded-md">
                  <Loader2 className="w-[12px] h-[12px] animate-spin text-muted-foreground" />
                </div>
              ) : queryCache[variable.name]?.error ? (
                // NAN-710: hover to see the full diagnostic (field name + which
                // columns are actually available). Most common cause: the
                // variable's `queryField` doesn't match the column name returned
                // by the query — typically because the variable was authored
                // with the display label instead of the snake_case column.
                <span
                  className="font-mono text-[10.5px] text-rose-400 border border-rose-500/30 rounded px-1.5 py-0.5 cursor-help"
                  title={queryCache[variable.name]?.error}
                >
                  load error
                </span>
              ) : (
                <Select
                  value={values[variable.name] || variable.defaultValue || ''}
                  onValueChange={value => handleChange(variable.name, value)}
                >
                  <SelectTrigger className="h-[26px] w-[150px] text-[12px]">
                    <SelectValue placeholder={`— any —`} />
                  </SelectTrigger>
                  <SelectContent className="max-h-[300px]">
                    {queryCache[variable.name]?.options.map(option => (
                      <SelectItem key={option} value={option} className="text-[12px]">
                        {option}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </>
          )}
        </div>
      ))}

      {hasTextVariables && (
        <Button
          size="sm"
          className="h-[26px]"
          onClick={applyTextChanges}
          disabled={!hasPendingChanges}
        >
          <Search className="w-[12px] h-[12px]" />
          Apply
        </Button>
      )}
    </div>
  );
}

export default VariableControls;
