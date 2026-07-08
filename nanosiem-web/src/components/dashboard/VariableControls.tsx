// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VariableControls Component
 *
 * Renders input controls for dashboard variables in the dashboard toolbar.
 * Supports dropdown (static options), text input, and query-based (dynamic) variables.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
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
import { substituteVariables } from './variable-substitution';

export interface VariableControlsProps {
  variables: DashboardVariable[];
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
  timeRange: TimeRange;
  /**
   * NAN-711 (DSH54): query-backed option fetches must not fire before the user
   * has run the dashboard at least once. Defaults to true so other callers keep
   * eager behaviour.
   */
  hasRunOnce?: boolean;
}

// DSH22: Radix Select can't represent "no selection", so an explicit sentinel
// option maps back to the empty value (which the substitution module treats as
// "unfiltered"). Radix also forbids an empty-string item value, hence a token.
const ANY_OPTION = '__any__';

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
  hasRunOnce = true,
}: VariableControlsProps) {
  const [queryCache, setQueryCache] = useState<QueryOptionsCache>({});
  // Local state for text inputs - only apply on Enter or button click
  const [textValues, setTextValues] = useState<Record<string, string>>({});
  // Track if any text value has pending changes
  const [hasPendingChanges, setHasPendingChanges] = useState(false);
  // DSH55: names of text variables with un-applied edits, so an external
  // `values` change (dropdown pick) doesn't wipe pending typing.
  const pendingKeys = useRef<Set<string>>(new Set());
  // DSH54: per-variable request sequence so a stale (slower / older time-range /
  // older sibling-value) option response can't overwrite a newer one.
  const fetchSeq = useRef<Record<string, number>>({});

  // Sync textValues with external values, PRESERVING keys the user is mid-edit
  // on (DSH55).
  useEffect(() => {
    setTextValues(prev => {
      const next: Record<string, string> = { ...values };
      for (const key of pendingKeys.current) {
        if (key in prev) next[key] = prev[key];
      }
      return next;
    });
    setHasPendingChanges(pendingKeys.current.size > 0);
  }, [values]);

  // Fetch options for query-type variables
  const fetchQueryOptions = useCallback(async (variable: DashboardVariable) => {
    if (!variable.query || !variable.queryField) return;
    const queryField = variable.queryField;

    const seq = (fetchSeq.current[variable.name] ?? 0) + 1;
    fetchSeq.current[variable.name] = seq;
    const isStale = () => fetchSeq.current[variable.name] !== seq;

    setQueryCache(prev => ({
      ...prev,
      [variable.name]: { options: prev[variable.name]?.options ?? [], loading: true },
    }));

    try {
      // DSH54: pass sibling variable values into the option query via the shared
      // substitution so CHAINED variables (e.g. `source=$src | stats count by
      // host`) filter by the current selections instead of the literal `$src`.
      const definedNames = variables.map(v => v.name);
      const optionQuery = substituteVariables(variable.query, values, definedNames);

      const response = await api.panelQuery({
        query: optionQuery,
        query_mode: 'piped',
        time_range: timeRange,
      });
      if (isStale()) return; // a newer fetch superseded this one (DSH54)

      // Extract unique values from the specified field
      const options = new Set<string>();
      for (const row of response.results) {
        const value = row[queryField];
        if (value !== undefined && value !== null) {
          options.add(String(value));
        }
      }

      // NAN-710: if 0 options came back from a non-empty result set AND the
      // requested field is actually missing from the response shape, surface a
      // diagnostic. Most likely cause: the display label was used as
      // `queryField` instead of the snake_case column name. ClickHouse returns
      // identically-shaped rows so the first row's keys are authoritative.
      if (options.size === 0 && response.results.length > 0) {
        const availableFields = Object.keys(response.results[0] ?? {}).sort();
        if (!availableFields.includes(queryField)) {
          if (isStale()) return;
          setQueryCache(prev => ({
            ...prev,
            [variable.name]: {
              options: [],
              loading: false,
              error: `field "${queryField}" not found — available: ${availableFields.join(', ')}`,
            },
          }));
          return;
        }
        // Field is present but every value was null/undefined — genuinely empty.
      }

      if (isStale()) return;
      setQueryCache(prev => ({
        ...prev,
        [variable.name]: {
          options: Array.from(options).sort(),
          loading: false,
        },
      }));
    } catch (err) {
      if (isStale()) return;
      setQueryCache(prev => ({
        ...prev,
        [variable.name]: {
          options: [],
          loading: false,
          error: err instanceof Error ? err.message : 'Failed to load options',
        },
      }));
    }
  }, [timeRange, variables, values]);

  // Fetch query options once the dashboard has run (NAN-711 gate, DSH54) and
  // whenever the time range or sibling variable values change.
  useEffect(() => {
    if (!hasRunOnce) return;
    for (const variable of variables) {
      if (variable.type === 'query') {
        fetchQueryOptions(variable);
      }
    }
  }, [variables, timeRange, fetchQueryOptions, hasRunOnce]);

  // Handler for dropdown/query changes - applies immediately
  const handleChange = (name: string, value: string) => {
    onChange({ ...values, [name]: value });
  };

  // Handler for text input changes - only updates local state
  const handleTextChange = useCallback((name: string, value: string) => {
    pendingKeys.current.add(name);
    setTextValues(prev => ({ ...prev, [name]: value }));
    setHasPendingChanges(true);
  }, []);

  // Apply text input changes - triggered by button or Enter key
  const applyTextChanges = useCallback(() => {
    // Merge text values with existing dropdown/query values
    onChange({ ...values, ...textValues });
    pendingKeys.current.clear();
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
              value={(values[variable.name] ?? variable.defaultValue ?? '') === '' ? ANY_OPTION : (values[variable.name] ?? variable.defaultValue ?? '')}
              onValueChange={value => handleChange(variable.name, value === ANY_OPTION ? '' : value)}
            >
              <SelectTrigger className="h-[26px] w-[150px] text-[12px]">
                <SelectValue placeholder={`— any —`} />
              </SelectTrigger>
              <SelectContent>
                {/* DSH22: explicit clear-to-"any" so a narrowed variable can be
                    widened back to the fleet view without a full reload. */}
                <SelectItem value={ANY_OPTION} className="text-[12px] text-muted-foreground">
                  — any —
                </SelectItem>
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
                // NAN-775: surface the full diagnostic inline next to the pill
                // (the message is also kept on `title=` for hover when the
                // text truncates). Most common cause: the variable's
                // `queryField` doesn't match the column name returned by the
                // query — typically because the variable was authored with
                // the display label instead of the snake_case column.
                <div className="inline-flex items-center gap-1.5 max-w-[420px]">
                  <span className="font-mono text-[10.5px] text-rose-400 border border-rose-500/30 rounded px-1.5 py-0.5 shrink-0">
                    load error
                  </span>
                  <span
                    className="font-mono text-[10.5px] text-rose-300/80 truncate"
                    title={queryCache[variable.name]?.error}
                  >
                    {queryCache[variable.name]?.error}
                  </span>
                </div>
              ) : (
                <Select
                  value={(values[variable.name] ?? variable.defaultValue ?? '') === '' ? ANY_OPTION : (values[variable.name] ?? variable.defaultValue ?? '')}
                  onValueChange={value => handleChange(variable.name, value === ANY_OPTION ? '' : value)}
                >
                  <SelectTrigger className="h-[26px] w-[150px] text-[12px]">
                    <SelectValue placeholder={`— any —`} />
                  </SelectTrigger>
                  <SelectContent className="max-h-[300px]">
                    {/* DSH22: explicit clear-to-"any" (see dropdown variant). */}
                    <SelectItem value={ANY_OPTION} className="text-[12px] text-muted-foreground">
                      — any —
                    </SelectItem>
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
