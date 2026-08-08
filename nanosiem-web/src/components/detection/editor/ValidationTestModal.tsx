// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Calendar } from '@/components/ui/calendar';
import { Label } from '@/components/ui/label';
import { Loader2, Play, Search, Calendar as CalendarIcon, AlertTriangle, Zap, Clock, Database, CircleCheck, XCircle } from 'lucide-react';
import { format, subDays, differenceInDays } from 'date-fns';
import { DayFlag, SelectionState, UI, type DateRange } from 'react-day-picker';
import { useTestQuery } from '@/hooks/use-api';
import type { TestDetectionResult, ValidateDetectionResult } from '@/lib/api';
import { toast } from 'sonner';
import { formatUTCShort, parseUTCTimestamp } from '@/lib/date-utils';
import { api } from '@/lib/api';

interface ValidationTestModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  query: string;
  detectionMode?: string;
  onValidationResult?: (result: { valid: boolean; matchCount?: number; error?: string }) => void;
}

export function ValidationTestModal({
  open,
  onOpenChange,
  query,
  detectionMode,
  onValidationResult,
}: ValidationTestModalProps) {
  const { mutate: testQuery, loading: validating } = useTestQuery();
  const [dateRange, setDateRange] = useState<DateRange | undefined>({
    from: subDays(new Date(), 7),
    to: new Date(),
  });
  const [testResult, setTestResult] = useState<TestDetectionResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [validateResult, setValidateResult] = useState<ValidateDetectionResult | null>(null);
  const [validateLoading, setValidateLoading] = useState(false);

  // Fetch validation info when modal opens or query/mode changes
  useEffect(() => {
    if (open && query.trim()) {
      setValidateLoading(true);
      api.validateDetection(query, detectionMode)
        .then(result => {
          setValidateResult(result);
        })
        .catch(err => {
          console.error('Validation failed:', err);
          setValidateResult(null);
        })
        .finally(() => {
          setValidateLoading(false);
        });
    }
  }, [open, query, detectionMode]);

  const isRangeTooLarge = dateRange?.from && dateRange?.to && differenceInDays(dateRange.to, dateRange.from) > 7;

  const handleRunTest = async () => {
    if (!dateRange?.from || !dateRange?.to) return;

    const timeRange = {
      start: dateRange.from.toISOString(),
      end: dateRange.to.toISOString(),
    };

    try {
      setTestError(null);
      const result = await testQuery({ query, timeRange });
      setTestResult(result);
      if (onValidationResult) {
        onValidationResult({ valid: true, matchCount: result.total_matches });
      }
    } catch (err: unknown) {
      const errorMsg = (err as Error).message || 'Invalid query syntax';
      setTestError(errorMsg);
      if (onValidationResult) {
        onValidationResult({ valid: false, error: errorMsg });
      }
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Search className="w-5 h-5 text-primary" />
            Test Detection Query
          </DialogTitle>
          <DialogDescription className="sr-only">
            Test your detection query against historical data to see matching events
          </DialogDescription>
        </DialogHeader>

        <div className="flex gap-6 flex-1 overflow-hidden">
          <div className="space-y-4">
            <div>
              <Label className="text-muted-foreground text-xs uppercase tracking-wider mb-2 block">
                <CalendarIcon className="w-3 h-3 inline mr-1" />
                Date Range (max 7 days)
              </Label>
              <Calendar
                mode="range"
                selected={dateRange}
                onSelect={setDateRange}
                numberOfMonths={1}
                className="rounded-lg border border-border bg-muted/50"
                classNames={{
                  [SelectionState.selected]: 'bg-primary [&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:hover:bg-primary [&>button]:hover:text-primary [&>button]:focus:bg-primary [&>button]:focus:text-foreground',
                  [SelectionState.range_middle]: 'bg-primary/30 [&>button]:bg-primary/30 [&>button]:text-blue-100 [&>button]:hover:bg-primary/40',
                  [SelectionState.range_start]: 'rounded-l-md [&>button]:bg-primary [&>button]:text-primary-foreground',
                  [SelectionState.range_end]: 'rounded-r-md [&>button]:bg-primary [&>button]:text-primary-foreground',
                  [DayFlag.today]: '[&>button]:bg-accent [&>button]:text-foreground',
                  [UI.DayButton]: 'h-8 w-8 p-0 font-normal text-foreground hover:bg-accent hover:text-primary aria-selected:opacity-100',
                  [UI.Weekday]: 'text-muted-foreground rounded-md w-8 font-normal text-[0.8rem]',
                  [UI.CaptionLabel]: 'text-sm font-medium text-foreground',
                  [UI.PreviousMonthButton]: 'h-7 w-7 bg-transparent p-0 text-muted-foreground hover:text-primary hover:bg-accent rounded',
                  [UI.NextMonthButton]: 'h-7 w-7 bg-transparent p-0 text-muted-foreground hover:text-primary hover:bg-accent rounded',
                }}
              />
            </div>

            <div className="text-sm text-muted-foreground">
              {dateRange?.from && dateRange?.to ? (
                <p>{format(dateRange.from, 'MMM d, yyyy')} — {format(dateRange.to, 'MMM d, yyyy')}</p>
              ) : (
                <p>Select a date range</p>
              )}
              {isRangeTooLarge && (
                <p className="text-yellow-400 text-xs">Range exceeds 7 days - please narrow your selection</p>
              )}
            </div>

            <Button
              onClick={handleRunTest}
              disabled={validating || !dateRange?.from || !dateRange?.to || isRangeTooLarge}
              className="w-full bg-primary hover:bg-primary/90 disabled:opacity-50"
            >
              {validating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run Test
            </Button>
          </div>

          <div className="flex-1 overflow-hidden flex flex-col min-w-0">
            {/* Query Validation Info */}
            <div className="mb-4">
              <Label className="text-muted-foreground text-xs uppercase tracking-wider mb-2 block">Query Analysis</Label>
              {validateLoading ? (
                <div className="bg-muted/50 rounded-lg p-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Analyzing query...</span>
                </div>
              ) : validateResult ? (
                <div className="bg-muted/50 rounded-lg p-3 space-y-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    {/* Valid/Invalid */}
                    <div className="flex items-center gap-1.5">
                      {validateResult.valid ? (
                        <CircleCheck className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-500" />
                      )}
                      <span className={`text-sm font-medium ${validateResult.valid ? 'text-emerald-500' : 'text-red-500'}`}>
                        {validateResult.valid ? 'Valid Query' : 'Invalid Query'}
                      </span>
                    </div>

                    {/* Detection Mode */}
                    <Badge className={`${validateResult.effective_mode === 'real-time' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-purple-500/10 text-purple-400 border-purple-500/20'} rounded-lg inline-flex items-center gap-1`}>
                      {validateResult.effective_mode === 'real-time' ? <Zap className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                      {validateResult.effective_mode === 'real-time' ? 'Real-Time' : 'Scheduled'}
                    </Badge>

                    {/* MV Badge */}
                    {validateResult.creates_materialized_view && (
                      <Badge
                        className="bg-blue-500/10 text-blue-400 border-blue-500/20 rounded-lg inline-flex items-center gap-1 cursor-help"
                        title="Materialized View: A ClickHouse database object that continuously processes incoming data and stores matching results for instant alerting. MVs provide sub-second detection latency."
                      >
                        <Database className="w-3 h-3" />
                        Creates MV
                      </Badge>
                    )}
                  </div>

                  {/* Mode Reason */}
                  <p className="text-xs text-muted-foreground">{validateResult.mode_reason}</p>

                  {/* Warning */}
                  {validateResult.warning && (
                    <div className="bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1.5 mt-2">
                      <p className="text-xs text-amber-400 flex items-start gap-1.5">
                        <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                        {validateResult.warning}
                      </p>
                    </div>
                  )}

                  {/* Errors */}
                  {validateResult.errors && validateResult.errors.length > 0 && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded px-2 py-1.5 mt-2">
                      {validateResult.errors.map((err, i) => (
                        <p key={i} className="text-xs text-red-400">{err}</p>
                      ))}
                    </div>
                  )}

                  {/* Referenced Fields */}
                  {validateResult.referenced_fields && validateResult.referenced_fields.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap mt-1">
                      <span className="text-xs text-muted-foreground">Fields:</span>
                      {validateResult.referenced_fields.map((field, i) => (
                        <Badge key={i} variant="outline" className="text-[10px] px-1.5 py-0 h-5">{field}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            <Label className="text-muted-foreground text-xs uppercase tracking-wider mb-2">Test Results</Label>

            {testError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-4">
                <p className="text-red-400 text-sm flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  {testError}
                </p>
              </div>
            )}

            {testResult && (
              <div className="space-y-4 flex-1 overflow-auto">
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-muted/50 rounded-lg p-3">
                    <p className="text-2xl font-bold text-foreground">{testResult.total_matches}</p>
                    <p className="text-xs text-muted-foreground">Total Matches</p>
                  </div>
                  <div className="bg-muted/50 rounded-lg p-3">
                    <p className="text-2xl font-bold text-foreground">{testResult.sample_events.length}</p>
                    <p className="text-xs text-muted-foreground">Sample Events</p>
                  </div>
                  <div className="bg-muted/50 rounded-lg p-3">
                    <p className="text-2xl font-bold text-foreground">{testResult.execution_time_ms}ms</p>
                    <p className="text-xs text-muted-foreground">Execution Time</p>
                  </div>
                </div>

                {testResult.matches_by_day.length > 0 && (() => {
                  // Deduplicate and aggregate by date, limit to 7 most recent days
                  const aggregatedByDay = testResult.matches_by_day.reduce((acc, day) => {
                    const dateKey = (day.date || '').split('T')[0]; // Ensure just the date part
                    const count = typeof day.count === 'number' ? day.count : Number(day.count) || 0;
                    if (dateKey) {
                      acc[dateKey] = (acc[dateKey] || 0) + count;
                    }
                    return acc;
                  }, {} as Record<string, number>);

                  const sortedDays = Object.entries(aggregatedByDay)
                    .map(([date, count]) => ({ date, count }))
                    .filter(d => d.date) // Filter out empty dates only
                    .sort((a, b) => a.date.localeCompare(b.date))
                    .slice(-7); // Last 7 days

                  if (sortedDays.length === 0) return null;

                  const maxCount = Math.max(...sortedDays.map(d => d.count), 1);

                  return (
                    <div className="bg-muted/50 rounded-lg p-3">
                      <p className="text-xs text-muted-foreground mb-2">Matches by Day ({sortedDays.reduce((sum, d) => sum + d.count, 0)} total)</p>
                      <div className="flex gap-2">
                        {sortedDays.map((day, i) => {
                          const heightPx = Math.max((day.count / maxCount) * 48, 4); // Max 48px, min 4px
                          return (
                            <div key={i} className="flex-1 flex flex-col items-center gap-1 min-w-0">
                              <span className="text-[10px] text-primary font-medium">{day.count}</span>
                              <div className="w-full h-12 flex items-end">
                                <div
                                  className="w-full bg-primary/60 rounded-t"
                                  style={{ height: `${heightPx}px` }}
                                />
                              </div>
                              <span className="text-[10px] text-muted-foreground truncate w-full text-center">{day.date.slice(5)}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}

                {testResult.sample_events.length > 0 && (
                  <div className="bg-muted/50 rounded-lg p-3">
                    <p className="text-xs text-muted-foreground mb-2">Sample Events ({testResult.sample_events.length})</p>
                    <div className="space-y-1 max-h-80 overflow-auto">
                      {testResult.sample_events.slice(0, 50).map((event, i) => {
                        const eventObj = event as Record<string, unknown>;
                        const timestamp = eventObj.timestamp ? formatUTCShort(parseUTCTimestamp(String(eventObj.timestamp))) : null;
                        return (
                          <div key={i} className="bg-muted/30 rounded px-2 py-1.5 text-xs font-mono hover:bg-muted/40 transition-colors">
                            <div className="flex flex-wrap gap-x-2 gap-y-0.5">
                              {timestamp && (
                                <span className="text-muted-foreground flex-shrink-0">
                                  {timestamp}
                                </span>
                              )}
                              {(() => {
                                // Flatten nested objects recursively into dot-notation fields
                                const flattenObject = (obj: Record<string, unknown>, prefix = ''): Array<{key: string, value: unknown}> => {
                                  return Object.entries(obj).flatMap(([k, v]) => {
                                    const key = prefix ? `${prefix}.${k}` : k;
                                    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
                                      return flattenObject(v as Record<string, unknown>, key);
                                    }
                                    return [{ key, value: v }];
                                  });
                                };
                                return flattenObject(eventObj)
                                  .filter(({ key, value }) => !['timestamp', 'id', 'metadata'].includes(key.split('.')[0]) && value != null && value !== '')
                                  .slice(0, 15)
                                  .map(({ key, value }) => {
                                    const displayValue = typeof value === 'string' ? `"${value}"` : String(value);
                                    const copyValue = `${key} = ${displayValue}`;
                                    return (
                                      <span
                                        key={key}
                                        className="inline-flex items-center cursor-pointer hover:bg-accent rounded px-0.5 -mx-0.5 transition-colors"
                                        onClick={() => {
                                          navigator.clipboard.writeText(copyValue);
                                          toast.success('Copied to clipboard', {
                                            description: copyValue.length > 60 ? copyValue.slice(0, 60) + '...' : copyValue,
                                            duration: 2000,
                                          });
                                        }}
                                        title={`Click to copy: ${copyValue}`}
                                      >
                                        <span className="text-muted-foreground">{key}=</span>
                                        <span className="text-primary">{displayValue}</span>
                                      </span>
                                    );
                                  });
                              })()}
                            </div>
                          </div>
                        );
                      })}
                      {testResult.sample_events.length > 50 && (
                        <p className="text-xs text-muted-foreground text-center py-2">
                          Showing 50 of {testResult.sample_events.length} events
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {testResult.total_matches === 0 && (
                  <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 rounded-lg p-4">
                    <p className="text-amber-800 dark:text-amber-400 text-sm">No matches found in the selected time range. Try expanding the date range or adjusting your query.</p>
                  </div>
                )}
              </div>
            )}

            {!testResult && !testError && (
              <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
                <p>Select a date range and click "Run Test" to see results</p>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
