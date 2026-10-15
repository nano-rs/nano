// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useId } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { PlatformManagedNotice } from '@/components/settings/PlatformManagedNotice';
import { platformManaged } from '@/lib/platform-managed';
import { NumberInput } from '@/components/ui/number-input';
import { Switch } from '@/components/ui/switch';
import { AlertTriangle, Save } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import {
  useSearchAdmissionConfig,
  useUpdateSearchAdmissionConfig,
  useSearchQueryLimits,
  useUpdateSearchQueryLimits,
} from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import type { SharedLakeSettingApplicability } from '@/lib/api';
import { cn } from '@/lib/utils';

type Priority = 'realtime' | 'interactive' | 'analytics';
type LakeVerdicts = Record<string, SharedLakeSettingApplicability> | undefined;

/**
 * NAN-3300: on hosted-shared tenants the API says, per field, whether the
 * shared lake enforces it. A row covering several fields (a resource-budget
 * row) counts as enforced when any of them is; the API keeps such rows uniform.
 */
function lakeVerdict(verdicts: LakeVerdicts, ...fields: string[]): SharedLakeSettingApplicability | null {
  if (!verdicts) return null;
  const found = fields.map((f) => verdicts[f]).filter((v): v is SharedLakeSettingApplicability => v != null);
  if (found.length === 0) return null;
  const applies = found.some((v) => v.applies_on_shared_lake);
  return found.find((v) => v.applies_on_shared_lake === applies) ?? found[0];
}

function LakeApplicability({ verdict }: { verdict: SharedLakeSettingApplicability | null }) {
  if (!verdict) return null;
  return (
    <div className="mt-1 flex items-baseline gap-1.5 text-[11px] leading-snug">
      <span
        className={cn(
          'font-mono text-[10.5px] shrink-0',
          verdict.applies_on_shared_lake ? 'text-emerald-500' : 'text-muted-foreground',
        )}
      >
        {verdict.applies_on_shared_lake ? 'Enforced' : 'Not used on the shared lake'}
      </span>
      <span className="text-muted-foreground">{verdict.detail.replace(/^Not used on the shared lake:\s*/, '')}</span>
    </div>
  );
}

/** Dims a setting the shared lake doesn't use; its reason stays readable. */
const dimmed = (verdict: SharedLakeSettingApplicability | null) =>
  verdict && !verdict.applies_on_shared_lake ? 'opacity-50' : undefined;

const PRIORITIES: Array<{
  key: Priority;
  label: string;
  hint: string;
  execMin: number;
  execMax: number;
  memMin: number;
  memMax: number;
}> = [
  { key: 'realtime', label: 'Realtime', hint: 'Detection rules, NRT queries.', execMin: 5, execMax: 120, memMin: 1, memMax: 20 },
  { key: 'interactive', label: 'Interactive', hint: 'Analyst searches.', execMin: 30, execMax: 3600, memMin: 1, memMax: 100 },
  { key: 'analytics', label: 'Analytics', hint: 'Threat hunting, long-running queries.', execMin: 60, execMax: 7200, memMin: 5, memMax: 200 },
];

export function SearchSettings() {
  useDocumentTitle('Search');

  const { toast } = useToast();
  const { data: settings, loading: loadingSettings, error: loadError, refetch } = useSearchAdmissionConfig();
  const { mutate: updateSettings, loading: saving } = useUpdateSearchAdmissionConfig();
  const { data: queryLimits, loading: loadingLimits, refetch: refetchLimits } = useSearchQueryLimits();
  const { mutate: updateQueryLimits, loading: savingLimits } = useUpdateSearchQueryLimits();

  // Admission config (concurrency + ClickHouse resources)
  const [globalAdHocLimit, setGlobalAdHocLimit] = useState(30);
  const [perUserLimit, setPerUserLimit] = useState(5);
  const [maxQueueDepth, setMaxQueueDepth] = useState(100);
  const [queueTimeoutSeconds, setQueueTimeoutSeconds] = useState(120);
  const [interactiveMaxExecTime, setInteractiveMaxExecTime] = useState(300);
  const [interactiveMaxMemory, setInteractiveMaxMemory] = useState(20);
  const [analyticsMaxExecTime, setAnalyticsMaxExecTime] = useState(3600);
  const [analyticsMaxMemory, setAnalyticsMaxMemory] = useState(50);
  const [realtimeMaxExecTime, setRealtimeMaxExecTime] = useState(30);
  const [realtimeMaxMemory, setRealtimeMaxMemory] = useState(5);

  // Query safety limits
  const [maxGroupArraySize, setMaxGroupArraySize] = useState(10000);
  const [maxMvexpandRows, setMaxMvexpandRows] = useState(100000);
  const [maxPostProcessingGroups, setMaxPostProcessingGroups] = useState(1000000);
  const [maxStreamingCacheRows, setMaxStreamingCacheRows] = useState(50000);
  const [blockOnCostErrors, setBlockOnCostErrors] = useState(false);

  const baseId = useId();

  useEffect(() => {
    if (settings) {
      setGlobalAdHocLimit(settings.global_adhoc_limit);
      setPerUserLimit(settings.per_user_limit);
      setMaxQueueDepth(settings.max_queue_depth);
      setQueueTimeoutSeconds(settings.queue_timeout_seconds);
      setInteractiveMaxExecTime(settings.interactive_max_execution_time);
      setInteractiveMaxMemory(settings.interactive_max_memory_gb);
      setAnalyticsMaxExecTime(settings.analytics_max_execution_time);
      setAnalyticsMaxMemory(settings.analytics_max_memory_gb);
      setRealtimeMaxExecTime(settings.realtime_max_execution_time);
      setRealtimeMaxMemory(settings.realtime_max_memory_gb);
    }
  }, [settings]);

  useEffect(() => {
    if (queryLimits) {
      setMaxGroupArraySize(queryLimits.max_group_array_size);
      setMaxMvexpandRows(queryLimits.max_mvexpand_rows);
      setMaxPostProcessingGroups(queryLimits.max_post_processing_groups);
      setMaxStreamingCacheRows(queryLimits.max_streaming_cache_rows);
      setBlockOnCostErrors(queryLimits.block_on_cost_errors);
    }
  }, [queryLimits]);

  const validationError =
    perUserLimit > globalAdHocLimit ? 'Per-user limit cannot exceed the global ad-hoc limit.' : null;

  const hasChanges =
    settings != null &&
    (globalAdHocLimit !== settings.global_adhoc_limit ||
      perUserLimit !== settings.per_user_limit ||
      maxQueueDepth !== settings.max_queue_depth ||
      queueTimeoutSeconds !== settings.queue_timeout_seconds ||
      interactiveMaxExecTime !== settings.interactive_max_execution_time ||
      interactiveMaxMemory !== settings.interactive_max_memory_gb ||
      analyticsMaxExecTime !== settings.analytics_max_execution_time ||
      analyticsMaxMemory !== settings.analytics_max_memory_gb ||
      realtimeMaxExecTime !== settings.realtime_max_execution_time ||
      realtimeMaxMemory !== settings.realtime_max_memory_gb);

  const hasLimitsChanges =
    queryLimits != null &&
    (maxGroupArraySize !== queryLimits.max_group_array_size ||
      maxMvexpandRows !== queryLimits.max_mvexpand_rows ||
      maxPostProcessingGroups !== queryLimits.max_post_processing_groups ||
      maxStreamingCacheRows !== queryLimits.max_streaming_cache_rows ||
      blockOnCostErrors !== queryLimits.block_on_cost_errors);

  const handleSave = async () => {
    if (validationError) return;
    try {
      await updateSettings({
        global_adhoc_limit: globalAdHocLimit,
        per_user_limit: perUserLimit,
        max_queue_depth: maxQueueDepth,
        queue_timeout_seconds: queueTimeoutSeconds,
        interactive_max_execution_time: interactiveMaxExecTime,
        interactive_max_memory_gb: interactiveMaxMemory,
        analytics_max_execution_time: analyticsMaxExecTime,
        analytics_max_memory_gb: analyticsMaxMemory,
        realtime_max_execution_time: realtimeMaxExecTime,
        realtime_max_memory_gb: realtimeMaxMemory,
      });
      toast({
        title: 'Admission settings saved',
        description: 'Concurrency and resource limits take effect immediately.',
      });
      refetch();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to save settings';
      toast({ title: 'Error', description: message, variant: 'destructive' });
    }
  };

  const handleSaveLimits = async () => {
    try {
      await updateQueryLimits({
        max_group_array_size: maxGroupArraySize,
        max_mvexpand_rows: maxMvexpandRows,
        max_post_processing_groups: maxPostProcessingGroups,
        max_streaming_cache_rows: maxStreamingCacheRows,
        block_on_cost_errors: blockOnCostErrors,
      });
      toast({ title: 'Query limits saved', description: 'New caps apply to subsequent queries.' });
      refetchLimits();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to save query limits';
      toast({ title: 'Error', description: message, variant: 'destructive' });
    }
  };

  if ((loadingSettings && !settings) || (loadingLimits && !queryLimits)) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingIcon className="w-5 h-5 text-muted-foreground" />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="px-6 py-5">
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-4 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] font-medium text-red-400">Failed to load settings</div>
            <div className="text-[11px] text-muted-foreground mt-0.5">{loadError.message}</div>
            <Button
              onClick={() => refetch()}
              variant="outline"
              size="sm"
              className="h-7 text-[11.5px] px-2.5 mt-2 border-red-500/30 text-red-400"
            >
              Try again
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Hosted-shared tenant (NAN-2361): the platform sets admission and query
  // limits; the values below are its defaults and the editors are read-only.
  // NAN-3300: each field also carries whether the shared lake enforces it.
  const managed = platformManaged(settings) ?? platformManaged(queryLimits);
  const readOnly = !!managed;
  const admissionLake: LakeVerdicts = managed ? settings?.shared_lake_applicability : undefined;
  const limitsLake: LakeVerdicts = managed ? queryLimits?.shared_lake_applicability : undefined;
  const budgetsUnusedOnLake = PRIORITIES.every(
    (p) => lakeVerdict(admissionLake, `${p.key}_max_execution_time`, `${p.key}_max_memory_gb`)?.applies_on_shared_lake === false,
  );

  // ID factories for a11y
  const id = (suffix: string) => `${baseId}-${suffix}`;

  // Per-priority resource state map
  const priorityState: Record<Priority, {
    exec: [number, (n: number) => void];
    mem: [number, (n: number) => void];
  }> = {
    realtime: { exec: [realtimeMaxExecTime, setRealtimeMaxExecTime], mem: [realtimeMaxMemory, setRealtimeMaxMemory] },
    interactive: { exec: [interactiveMaxExecTime, setInteractiveMaxExecTime], mem: [interactiveMaxMemory, setInteractiveMaxMemory] },
    analytics: { exec: [analyticsMaxExecTime, setAnalyticsMaxExecTime], mem: [analyticsMaxMemory, setAnalyticsMaxMemory] },
  };

  return (
    <div className="px-6 py-5 space-y-7">
      <div>
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Search</h1>
        <p className="text-[11.5px] text-muted-foreground mt-0.5">
          Admission control, query limits, resource policy
        </p>
      </div>

      {managed && <PlatformManagedNotice verdict={managed} title="Search limits" />}

      {/* CONCURRENCY LIMITS */}
      <section>
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Concurrency limits
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Caps how many ad-hoc search queries can run simultaneously across the platform. Detection rules bypass these limits.
        </p>

        <div className="flex flex-col">
          {[
            {
              key: 'global',
              field: 'global_adhoc_limit',
              label: 'Global ad-hoc limit',
              hint: 'Maximum ad-hoc queries (Interactive + Analytics) running concurrently across all users. (1–500)',
              value: globalAdHocLimit,
              onChange: setGlobalAdHocLimit,
              min: 1,
              max: 500,
              suffix: '',
            },
            {
              key: 'per-user',
              field: 'per_user_limit',
              label: 'Per-user limit',
              hint: 'Maximum concurrent searches per individual user. Must not exceed the global limit. (1–50)',
              value: perUserLimit,
              onChange: setPerUserLimit,
              min: 1,
              max: 50,
              suffix: '',
            },
            {
              key: 'queue-depth',
              field: 'max_queue_depth',
              label: 'Max queue depth',
              hint: 'How many searches can wait in the queue before new ones are rejected. (10–1,000)',
              value: maxQueueDepth,
              onChange: setMaxQueueDepth,
              min: 10,
              max: 1000,
              suffix: '',
            },
            {
              key: 'queue-timeout',
              field: 'queue_timeout_seconds',
              label: 'Queue timeout',
              hint: 'How long a search waits in the queue before timing out. (10–600 sec)',
              value: queueTimeoutSeconds,
              onChange: setQueueTimeoutSeconds,
              min: 10,
              max: 600,
              suffix: 'sec',
            },
          ].map((row) => {
            const inputId = id(row.key);
            const descId = id(`${row.key}-desc`);
            const verdict = lakeVerdict(admissionLake, row.field);
            return (
              <div key={row.key} data-testid={`setting-${row.field}`} className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
                <div className="min-w-0 flex-1">
                  <label htmlFor={inputId} className={cn('text-[12.5px] font-medium text-foreground', !readOnly && 'cursor-pointer', dimmed(verdict))}>
                    {row.label}
                  </label>
                  <div id={descId} className={cn('text-[11px] text-muted-foreground mt-0.5', dimmed(verdict))}>{row.hint}</div>
                  <LakeApplicability verdict={verdict} />
                </div>
                <div className={cn('flex items-center gap-2 shrink-0', dimmed(verdict))}>
                  <NumberInput
                    id={inputId}
                    value={row.value}
                    onChange={row.onChange}
                    min={row.min}
                    max={row.max}
                    disabled={readOnly}
                    aria-describedby={descId}
                    className="h-8 w-[80px] text-center font-mono text-[12px]"
                  />
                  {row.suffix && (
                    <span className="font-mono text-[10.5px] text-muted-foreground">{row.suffix}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* CLICKHOUSE RESOURCE LIMITS */}
      <section>
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Resource budgets
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Per-query execution time and memory caps sent to ClickHouse for each priority tier.
          {budgetsUnusedOnLake && ' The shared lake doesn’t use them.'}
        </p>

        <div className="flex flex-col">
          <div className="grid grid-cols-[160px_1fr_1fr] gap-3 px-3 py-1.5 border-y border-border bg-card/50 text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
            <div>Priority</div>
            <div>Max execution time</div>
            <div>Max memory</div>
          </div>
          {PRIORITIES.map((p) => {
            const { exec, mem } = priorityState[p.key];
            const execId = id(`${p.key}-exec`);
            const memId = id(`${p.key}-mem`);
            const descId = id(`${p.key}-desc`);
            const verdict = lakeVerdict(admissionLake, `${p.key}_max_execution_time`, `${p.key}_max_memory_gb`);
            return (
              <div key={p.key} data-testid={`setting-${p.key}-budget`} className="border-b border-border/60">
                <div
                  className={cn(
                    'grid grid-cols-[160px_1fr_1fr] gap-3 items-center px-3 h-14 hover:bg-foreground/[0.025] transition-colors',
                    dimmed(verdict),
                  )}
                >
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium text-foreground">{p.label}</div>
                    <div id={descId} className="text-[11px] text-muted-foreground mt-0.5">{p.hint}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <NumberInput
                      id={execId}
                      aria-label={`${p.label} max execution time`}
                      aria-describedby={descId}
                      value={exec[0]}
                      onChange={exec[1]}
                      min={p.execMin}
                      max={p.execMax}
                      disabled={readOnly}
                      className="h-8 w-[80px] text-center font-mono text-[12px]"
                    />
                    <span className="font-mono text-[10.5px] text-muted-foreground">sec</span>
                    <span className="font-mono text-[10.5px] text-muted-foreground/70 ml-1">
                      ({p.execMin}–{p.execMax.toLocaleString()})
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <NumberInput
                      id={memId}
                      aria-label={`${p.label} max memory`}
                      aria-describedby={descId}
                      value={mem[0]}
                      onChange={mem[1]}
                      min={p.memMin}
                      max={p.memMax}
                      disabled={readOnly}
                      className="h-8 w-[80px] text-center font-mono text-[12px]"
                    />
                    <span className="font-mono text-[10.5px] text-muted-foreground">GB</span>
                    <span className="font-mono text-[10.5px] text-muted-foreground/70 ml-1">
                      ({p.memMin}–{p.memMax})
                    </span>
                  </div>
                </div>
                {verdict && (
                  <div className="px-3 pb-2 -mt-1">
                    <LakeApplicability verdict={verdict} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {validationError && (
        <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <span className="text-[11.5px] text-amber-400">{validationError}</span>
        </div>
      )}

      <div className="flex justify-end items-center gap-2 pt-1">
        {hasChanges && (
          <span className="font-mono text-[10.5px] text-amber-400">Unsaved changes</span>
        )}
        <Button
          onClick={handleSave}
          disabled={!!managed || !hasChanges || saving || !!validationError}
          size="sm"
          className="h-7 text-[11.5px] px-2.5"
        >
          {saving ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
          Save admission settings
        </Button>
      </div>

      {/* QUERY SAFETY LIMITS */}
      <section className="pt-4 border-t border-border">
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Query safety
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Bounds for memory-intensive query operations — prevents OOM from unbounded array aggregation, expansion, or post-processing.
        </p>

        <div className="flex flex-col">
          {[
            {
              key: 'group-array',
              field: 'max_group_array_size',
              label: 'Max array aggregation size',
              hint: 'Max elements per group in groupArray / values() / list(). Arrays are truncated beyond this. (100–1,000,000)',
              value: maxGroupArraySize,
              onChange: setMaxGroupArraySize,
              min: 100,
              max: 1000000,
              suffix: 'elements',
            },
            {
              key: 'mvexpand',
              field: 'max_mvexpand_rows',
              label: 'Max mvexpand rows',
              hint: 'Default row cap for mvexpand when the query doesn’t specify one. Array expansion runs before LIMIT. (1,000–10,000,000)',
              value: maxMvexpandRows,
              onChange: setMaxMvexpandRows,
              min: 1000,
              max: 10000000,
              suffix: 'rows',
            },
            {
              key: 'post-groups',
              field: 'max_post_processing_groups',
              label: 'Max post-processing groups',
              hint: 'Max groups in Rust-side post-processing (stats, top, rare). Excess dropped. Only applies to commands that can’t run in ClickHouse. (10,000–10,000,000)',
              value: maxPostProcessingGroups,
              onChange: setMaxPostProcessingGroups,
              min: 10000,
              max: 10000000,
              suffix: 'groups',
            },
            {
              key: 'cache-rows',
              field: 'max_streaming_cache_rows',
              label: 'Max streaming cache rows',
              hint: 'Max rows buffered for the streaming result cache. Beyond this, results still stream to the client but aren’t cached for re-display. (1,000–1,000,000)',
              value: maxStreamingCacheRows,
              onChange: setMaxStreamingCacheRows,
              min: 1000,
              max: 1000000,
              suffix: 'rows',
            },
          ].map((row) => {
            const inputId = id(row.key);
            const descId = id(`${row.key}-desc`);
            const verdict = lakeVerdict(limitsLake, row.field);
            return (
              <div key={row.key} data-testid={`setting-${row.field}`} className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
                <div className="min-w-0 flex-1">
                  <label htmlFor={inputId} className={cn('text-[12.5px] font-medium text-foreground', !readOnly && 'cursor-pointer', dimmed(verdict))}>
                    {row.label}
                  </label>
                  <div id={descId} className={cn('text-[11px] text-muted-foreground mt-0.5', dimmed(verdict))}>{row.hint}</div>
                  <LakeApplicability verdict={verdict} />
                </div>
                <div className={cn('flex items-center gap-2 shrink-0', dimmed(verdict))}>
                  <NumberInput
                    id={inputId}
                    value={row.value}
                    onChange={row.onChange}
                    min={row.min}
                    max={row.max}
                    disabled={readOnly}
                    aria-describedby={descId}
                    className="h-8 w-[80px] text-center font-mono text-[12px]"
                  />
                  <span className="font-mono text-[10.5px] text-muted-foreground">{row.suffix}</span>
                </div>
              </div>
            );
          })}

          {(() => {
            const verdict = lakeVerdict(limitsLake, 'block_on_cost_errors');
            return (
              <div data-testid="setting-block_on_cost_errors" className="flex items-center justify-between gap-4 py-3 border-b border-border/60">
                <div className="min-w-0 flex-1">
                  <label htmlFor={id('block-cost')} className={cn('text-[12.5px] font-medium text-foreground', !readOnly && 'cursor-pointer', dimmed(verdict))}>
                    Block queries with cost-analysis errors
                  </label>
                  <div className={cn('text-[11px] text-muted-foreground mt-0.5', dimmed(verdict))}>
                    Reject queries that trigger Error-severity cost warnings (unbounded dedup, unbounded transaction, etc.) instead of just warning. Recommended for shared environments.
                  </div>
                  <LakeApplicability verdict={verdict} />
                </div>
                <Switch
                  id={id('block-cost')}
                  checked={blockOnCostErrors}
                  onCheckedChange={setBlockOnCostErrors}
                  disabled={readOnly}
                  className={cn('h-4 w-7', dimmed(verdict))}
                />
              </div>
            );
          })()}
        </div>

        <div className="flex justify-end items-center gap-2 pt-4">
          {hasLimitsChanges && (
            <span className="font-mono text-[10.5px] text-amber-400">Unsaved changes</span>
          )}
          <Button
            onClick={handleSaveLimits}
            disabled={!!managed || !hasLimitsChanges || savingLimits}
            size="sm"
            className="h-7 text-[11.5px] px-2.5"
          >
            {savingLimits ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
            Save query limits
          </Button>
        </div>
      </section>
    </div>
  );
}

export default SearchSettings;
