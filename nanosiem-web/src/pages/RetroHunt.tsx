// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-1791 — auto retro-hunt rules.
//
// A retro-hunt rule watches the threat-intel feeds and, when NEW indicators
// land, matches just that delta against historical logs — "this indicator was
// published today, and it was in your logs three weeks ago". Hits flow through
// the standard signal processor, so they show up as normal alerts/matches.
//
// This is a compact dedicated surface under /rules rather than a mode inside
// RuleEditorRedesign: a retro-hunt rule has no nPL query to edit (the whole
// editor — CodeMirror, FlowLens, test drawer, predicates — is query-shaped), so
// folding it in would mean gutting that editor. Everything else about the rule
// (list, promote/pause, matches) reuses the standard /rules surfaces.

import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ArrowUpRight, History } from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { RetroHuntRun } from '@/lib/api/types';

const ARTIFACT_TYPES = ['ip', 'domain', 'hash', 'url'] as const;
const DEFAULT_LOOKBACK_DAYS = 90;
const MAX_LOOKBACK_DAYS = 365;
const DEFAULT_MAX_INDICATORS = 500;
const MAX_MAX_INDICATORS = 1000;

/** Dense form row: label on the left, control on the right. */
function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-4 py-2.5 border-b border-border/60 last:border-b-0">
      <div className="w-[180px] shrink-0 pt-1">
        <div className="text-[12px] text-foreground">{label}</div>
        {hint && (
          <div className="text-[10.5px] text-muted-foreground mt-0.5 leading-snug">{hint}</div>
        )}
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}

const inputCls =
  'h-7 px-2 rounded-md border border-border bg-card text-[12px] text-foreground w-full focus:outline-none focus:ring-1 focus:ring-primary/40';

/** Multi-select chip row. Empty selection = "all". */
function ChipMulti({
  options,
  selected,
  onToggle,
  allLabel,
}: {
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
  allLabel: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {options.length === 0 && (
        <span className="text-[11px] text-muted-foreground">No feeds have synced yet.</span>
      )}
      {options.map((opt) => {
        const on = selected.includes(opt);
        return (
          <button
            key={opt}
            type="button"
            onClick={() => onToggle(opt)}
            className={`h-6 px-2 rounded-md border text-[11px] font-mono transition-colors ${
              on
                ? 'border-primary bg-primary/10 text-foreground'
                : 'border-border text-muted-foreground hover:bg-foreground/5'
            }`}
          >
            {opt}
          </button>
        );
      })}
      {selected.length === 0 && options.length > 0 && (
        <span className="text-[10.5px] text-muted-foreground ml-1">{allLabel}</span>
      )}
    </div>
  );
}

export function RetroHunt() {
  const { id } = useParams<{ id: string }>();
  const isNew = !id;
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  useDocumentTitle(isNew ? 'New retro-hunt' : 'Retro-hunt');

  // --- form state ---
  const [name, setName] = useState('Retro-hunt: new threat intel');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<'critical' | 'high' | 'medium' | 'low'>('high');
  const [mode, setMode] = useState<'live' | 'alerting'>('live');
  const [cron, setCron] = useState('*/30 * * * *');
  const [feeds, setFeeds] = useState<string[]>([]);
  const [artifactTypes, setArtifactTypes] = useState<string[]>([]);
  const [lookbackDays, setLookbackDays] = useState(DEFAULT_LOOKBACK_DAYS);
  const [maxIndicators, setMaxIndicators] = useState(DEFAULT_MAX_INDICATORS);

  // --- data ---
  const { data: availableFeeds = [] } = useQuery({
    queryKey: ['retro-hunt-feeds'],
    queryFn: () => api.listRetroHuntFeeds(),
  });

  const { data: rule } = useQuery({
    queryKey: ['detection', id],
    queryFn: () => api.getDetection(id!),
    enabled: !isNew,
  });

  const { data: view, isLoading: viewLoading } = useQuery({
    queryKey: ['retro-hunt', id],
    queryFn: () => api.getRetroHunt(id!),
    enabled: !isNew,
  });

  const { data: runs = [] } = useQuery({
    queryKey: ['retro-hunt-runs', id],
    queryFn: () => api.listRetroHuntRuns(id!),
    enabled: !isNew,
    refetchInterval: 30_000,
  });

  // Hydrate the config form once the existing rule's config arrives.
  useEffect(() => {
    if (view?.config) {
      setFeeds(view.config.feeds);
      setArtifactTypes(view.config.artifact_types);
      setLookbackDays(view.config.lookback_days);
      setMaxIndicators(view.config.max_indicators_per_run);
    }
  }, [view?.config]);

  const createMut = useMutation({
    mutationFn: () =>
      api.createRetroHunt({
        name,
        description: description || undefined,
        severity,
        mode,
        schedule_cron: cron,
        feeds,
        artifact_types: artifactTypes,
        lookback_days: lookbackDays,
        max_indicators_per_run: maxIndicators,
      }),
    onSuccess: (created) => {
      toast({ title: 'Retro-hunt rule created', description: created.name });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      navigate(`/rules/retro-hunt/${created.id}`);
    },
    onError: (e: Error) =>
      toast({ title: 'Could not create rule', description: e.message, variant: 'destructive' }),
  });

  const saveMut = useMutation({
    mutationFn: () =>
      api.updateRetroHunt(id!, {
        feeds,
        artifact_types: artifactTypes,
        lookback_days: lookbackDays,
        max_indicators_per_run: maxIndicators,
      }),
    onSuccess: () => {
      toast({ title: 'Config saved' });
      queryClient.invalidateQueries({ queryKey: ['retro-hunt', id] });
    },
    onError: (e: Error) =>
      toast({ title: 'Could not save config', description: e.message, variant: 'destructive' }),
  });

  const toggle = (list: string[], set: (v: string[]) => void) => (value: string) =>
    set(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);

  const totals = useMemo(() => {
    return runs.reduce(
      (acc, r) => ({
        hunted: acc.hunted + r.indicators_hunted,
        hits: acc.hits + r.hits,
      }),
      { hunted: 0, hits: 0 },
    );
  }, [runs]);

  const lookbackInvalid = lookbackDays < 1 || lookbackDays > MAX_LOOKBACK_DAYS;
  const capInvalid = maxIndicators < 1 || maxIndicators > MAX_MAX_INDICATORS;
  const canSubmit = name.trim().length > 0 && !lookbackInvalid && !capInvalid;

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-end justify-between gap-2">
        <div className="min-w-0">
          <h1 className="text-[20px] font-semibold text-foreground tracking-[-0.01em] leading-none flex items-center gap-2">
            <History className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
            {isNew ? 'New retro-hunt' : rule?.name || 'Retro-hunt'}
          </h1>
          <p className="text-[12px] text-muted-foreground mt-1.5 leading-none">
            Match newly-published threat intel against historical logs
            {!isNew && view?.state?.last_run_at && (
              <>
                <span className="text-muted-foreground/60 mx-1.5">·</span>
                <span className="font-mono text-[10.5px]">
                  last run {new Date(view.state.last_run_at).toLocaleString()}
                </span>
              </>
            )}
            {!isNew && (
              <>
                <span className="text-muted-foreground/60 mx-1.5">·</span>
                <span className="font-mono text-[10.5px]">{totals.hunted} indicators hunted</span>
                <span className="text-muted-foreground/60 mx-1.5">·</span>
                <span className="font-mono text-[10.5px] text-foreground">{totals.hits} hits</span>
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {!isNew && (
            <Link
              to={`/rules/${id}/matches`}
              className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
            >
              <ArrowUpRight className="w-3.5 h-3.5" strokeWidth={2} />
              View hits
            </Link>
          )}
          <button
            type="button"
            disabled={!canSubmit || createMut.isPending || saveMut.isPending}
            onClick={() => (isNew ? createMut.mutate() : saveMut.mutate())}
            className="h-8 px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[11.5px] font-medium disabled:opacity-50"
          >
            {isNew
              ? createMut.isPending
                ? 'Creating…'
                : 'Create rule'
              : saveMut.isPending
                ? 'Saving…'
                : 'Save config'}
          </button>
        </div>
      </div>

      {/* Config card */}
      <div className="border border-border rounded-md bg-card px-4 py-1">
        {isNew && (
          <>
            <Field label="Name">
              <input
                className={inputCls}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Retro-hunt: new threat intel"
              />
            </Field>
            <Field label="Description" hint="Optional">
              <input
                className={inputCls}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </Field>
            <Field label="Severity">
              <select
                className={inputCls}
                value={severity}
                onChange={(e) => setSeverity(e.target.value as typeof severity)}
              >
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </Field>
            <Field
              label="Mode"
              hint="Live bakes in (findings, no alerts). A retro-hunt consumes indicators as it hunts them, so promote to Alerting to alert on intel landing after promotion — or create directly in Alerting to alert on the current backlog."
            >
              <select
                className={inputCls}
                value={mode}
                onChange={(e) => setMode(e.target.value as typeof mode)}
              >
                <option value="live">live (bake-in)</option>
                <option value="alerting">alerting</option>
              </select>
            </Field>
            <Field label="Schedule" hint="Cron. Retro hunts aren't latency-sensitive.">
              <input
                className={`${inputCls} font-mono`}
                value={cron}
                onChange={(e) => setCron(e.target.value)}
              />
            </Field>
          </>
        )}

        <Field label="Feeds" hint="Which intel feeds to watch. None selected = all feeds.">
          <ChipMulti
            options={availableFeeds}
            selected={feeds}
            onToggle={toggle(feeds, setFeeds)}
            allLabel="all feeds"
          />
        </Field>

        <Field label="Artifact types" hint="None selected = all types.">
          <ChipMulti
            options={[...ARTIFACT_TYPES]}
            selected={artifactTypes}
            onToggle={toggle(artifactTypes, setArtifactTypes)}
            allLabel="all types"
          />
        </Field>

        <Field label="Lookback" hint={`How far back to hunt. Max ${MAX_LOOKBACK_DAYS}d (log retention).`}>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={1}
              max={MAX_LOOKBACK_DAYS}
              className={`${inputCls} font-mono w-[110px]`}
              value={lookbackDays}
              onChange={(e) => setLookbackDays(Number(e.target.value))}
            />
            <span className="text-[11px] text-muted-foreground">days</span>
            {lookbackInvalid && (
              <span className="text-[11px] text-destructive">1–{MAX_LOOKBACK_DAYS}</span>
            )}
          </div>
        </Field>

        <Field
          label="Max indicators / run"
          hint="Cost cap. Overflow is carried to the next run — never silently dropped."
        >
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={1}
              max={MAX_MAX_INDICATORS}
              className={`${inputCls} font-mono w-[110px]`}
              value={maxIndicators}
              onChange={(e) => setMaxIndicators(Number(e.target.value))}
            />
            {capInvalid && (
              <span className="text-[11px] text-destructive">1–{MAX_MAX_INDICATORS}</span>
            )}
          </div>
        </Field>
      </div>

      {/* Run history */}
      {!isNew && (
        <div className="border border-border rounded-md bg-card overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border flex items-center justify-between">
            <div className="text-[12px] font-medium text-foreground">Run history</div>
            <div className="text-[10.5px] text-muted-foreground">
              Watermark:{' '}
              <span className="font-mono">
                {view?.state?.watermark
                  ? new Date(view.state.watermark).toLocaleString()
                  : 'not set (first run pending)'}
              </span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-[11.5px]">
              <thead>
                <tr className="text-[10.5px] uppercase tracking-wide text-muted-foreground border-b border-border">
                  <th className="text-left font-medium px-4 py-1.5">Started</th>
                  <th className="text-left font-medium px-3 py-1.5">Status</th>
                  <th className="text-right font-medium px-3 py-1.5">Considered</th>
                  <th className="text-right font-medium px-3 py-1.5">Hunted</th>
                  <th className="text-right font-medium px-3 py-1.5">Hits</th>
                  <th className="text-left font-medium px-3 py-1.5">Truncated</th>
                </tr>
              </thead>
              <tbody>
                {viewLoading && (
                  <tr>
                    <td colSpan={6} className="px-4 py-4 text-muted-foreground text-[12px]">
                      Loading…
                    </td>
                  </tr>
                )}
                {!viewLoading && runs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-4 text-muted-foreground text-[12px]">
                      No runs yet. The rule runs on its schedule ({rule?.schedule_cron || 'cron'}).
                    </td>
                  </tr>
                )}
                {runs.map((run: RetroHuntRun) => (
                  <tr key={run.id} className="border-b border-border/60 last:border-b-0 h-[26px]">
                    <td className="px-4 py-1 font-mono text-[10.5px] text-muted-foreground whitespace-nowrap">
                      {new Date(run.started_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-1">
                      <span
                        className={
                          run.status === 'error'
                            ? 'text-destructive'
                            : run.status === 'running'
                              ? 'text-muted-foreground'
                              : 'text-foreground'
                        }
                        title={run.error || undefined}
                      >
                        {run.status}
                      </span>
                    </td>
                    <td className="px-3 py-1 text-right font-mono text-[10.5px]">
                      {run.candidates_considered}
                    </td>
                    <td className="px-3 py-1 text-right font-mono text-[10.5px]">
                      {run.indicators_hunted}
                    </td>
                    <td
                      className={`px-3 py-1 text-right font-mono text-[10.5px] ${
                        run.hits > 0 ? 'text-foreground font-medium' : 'text-muted-foreground'
                      }`}
                    >
                      {run.hits}
                    </td>
                    <td className="px-3 py-1">
                      {run.truncated ? (
                        <span
                          className="inline-flex items-center gap-1 text-warning"
                          title={`Hit the per-run cap. ${run.overflow_remaining} indicator(s) carried to the next run.`}
                        >
                          <AlertTriangle className="w-3 h-3" strokeWidth={1.5} />
                          <span className="font-mono text-[10.5px]">
                            +{run.overflow_remaining} carried
                          </span>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
