// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 / NAN-5850 — the unified MITRE ATT&CK coverage page.
// One matrix, one technique list, three layers per technique: detection
// (rules by mode), hunt (enterprise: hunted, findings, rule ideas) and
// telemetry (required data and its live readiness). Tabs: Matrix, Gaps,
// Telemetry. Every filter lives in the URL (design 4.4) so a view is a link.
// AppLayout owns the breadcrumb; this page renders title, meta row, content.
//
// Open core: no hunt layer. The Hunts / Both views and the hunted filter are
// not rendered, and the combined classes degrade to detected / telemetry, no
// rule / blind / unmapped. The headline % is live-rule coverage only.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertTriangle, ChevronDown, Search as SearchIcon } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import {
  useMitreCoverage,
  useMitreData,
  useMitreQuarantine,
  type MitreQuarantinedMapping,
  type MitreSyncState,
} from '@/hooks/useMitreData';
import { Button } from '@/components/ui/button';
import { InfoTip } from '@/components/ui/info-tip';
import { Term } from '@/components/ui/term';
import { EnterpriseTerm } from '@/enterprise/components/glossary/EnterpriseTerm';
import { Card, CardContent } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

import { CoverageMatrix, orderTactics } from '@/components/mitre/CoverageMatrix';
import { TechniqueDetailSheet } from '@/components/mitre/TechniqueDetailSheet';
import { GapsTable } from '@/components/mitre/GapsTable';
import { Legend } from '@/components/mitre/Legend';
import { TelemetryTab } from '@/components/mitre/TelemetryTab';
import {
  type Density,
  type TechniqueCoverage,
  ALL_RULE_MODES,
  countRulesByStatus,
  summarizeTechniqueCoverage,
} from '@/components/mitre/types';
import {
  type ClassCounts,
  type CoverageClass,
  type CoverageTab,
  type CoverageView,
  type GapKind,
  type HuntWindow,
  type TechniqueLayers,
  type UnifiedCoverageState,
  COVERAGE_CLASSES,
  COVERAGE_COLOR,
  GAP_KINDS,
  HUNT_WINDOWS,
  RULE_MODES,
  classLabel,
  countClasses,
  effectiveView,
  gapLabel,
  hasNarrowingFilters,
  inGapQueue,
  isDimmed,
  matchesUnifiedFilters,
  parseCoverageParams,
  techniqueLayers,
  filterKey,
  searchHaystack,
  techniqueSourceTypes,
  viewFellBack,
  writeCoverageParams,
} from '@/components/mitre/layers';
import { useHuntTechniqueCoverage } from '@/enterprise/hooks/use-hunt-technique-coverage';
import {
  CoverageHuntsSection,
  CoverageTechniqueBindings,
  CoverageTelemetryEnterprise,
  ReconMeta,
  ReconResultProvider,
  RunReconButton,
  useCoverageHuntActions,
} from '@/enterprise/components/coverage';
import { openPivtPanel } from '@/enterprise/components/pivt/commands/router';

// ----------------------------------------------------------------------------
// Unmapped-rules banner (NAN-1918).
//
// Coverage counts only live mappings, so a rule whose mapping a catalog sync
// dropped stops contributing, and the percentage rises. Without this the
// number on this page looks better precisely because detection got worse.
// ----------------------------------------------------------------------------

function DroppedMappingsBanner({ mappings }: { mappings: MitreQuarantinedMapping[] }) {
  const [expanded, setExpanded] = useState(false);
  if (mappings.length === 0) return null;

  return (
    <div className="mx-4 mt-2 border border-amber-500/30 bg-amber-500/10 rounded-md">
      <div className="flex items-start gap-2 px-3 py-2">
        <AlertTriangle className="w-4 h-4 mt-[1px] shrink-0 text-amber-500" strokeWidth={1.5} />
        <div className="min-w-0 flex-1">
          <p className="text-[12px] leading-snug">
            <span className="font-medium">
              {mappings.length} {mappings.length === 1 ? 'rule has' : 'rules have'} no ATT&amp;CK
              mapping
            </span>
            <span className="text-muted-foreground">
              {': '}an ATT&amp;CK catalog update removed {mappings.length === 1 ? 'its tag' : 'their tags'}, so the coverage figure below leaves{' '}
              {mappings.length === 1 ? 'it' : 'them'} out.
            </span>
          </p>
          <button
            type="button"
            onClick={() => setExpanded((open) => !open)}
            className="mt-1 text-[11px] text-muted-foreground hover:text-foreground underline underline-offset-2"
          >
            {expanded ? 'Hide' : 'Show'} affected rules
          </button>
          {expanded && (
            <ul className="mt-2 space-y-1 border-t border-amber-500/20 pt-2">
              {mappings.map((mapping) => (
                <li key={mapping.id} className="flex flex-wrap items-baseline gap-x-2 text-[11px]">
                  <span className="font-mono text-[10.5px]">
                    {mapping.rule_name ?? mapping.rule_id}
                  </span>
                  <span className="text-muted-foreground">was</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground">
                    {[...mapping.original_tactics, ...mapping.original_techniques].join(' ') || '-'}
                  </span>
                  <span className="text-muted-foreground">· {mapping.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Summary strip (design 4.8).
// ----------------------------------------------------------------------------

interface SummaryStripProps {
  pct: number;
  covered: number;
  total: number;
  counts: ClassCounts;
  huntLayer: boolean;
  days: number;
  huntedCount: number;
  findingsCount: number;
  ideasReady: number;
}

function SummaryStrip({ pct, covered, total, counts, huntLayer, days, huntedCount, findingsCount, ideasReady }: SummaryStripProps) {
  const classes = COVERAGE_CLASSES.filter((c) => huntLayer || (c !== 'both' && c !== 'hunted'));
  const denom = Math.max(total, 1);
  return (
    <div className="shrink-0 flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5 border-b border-border" data-testid="coverage-summary">
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-[20px] font-medium tabular-nums" data-testid="coverage-pct">{pct}%</span>
        <span className="text-[11px] text-muted-foreground"><Term id="live-rule-coverage">live-rule coverage</Term></span>
      </div>
      <div className="flex-1 min-w-[280px] max-w-[520px]">
        <div className="flex h-1.5 border border-border rounded-[2px] overflow-hidden">
          {classes.map((c) => (
            <span
              key={c}
              title={`${classLabel(c, huntLayer)} ${counts[c]}`}
              style={{
                width: `${(counts[c] / denom) * 100}%`,
                background: c === 'unmapped' ? 'var(--border)' : COVERAGE_COLOR[c],
                opacity: c === 'blind' ? 0.6 : 1,
              }}
            />
          ))}
        </div>
        <div className="mt-1 flex justify-between gap-3 whitespace-nowrap font-mono text-[10px] text-muted-foreground">
          <span>{covered} of {total} <Term id="technique">techniques</Term> have a live rule</span>
          <span>
            {counts.huntable}{' '}
            {huntLayer ? <EnterpriseTerm id="cov-huntable">huntable, no rule</EnterpriseTerm> : <Term id="cov-telemetry-no-rule">with telemetry, no rule</Term>}
          </span>
        </div>
      </div>
      <div className="flex gap-4 text-[11px] text-muted-foreground">
        {huntLayer && (
          <>
            <div><span className="block font-mono text-[12px] text-foreground tabular-nums" data-testid="coverage-stat-hunted">{huntedCount}</span>hunted in {days}d</div>
            <div><span className="block font-mono text-[12px] text-foreground tabular-nums" data-testid="coverage-stat-findings">{findingsCount}</span>findings in {days}d</div>
            <div><span className="block font-mono text-[12px] text-foreground tabular-nums" data-testid="coverage-stat-ideas">{ideasReady}</span><EnterpriseTerm id="rule-idea">rule ideas</EnterpriseTerm> ready</div>
          </>
        )}
        <div>
          <span className="block font-mono text-[12px] tabular-nums" style={{ color: COVERAGE_COLOR.warn }} data-testid="coverage-stat-no-telemetry">
            {counts.noTelemetry}
          </span>
          <Term id="rule-no-telemetry">rule, no telemetry</Term>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Filter row (design 4.4).
// ----------------------------------------------------------------------------

const VIEW_LABEL: Record<CoverageView, string> = {
  detections: 'Detections',
  hunts: 'Hunts',
  both: 'Both',
  gaps: 'Gaps',
};

const CHIP = 'h-[22px] px-[7px] rounded-[3px] border font-mono text-[10.5px] inline-flex items-center gap-1 transition-colors';
const SELECT = 'h-6 rounded-[4px] border border-border bg-card px-1.5 text-[11.5px] text-foreground focus:outline-none focus:border-primary/50';

interface FilterRowProps {
  state: UnifiedCoverageState;
  view: CoverageView;
  huntLayer: boolean;
  tactics: { id: string; name: string }[];
  sourceTypes: string[];
  density: Density;
  onDensity: (d: Density) => void;
  showIds: boolean;
  onShowIds: (v: boolean) => void;
  subsOpen: boolean;
  onSubsOpen: (v: boolean) => void;
  update: (patch: Partial<UnifiedCoverageState>) => void;
}

/**
 * Search keeps its own keystroke state and commits to the URL after a short
 * pause, so typing never refilters ~900 cells per character.
 */
const SEARCH_DEBOUNCE_MS = 200;

function SearchInput({ value, onCommit, placeholder }: { value: string; onCommit: (q: string) => void; placeholder: string }) {
  const [text, setText] = useState(value);
  const committed = useRef(value);
  // Follow outside changes (back / forward, a cleared filter).
  useEffect(() => {
    if (value !== committed.current) {
      committed.current = value;
      setText(value);
    }
  }, [value]);
  useEffect(() => {
    if (text === committed.current) return undefined;
    const t = window.setTimeout(() => {
      committed.current = text;
      onCommit(text);
    }, SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(t);
  }, [text, onCommit]);
  return (
    <input
      value={text}
      onChange={(e) => setText(e.target.value)}
      placeholder={placeholder}
      aria-label="Search techniques"
      data-testid="coverage-filter-q"
      className={cn(SELECT, 'w-full pl-6 placeholder:text-muted-foreground')}
    />
  );
}

function toggled<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

function FilterRow({ state, view, huntLayer, tactics, sourceTypes, density, onDensity, showIds, onShowIds, subsOpen, onSubsOpen, update }: FilterRowProps) {
  const views: CoverageView[] = huntLayer ? ['detections', 'hunts', 'both', 'gaps'] : ['detections', 'gaps'];
  return (
    <div className="shrink-0 flex flex-wrap items-center gap-2 px-4 py-2 border-b border-border" data-testid="coverage-filters">
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">View</span>
      <div className="inline-flex h-6 border border-border rounded-[4px] overflow-hidden" role="radiogroup" aria-label="Coverage view">
        {views.map((v) => (
          <button
            key={v}
            type="button"
            role="radio"
            aria-checked={view === v}
            data-testid={`coverage-view-${v}`}
            onClick={() => update({ view: v })}
            className={cn(
              'px-2.5 text-[11.5px] border-r border-border last:border-r-0',
              view === v ? 'bg-secondary text-foreground' : 'text-foreground/70 hover:text-foreground',
            )}
          >
            {VIEW_LABEL[v]}
          </button>
        ))}
      </div>

      <span className="w-px h-[18px] bg-border" />
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Mode</span>
      <div className="inline-flex gap-1" data-testid="coverage-filter-mode" role="group" aria-label="Rule mode">
        {RULE_MODES.map((m) => {
          const on = state.modes.has(m);
          return (
            <button
              key={m}
              type="button"
              aria-pressed={on}
              data-testid={`coverage-filter-mode-${m}`}
              onClick={() => update({ modes: toggled(state.modes, m) })}
              className={cn(CHIP, on ? 'border-primary/60 text-foreground bg-primary/10' : 'border-border text-foreground/70 hover:text-foreground')}
            >
              {m}
            </button>
          );
        })}
      </div>

      <span className="w-px h-[18px] bg-border" />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            data-testid="coverage-filter-source"
            aria-label="Data source"
            className={cn(SELECT, 'inline-flex items-center gap-1 font-mono text-[10.5px]', state.sources.size > 0 && 'border-primary/60')}
          >
            {state.sources.size === 0
              ? 'All data sources'
              : state.sources.size === 1
                ? [...state.sources][0]
                : `${state.sources.size} sources`}
            <ChevronDown className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="max-h-[320px] overflow-y-auto">
          {sourceTypes.length === 0 ? (
            <div className="px-2 py-1.5 text-[11px] text-muted-foreground">No source types reported</div>
          ) : (
            sourceTypes.map((s) => (
              <DropdownMenuCheckboxItem
                key={s}
                checked={state.sources.has(s)}
                onSelect={(e) => e.preventDefault()}
                onCheckedChange={() => update({ sources: toggled(state.sources, s) })}
                className="font-mono text-[11px]"
              >
                {s}
              </DropdownMenuCheckboxItem>
            ))
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <select
        data-testid="coverage-filter-tactic"
        aria-label="Tactic"
        className={SELECT}
        value={state.tactic ?? ''}
        onChange={(e) => update({ tactic: e.target.value || null })}
      >
        <option value="">All tactics</option>
        {tactics.map((t) => (
          <option key={t.id} value={t.id}>{t.id} {t.name}</option>
        ))}
      </select>

      {huntLayer && (
        <select
          data-testid="coverage-filter-hunted"
          aria-label="Hunted in last"
          className={SELECT}
          value={state.hunted}
          onChange={(e) => update({ hunted: Number(e.target.value) as HuntWindow })}
        >
          {HUNT_WINDOWS.map((d) => <option key={d} value={d}>Hunted in {d}d</option>)}
        </select>
      )}

      <div className="relative w-[200px]">
        <SearchIcon className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
        <SearchInput
          value={state.q}
          onCommit={(q) => update({ q })}
          placeholder={huntLayer ? 'T1059, PowerShell, rule, hunt' : 'T1059, PowerShell, rule'}
        />
      </div>

      {view === 'gaps' && (
        <>
          <span className="w-px h-[18px] bg-border" />
          <div className="inline-flex gap-1" role="group" aria-label="Gap kind">
            {GAP_KINDS.map((g) => {
              const on = state.gaps.has(g);
              return (
                <button
                  key={g}
                  type="button"
                  aria-pressed={on}
                  data-testid={`coverage-gap-chip-${g}`}
                  onClick={() => update({ gaps: toggled(state.gaps, g as GapKind) })}
                  className={cn(CHIP, on ? 'border-amber-500/60 bg-amber-500/10 text-foreground' : 'border-border text-foreground/70 hover:text-foreground')}
                >
                  {gapLabel(g, huntLayer)}
                </button>
              );
            })}
          </div>
        </>
      )}

      <div className="flex-1 min-w-[8px]" />
      <div className="flex items-center gap-1">
        {(['compact', 'default', 'roomy'] as Density[]).map((d) => (
          <button
            key={d}
            type="button"
            title={`${d} density`}
            onClick={() => onDensity(d)}
            className={cn(CHIP, density === d ? 'border-primary/60 text-foreground bg-primary/10' : 'border-border text-muted-foreground hover:text-foreground')}
          >
            {d[0]}
          </button>
        ))}
        <button
          type="button"
          onClick={() => onShowIds(!showIds)}
          className={cn(CHIP, showIds ? 'border-primary/60 text-foreground bg-primary/10' : 'border-border text-muted-foreground hover:text-foreground')}
        >
          IDs
        </button>
        <button
          type="button"
          aria-label={subsOpen ? 'Collapse sub-techniques' : 'Expand sub-techniques'}
          onClick={() => onSubsOpen(!subsOpen)}
          className={cn(CHIP, subsOpen ? 'border-primary/60 text-foreground bg-primary/10' : 'border-border text-muted-foreground hover:text-foreground')}
        >
          <Term id="sub-technique" nested>subs</Term>
        </button>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Boot / seed window: the pinned ATT&CK catalog hasn't populated yet, so the
// matrix would render a phantom 0-of-0 grid (NAN-1766 / D5).
// ----------------------------------------------------------------------------

function CatalogEmptyState({ syncState }: { syncState: MitreSyncState | null }) {
  const neverSynced = syncState == null || syncState.last_success_at == null;
  const failed = syncState?.status === 'failed';
  const syncing = !failed && (syncState == null || syncState.status === 'syncing' || neverSynced);

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="max-w-[460px] text-center flex flex-col items-center gap-3">
        {syncing ? (
          <>
            <LoadingIcon className="w-8 h-8 text-muted-foreground" />
            <div className="text-[14px] font-semibold text-foreground">ATT&amp;CK catalog syncing…</div>
            <div className="text-[11.5px] text-muted-foreground leading-relaxed">
              Usually under a minute on first boot.
            </div>
          </>
        ) : (
          <>
            <AlertTriangle className="w-8 h-8 text-amber-500" strokeWidth={1.5} />
            <div className="text-[14px] font-semibold text-foreground">ATT&amp;CK catalog unavailable</div>
            <div className="text-[11.5px] text-muted-foreground leading-relaxed">
              Not populated yet. Air-gapped or egress-restricted deployments must seed it first.
            </div>
            {syncState?.last_error ? (
              <div className="text-[10.5px] font-mono text-rose-500/90 break-words max-w-full">
                {syncState.last_error}
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Page.
// ----------------------------------------------------------------------------

// Stable identity so the coverage query key does not churn per render.
// NAN-5717: request every mode so staging / paused rules reach the page.
const ALL_MODES_FILTERS = { severity: [] as string[], mode: [...ALL_RULE_MODES] };

const TAB_LABEL: Record<CoverageTab, string> = { matrix: 'Matrix', gaps: 'Gaps', telemetry: 'Telemetry' };

export function MitreCoverage() {
  return (
    <ReconResultProvider>
      <MitreCoverageBody />
    </ReconResultProvider>
  );
}

function MitreCoverageBody() {
  useDocumentTitle('MITRE ATT&CK Coverage');
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  // The hunt layer: hunts capability AND hunts:view (design 6).
  const huntLayer = Boolean(capabilities.hunts) && hasPermission('hunts:view');

  const [params, setParams] = useSearchParams();
  const state = useMemo(() => parseCoverageParams(params), [params]);
  const view = effectiveView(state.view, huntLayer);
  const fellBack = viewFellBack(state.view, huntLayer);
  // `setParams` changes identity on every URL change; a ref keeps `update`
  // (and every handler built on it) stable so memoized cells do not re-render.
  const setParamsRef = useRef(setParams);
  setParamsRef.current = setParams;
  const update = useCallback((patch: Partial<UnifiedCoverageState>) => {
    setParamsRef.current((prev) => writeCoverageParams({ ...parseCoverageParams(prev), ...patch }, prev), { replace: true });
  }, []);
  // Filtering keys on the filter params only; `tech` / `tab` changes reuse it.
  const filterParams = filterKey(state);
  const filterState = useMemo(() => parseCoverageParams(new URLSearchParams(filterParams)), [filterParams]);

  const [density, setDensity] = useState<Density>('default');
  const [showIds, setShowIds] = useState(true);
  const [subsOpen, setSubsOpen] = useState(true);

  const { data, loading, error } = useMitreCoverage(ALL_MODES_FILTERS);
  const { data: catalogData } = useMitreData();
  const { mappings: quarantined } = useMitreQuarantine();
  const droppedMappings = useMemo(
    () => quarantined.filter((mapping) => mapping.repaired_at === null),
    [quarantined],
  );
  const hunts = useHuntTechniqueCoverage(state.hunted, huntLayer);
  const huntActions = useCoverageHuntActions();

  const techniques = useMemo(() => data?.techniques ?? [], [data?.techniques]);
  const tactics = useMemo(() => data?.tactics ?? [], [data?.tactics]);
  const techniqueById = useMemo(() => new Map(techniques.map((t) => [t.technique_id, t])), [techniques]);
  const tacticsById = useMemo(() => new Map(tactics.map((t) => [t.tactic_id, t])), [tactics]);

  const factsById = useMemo(() => {
    const now = Date.now();
    const map = new Map<string, TechniqueLayers>();
    techniques.forEach((t) => {
      map.set(t.technique_id, techniqueLayers(t, huntLayer ? hunts.data?.get(t.technique_id) ?? null : null, state.hunted, now));
    });
    return map;
  }, [techniques, huntLayer, hunts.data, state.hunted]);

  const subsByParent = useMemo(() => {
    const map = new Map<string, TechniqueCoverage[]>();
    techniques
      .filter((t) => t.is_subtechnique && t.parent_id)
      .forEach((t) => {
        const list = map.get(t.parent_id!) ?? [];
        list.push(t);
        map.set(t.parent_id!, list);
      });
    return map;
  }, [techniques]);

  // Headline: live-rule coverage, unchanged math (design Q7).
  const coverageStats = useMemo(() => summarizeTechniqueCoverage(techniques), [techniques]);
  const ruleStatusCounts = useMemo(() => countRulesByStatus(techniques), [techniques]);
  const counts = useMemo(() => countClasses(factsById.values()), [factsById]);
  const total = data?.summary.total_techniques ?? coverageStats.total;

  const huntStats = useMemo(() => {
    let hunted = 0;
    let findings = 0;
    let ideas = 0;
    factsById.forEach((f) => {
      if (f.h === 'hunted') hunted += 1;
      findings += f.findings;
      ideas += f.layer?.rule_ideas.ready ?? 0;
    });
    return { hunted, findings, ideas };
  }, [factsById]);

  // Per-technique source types and search text, once per data load.
  const searchIndex = useMemo(() => {
    const map = new Map<string, { sourceTypes: string[]; haystack: string }>();
    techniques.forEach((t) => {
      const layer = huntLayer ? hunts.data?.get(t.technique_id) ?? null : null;
      map.set(t.technique_id, { sourceTypes: techniqueSourceTypes(t), haystack: searchHaystack(t, layer) });
    });
    return map;
  }, [techniques, huntLayer, hunts.data]);

  const allSourceTypes = useMemo(() => {
    const set = new Set<string>();
    searchIndex.forEach((entry) => entry.sourceTypes.forEach((s) => set.add(s)));
    return set;
  }, [searchIndex]);
  const sourceTypes = useMemo(
    () => [...new Set([...allSourceTypes, ...filterState.sources])].sort(),
    [allSourceTypes, filterState.sources],
  );

  const tacticOptions = useMemo(
    () => orderTactics(tactics).map((t) => ({ id: t.tactic_id, name: t.tactic_name })),
    [tactics],
  );

  const matches = useCallback((t: TechniqueCoverage) => {
    const facts = factsById.get(t.technique_id);
    if (!facts) return false;
    // The matrix shows the tactic column itself; the tactic filter only
    // narrows the Gaps table.
    return matchesUnifiedFilters(t, { ...filterState, tactic: null }, { layer: facts.layer, facts, ...searchIndex.get(t.technique_id) });
  }, [factsById, filterState, searchIndex]);
  const dimmed = useCallback((f: TechniqueLayers) => isDimmed(view, filterState.gaps, f), [view, filterState.gaps]);

  const gapRows = useMemo(
    () => techniques
      .map((technique) => ({ technique, facts: factsById.get(technique.technique_id)! }))
      .filter(({ technique, facts }) => facts
        && matchesUnifiedFilters(technique, filterState, { layer: facts.layer, facts, ...searchIndex.get(technique.technique_id) })
        && inGapQueue(filterState.gaps, facts)),
    [techniques, factsById, filterState, searchIndex],
  );

  // Destination permissions for panel and Gaps-table actions.
  const canCreateRule = hasPermission('detections:create');
  const canViewSources = hasPermission('log_sources:view');
  const canOnboard = hasPermission('log_sources:create');
  const actionPerms = useMemo(
    () => ({ createRule: canCreateRule, viewSources: canViewSources, onboard: canOnboard }),
    [canCreateRule, canViewSources, canOnboard],
  );
  const regressed = useMemo(
    () => new Set(huntLayer ? hunts.recon?.regressed_to_blind ?? [] : []),
    [huntLayer, hunts.recon],
  );

  const selected = state.tech ? techniqueById.get(state.tech) ?? null : null;
  const parentOfSelected = selected?.is_subtechnique && selected.parent_id ? techniqueById.get(selected.parent_id) ?? null : null;
  const panelSubs = subsByParent.get((parentOfSelected ?? selected)?.technique_id ?? '') ?? [];
  const selectedFacts = selected ? factsById.get(selected.technique_id) : undefined;

  const openTechnique = useCallback((_tacticId: string, techniqueId: string) => update({ tech: techniqueId }), [update]);
  const closePanel = useCallback((open: boolean) => {
    if (!open) update({ tech: null });
  }, [update]);
  const toggleClass = useCallback(
    (cls: CoverageClass) => update({ classes: toggled(filterState.classes, cls) }),
    [filterState.classes, update],
  );

  if (error) {
    return (
      <Card className="border-rose-500/20 bg-rose-500/10">
        <CardContent className="p-6">
          <p className="text-rose-500">Failed to load MITRE coverage data: {error}</p>
          <Button onClick={() => window.location.reload()} className="mt-4">
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!loading && techniques.length === 0) {
    return (
      <div className="flex flex-col h-full min-h-0 -m-3">
        <CatalogEmptyState syncState={catalogData?.sync_state ?? null} />
      </div>
    );
  }

  const version = catalogData?.sync_state?.release_version ?? catalogData?.last_sync?.version ?? null;
  const tab = state.tab;

  return (
    <div className="flex h-full min-h-0 -m-3" data-testid="mitre-coverage-page" data-view={view} data-hunt-layer={huntLayer ? 'on' : 'off'}>
      <section className="flex-1 min-w-0 flex flex-col overflow-hidden">
        {/* Title + meta row */}
        <div className="shrink-0 px-4 pt-3">
          <div className="flex items-center gap-2.5">
            <h1 className="text-[16px] font-semibold tracking-[-0.005em] text-foreground"><Term id="mitre-attack">MITRE ATT&amp;CK</Term> coverage</h1>
            <span className="flex-1" />
            {huntLayer && <RunReconButton />}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-3.5 gap-y-1 font-mono text-[10.5px] text-muted-foreground" data-testid="coverage-meta">
            {version && <span>ATT&amp;CK <span className="text-foreground/80">{version}</span></span>}
            <span><span className="text-foreground/80">{total}</span> <Term id="technique">techniques</Term></span>
            {data?.summary.total_rules_with_mitre != null && (
              <span><span className="text-foreground/80">{data.summary.total_rules_with_mitre}</span> rules mapped</span>
            )}
            <span data-testid="mitre-rule-status-counts">
              <span data-testid="mitre-review-count">{ruleStatusCounts.review} in review</span>
              {' · '}
              <span data-testid="mitre-disabled-count">{ruleStatusCounts.disabled} disabled</span>
              <InfoTip label="About in review and disabled" variant="inline">
                In review counts rules in Staging mode. Disabled counts paused rules. Neither counts toward coverage.
              </InfoTip>
            </span>
            {huntLayer && <span>hunt window <span className="text-foreground/80">{state.hunted}d</span></span>}
            {huntLayer && <ReconMeta recon={hunts.recon} />}
            {huntLayer && hunts.error && <span className="text-amber-500">hunt layer unavailable</span>}
          </div>
          {fellBack && (
            <div className="mt-1.5 text-[11px] text-muted-foreground" data-testid="coverage-view-fallback">
              Hunt coverage needs Hunts access. Showing detections.
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="shrink-0 mt-2.5 flex gap-0.5 border-b border-border px-4" role="tablist">
          {(['matrix', 'gaps', 'telemetry'] as CoverageTab[]).map((t) => (
            <button
              key={t}
              type="button"
              role="tab"
              aria-selected={tab === t}
              data-testid={`coverage-tab-${t}`}
              onClick={() => update({ tab: t })}
              className={cn(
                'h-[30px] px-2.5 -mb-px text-[12px] border-b',
                tab === t ? 'text-foreground border-foreground' : 'text-foreground/70 border-transparent hover:text-foreground',
              )}
            >
              {TAB_LABEL[t]}
              {t === 'gaps' && <span className="ml-1 font-mono text-[10.5px] text-muted-foreground tabular-nums">{gapRows.length}</span>}
            </button>
          ))}
        </div>

        <DroppedMappingsBanner mappings={droppedMappings} />

        {tab !== 'telemetry' && (
          <>
            <SummaryStrip
              pct={coverageStats.percentage}
              covered={coverageStats.covered}
              total={coverageStats.total}
              counts={counts}
              huntLayer={huntLayer}
              days={state.hunted}
              huntedCount={huntStats.hunted}
              findingsCount={huntStats.findings}
              ideasReady={huntStats.ideas}
            />
            <FilterRow
              state={state}
              view={view}
              huntLayer={huntLayer}
              tactics={tacticOptions}
              sourceTypes={sourceTypes}
              density={density}
              onDensity={setDensity}
              showIds={showIds}
              onShowIds={setShowIds}
              subsOpen={subsOpen}
              onSubsOpen={setSubsOpen}
              update={update}
            />
            <Legend counts={counts} huntLayer={huntLayer} selected={state.classes} onToggle={toggleClass} />
          </>
        )}

        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <LoadingIcon className="w-8 h-8 text-muted-foreground" />
          </div>
        ) : tab === 'matrix' ? (
          <CoverageMatrix
            tactics={tactics}
            techniques={techniques}
            factsById={factsById}
            view={view}
            matches={matches}
            filtersActive={hasNarrowingFilters(filterState)}
            isDimmed={dimmed}
            tacticFilter={state.tactic}
            huntLayer={huntLayer}
            days={state.hunted}
            selectedId={state.tech}
            regressed={regressed}
            density={density}
            showIds={showIds}
            subsOpen={subsOpen}
            onOpenTechnique={openTechnique}
          />
        ) : tab === 'gaps' ? (
          <GapsTable
            rows={gapRows}
            huntLayer={huntLayer}
            days={state.hunted}
            selectedId={state.tech}
            actionPerms={actionPerms}
            regressed={regressed}
            onOpenTechnique={openTechnique}
          />
        ) : (
          <TelemetryTab
            techniques={techniques}
            factsById={factsById}
            enterpriseSection={huntLayer ? <CoverageTelemetryEnterprise /> : null}
            onSourceFilter={(s) => update({ sources: new Set([s]), tab: 'matrix' })}
          />
        )}
      </section>

      <TechniqueDetailSheet
        open={selected !== null}
        onOpenChange={closePanel}
        technique={selected}
        parentTechnique={parentOfSelected}
        subs={panelSubs}
        tacticsById={tacticsById}
        factsById={factsById}
        huntLayer={huntLayer}
        onSelectTechnique={(id) => update({ tech: id })}
        actionPerms={actionPerms}
        regressed={selected ? regressed.has(selected.technique_id) : false}
        huntsSection={selected && huntLayer ? (
          <CoverageHuntsSection
            technique={selected}
            layer={selectedFacts?.layer ?? null}
            days={state.hunted}
            onNewHunt={huntActions.huntFirst}
          />
        ) : null}
        telemetryExtra={selected && huntLayer ? (
          <CoverageTechniqueBindings
            sourceTypes={[...new Set((selected.data_sources ?? []).flatMap((d) => d.source_types ?? []))]}
          />
        ) : null}
        onDraftFromFindings={selected && huntActions.draftFromFindings
          ? () => huntActions.draftFromFindings?.(selected, selectedFacts?.layer ?? null, state.hunted)
          : null}
        onHuntFirst={huntActions.huntFirst}
        onGenerateAi={selected && capabilities.melod && hasPermission('melod:detection')
          ? () => openPivtPanel(`@detection A rule for ATT&CK ${selected.technique_id} ${selected.technique_name}.`)
          : null}
      />
      {huntActions.dialogs}
    </div>
  );
}

export default MitreCoverage;
