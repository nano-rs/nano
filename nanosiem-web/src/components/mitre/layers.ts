// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5850: the unified MITRE coverage cell model.
 *
 * Every technique gets three layer states, detection (D), hunt (H) and
 * telemetry (T), and one combined class. All functions here are pure and take
 * a `HuntTechniqueLayer | null`: open core always passes null, so H is `none`
 * and the classes degrade to detected / huntable ("telemetry, no rule") /
 * blind / unmapped. Live rules (alerting + live) define "detected", exactly as
 * `tierFor` does; staging and paused rules are visible but never count.
 */

import {
  type RequiredDataSource,
  type TechniqueCoverage,
  readinessOf,
  statusOf,
} from './types';
import {
  type HuntTechniqueLayer,
  type HuntedWindow,
  DEFAULT_HUNTED_WINDOW,
  HUNTED_WINDOWS,
} from './hunt-layer-types';

/** Total findings in the window across classes. */
export function findingsTotal(layer: HuntTechniqueLayer | null | undefined): number {
  if (!layer) return 0;
  const f = layer.findings_window;
  return (f?.lead ?? 0) + (f?.benign ?? 0) + (f?.duplicate ?? 0) + (f?.escalated ?? 0);
}

export type DetectionState = 'full' | 'partial' | 'review' | 'off' | 'none';
export type HuntState = 'hunted' | 'scheduled' | 'drafted' | 'none';
export type TelemetryState = 'active' | 'stale' | 'missing' | 'unknown' | 'unmapped';
export type CoverageClass = 'both' | 'detected' | 'hunted' | 'huntable' | 'blind' | 'unmapped';
export type CoverageView = 'detections' | 'hunts' | 'both' | 'gaps';
export type GapKind = 'huntable_no_rule' | 'rule_no_telemetry' | 'no_coverage';
export type CoverageTab = 'matrix' | 'gaps' | 'telemetry';
export type HuntWindow = HuntedWindow;

export const COVERAGE_VIEWS: readonly CoverageView[] = ['detections', 'hunts', 'both', 'gaps'];
export const COVERAGE_TABS: readonly CoverageTab[] = ['matrix', 'gaps', 'telemetry'];
export const GAP_KINDS: readonly GapKind[] = ['huntable_no_rule', 'rule_no_telemetry', 'no_coverage'];
export const HUNT_WINDOWS: readonly HuntWindow[] = HUNTED_WINDOWS;
export const RULE_MODES: readonly string[] = ['alerting', 'live', 'staging', 'paused'];
export const COVERAGE_CLASSES: readonly CoverageClass[] = ['both', 'detected', 'hunted', 'huntable', 'blind', 'unmapped'];
export const DEFAULT_HUNT_WINDOW: HuntWindow = DEFAULT_HUNTED_WINDOW;

// ----------------------------------------------------------------------------
// Layer states.
// ----------------------------------------------------------------------------

export function liveRuleCount(t: TechniqueCoverage): number {
  return (t.rules || []).filter((r) => statusOf(r.mode) === 'live').length;
}

export function detectionState(t: TechniqueCoverage): DetectionState {
  const live = liveRuleCount(t);
  if (live >= 2) return 'full';
  if (live === 1) return 'partial';
  const statuses = (t.rules || []).map((r) => statusOf(r.mode));
  if (statuses.includes('review')) return 'review';
  if (statuses.includes('disabled')) return 'off';
  return 'none';
}

export function isDetected(d: DetectionState): boolean {
  return d === 'full' || d === 'partial';
}

function isMapped(source: RequiredDataSource): boolean {
  return source.mapping_known !== false;
}

/**
 * Live readiness only (the recon surface never colors a cell):
 * active = any required source active; stale = configured, none active;
 * missing = mapped, nothing configured; unknown = health probe unavailable;
 * unmapped = no nano mapping for any declared data component.
 */
export function telemetryState(t: TechniqueCoverage): TelemetryState {
  const sources = t.data_sources ?? [];
  if (sources.some((s) => readinessOf(s) === 'active')) return 'active';
  const mapped = sources.filter(isMapped);
  if (mapped.length === 0) return 'unmapped';
  if (mapped.some((s) => readinessOf(s) === 'stale')) return 'stale';
  if (mapped.some((s) => readinessOf(s) === 'unknown' && s.configured !== false)) return 'unknown';
  return 'missing';
}

/**
 * hunted = a finished sweep inside the window (`sweeps_window > 0`, the
 * server's own clock and the contract B defines); scheduled = an enabled hunt
 * with none; drafted = hunts exist but all are disabled. `days` and `now` are
 * kept in the signature for callers; the server already windows the layer.
 */
export function huntState(
  layer: HuntTechniqueLayer | null | undefined,
  days: number = DEFAULT_HUNT_WINDOW,
  now: number = Date.now(),
): HuntState {
  void days;
  void now;
  if (!layer || layer.hunts_total <= 0) return 'none';
  if (layer.sweeps_window > 0) return 'hunted';
  if (layer.hunts_enabled > 0) return 'scheduled';
  return 'drafted';
}

/** First match wins (design 4.2). */
export function combinedClass(
  t: TechniqueCoverage,
  layer: HuntTechniqueLayer | null | undefined,
  days: number = DEFAULT_HUNT_WINDOW,
  now: number = Date.now(),
): CoverageClass {
  const det = isDetected(detectionState(t));
  const hunted = huntState(layer, days, now) === 'hunted';
  if (det && hunted) return 'both';
  if (det) return 'detected';
  if (hunted) return 'hunted';
  const tel = telemetryState(t);
  if (tel === 'active') return 'huntable';
  if (tel === 'unmapped') return 'unmapped';
  return 'blind';
}

/** A live rule whose telemetry is not arriving: a silent detection failure. */
export function ruleWithoutTelemetry(t: TechniqueCoverage): boolean {
  if (!isDetected(detectionState(t))) return false;
  const tel = telemetryState(t);
  return tel === 'stale' || tel === 'missing';
}

export function gapKinds(
  t: TechniqueCoverage,
  layer: HuntTechniqueLayer | null | undefined,
  days: number = DEFAULT_HUNT_WINDOW,
  now: number = Date.now(),
): GapKind[] {
  const kinds: GapKind[] = [];
  const cls = combinedClass(t, layer, days, now);
  if (cls === 'huntable' || cls === 'hunted') kinds.push('huntable_no_rule');
  if (ruleWithoutTelemetry(t)) kinds.push('rule_no_telemetry');
  if (
    liveRuleCount(t) === 0
    && huntState(layer, days, now) !== 'hunted'
    && telemetryState(t) !== 'active'
  ) {
    kinds.push('no_coverage');
  }
  return kinds;
}

/** Every computed fact about one technique, so render code calls this once. */
export interface TechniqueLayers {
  d: DetectionState;
  h: HuntState;
  t: TelemetryState;
  cls: CoverageClass;
  live: number;
  staging: number;
  noTelemetry: boolean;
  gaps: GapKind[];
  findings: number;
  layer: HuntTechniqueLayer | null;
}

export function techniqueLayers(
  t: TechniqueCoverage,
  layer: HuntTechniqueLayer | null | undefined,
  days: number = DEFAULT_HUNT_WINDOW,
  now: number = Date.now(),
): TechniqueLayers {
  const h = huntState(layer, days, now);
  return {
    d: detectionState(t),
    h,
    t: telemetryState(t),
    cls: combinedClass(t, layer, days, now),
    live: liveRuleCount(t),
    staging: (t.rules || []).filter((r) => statusOf(r.mode) === 'review').length,
    noTelemetry: ruleWithoutTelemetry(t),
    gaps: gapKinds(t, layer, days, now),
    findings: findingsTotal(layer),
    layer: layer ?? null,
  };
}

// ----------------------------------------------------------------------------
// Filters and URL state.
// ----------------------------------------------------------------------------

export interface UnifiedCoverageState {
  /** The view the URL asked for; `effectiveView` applies the hunt-layer gate. */
  view: CoverageView | null;
  modes: Set<string>;
  sources: Set<string>;
  tactic: string | null;
  hunted: HuntWindow;
  gaps: Set<GapKind>;
  classes: Set<CoverageClass>;
  q: string;
  tech: string | null;
  tab: CoverageTab;
}

function csvSet<T extends string>(raw: string | null, allowed?: readonly T[]): Set<T> {
  const parts = (raw ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  return new Set(
    (allowed ? parts.filter((p) => (allowed as readonly string[]).includes(p)) : parts) as T[],
  );
}

export function parseCoverageParams(params: URLSearchParams): UnifiedCoverageState {
  const view = params.get('view');
  const tab = params.get('tab');
  const hunted = Number(params.get('hunted'));
  return {
    view: (COVERAGE_VIEWS as readonly string[]).includes(view ?? '') ? (view as CoverageView) : null,
    modes: csvSet(params.get('mode')?.toLowerCase() ?? null, RULE_MODES),
    sources: csvSet(params.get('source')?.toLowerCase() ?? null),
    tactic: params.get('tactic')?.trim().toUpperCase() || null,
    hunted: (HUNT_WINDOWS as readonly number[]).includes(hunted) ? (hunted as HuntWindow) : DEFAULT_HUNT_WINDOW,
    gaps: csvSet(params.get('gap'), GAP_KINDS),
    classes: csvSet(params.get('class'), COVERAGE_CLASSES),
    q: params.get('q') ?? '',
    tech: params.get('tech')?.trim().toUpperCase() || null,
    tab: (COVERAGE_TABS as readonly string[]).includes(tab ?? '') ? (tab as CoverageTab) : 'matrix',
  };
}

/**
 * Write the state back, omitting defaults so a bare `/rules/coverage` stays
 * bare. Params this page does not own are preserved.
 */
export function writeCoverageParams(
  state: UnifiedCoverageState,
  base: URLSearchParams = new URLSearchParams(),
): URLSearchParams {
  const next = new URLSearchParams(base);
  const set = (key: string, value: string | null) => {
    if (value) next.set(key, value);
    else next.delete(key);
  };
  const join = (s: Set<string>) => (s.size ? [...s].sort().join(',') : null);
  set('view', state.view);
  set('mode', join(state.modes));
  set('source', join(state.sources));
  set('tactic', state.tactic);
  set('hunted', state.hunted === DEFAULT_HUNT_WINDOW ? null : String(state.hunted));
  set('gap', join(state.gaps));
  set('class', join(state.classes));
  set('q', state.q.trim() ? state.q : null);
  set('tech', state.tech);
  set('tab', state.tab === 'matrix' ? null : state.tab);
  return next;
}

export function defaultView(huntLayer: boolean): CoverageView {
  return huntLayer ? 'both' : 'detections';
}

/** `hunts` / `both` fall back to `detections` without the hunt layer. */
export function effectiveView(requested: CoverageView | null, huntLayer: boolean): CoverageView {
  if (!requested) return defaultView(huntLayer);
  if (!huntLayer && (requested === 'hunts' || requested === 'both')) return 'detections';
  return requested;
}

export function viewFellBack(requested: CoverageView | null, huntLayer: boolean): boolean {
  return !huntLayer && (requested === 'hunts' || requested === 'both');
}

/** Nano source types a technique touches: rule sources plus mapped telemetry. */
export function techniqueSourceTypes(t: TechniqueCoverage): string[] {
  const set = new Set<string>();
  (t.rules || []).forEach((r) => r.source && set.add(r.source.toLowerCase()));
  (t.data_sources ?? []).forEach((d) => (d.source_types ?? []).forEach((s) => set.add(s.toLowerCase())));
  return [...set];
}

export interface FilterContext {
  layer: HuntTechniqueLayer | null | undefined;
  facts: TechniqueLayers;
  /** Precomputed `techniqueSourceTypes(t)`; computed on demand when absent. */
  sourceTypes?: readonly string[];
  /** Precomputed `searchHaystack(t, layer)`; computed on demand when absent. */
  haystack?: string;
}

/** Lowercased text `q` searches: id, name, rule names, hunt titles. */
export function searchHaystack(t: TechniqueCoverage, layer: HuntTechniqueLayer | null | undefined): string {
  return [
    t.technique_id,
    t.technique_name,
    ...(t.rules || []).map((r) => r.name),
    ...(layer?.hunts ?? []).map((h) => h.title),
  ].join(' ').toLowerCase();
}

/** Filter inputs only: drops `tech` and `tab` so selecting a technique or switching tabs never invalidates filtering. */
export function filterKey(state: UnifiedCoverageState): string {
  return writeCoverageParams({ ...state, tech: null, tab: 'matrix' }).toString();
}

/**
 * Narrowing filters only (mode, source, tactic, q, legend classes). View and
 * gap chips dim in the matrix rather than hide; see `isDimmed`.
 */
export function matchesUnifiedFilters(
  t: TechniqueCoverage,
  state: UnifiedCoverageState,
  ctx: FilterContext,
): boolean {
  if (state.tactic && !t.tactic_ids.includes(state.tactic)) return false;
  if (state.modes.size > 0 && !(t.rules || []).some((r) => state.modes.has(r.mode.toLowerCase()))) {
    return false;
  }
  if (state.sources.size > 0 && !(ctx.sourceTypes ?? techniqueSourceTypes(t)).some((s) => state.sources.has(s))) {
    return false;
  }
  if (state.classes.size > 0 && !state.classes.has(ctx.facts.cls)) return false;
  const query = state.q.trim().toLowerCase();
  if (query) {
    if (!(ctx.haystack ?? searchHaystack(t, ctx.layer)).includes(query)) return false;
  }
  return true;
}

export function hasNarrowingFilters(state: UnifiedCoverageState): boolean {
  return state.modes.size > 0
    || state.sources.size > 0
    || state.classes.size > 0
    || state.q.trim().length > 0;
}

/** Gaps view: everything that is not a gap (or not a selected gap kind) fades. */
export function isDimmed(view: CoverageView, gaps: ReadonlySet<GapKind>, facts: TechniqueLayers): boolean {
  if (view !== 'gaps') return false;
  if (gaps.size > 0) return !facts.gaps.some((k) => gaps.has(k));
  return facts.gaps.length === 0;
}

export function inGapQueue(gaps: ReadonlySet<GapKind>, facts: TechniqueLayers): boolean {
  if (facts.gaps.length === 0) return false;
  return gaps.size === 0 || facts.gaps.some((k) => gaps.has(k));
}

/**
 * Gaps-table order: huntable-no-rule techniques with findings first (the best
 * rule-idea input), then by findings, then by class severity, then id.
 */
export function compareGapRows(
  a: { technique: TechniqueCoverage; facts: TechniqueLayers },
  b: { technique: TechniqueCoverage; facts: TechniqueLayers },
): number {
  const hot = (f: TechniqueLayers) => (f.gaps.includes('huntable_no_rule') && f.findings > 0 ? 1 : 0);
  const rank: Record<CoverageClass, number> = { hunted: 0, huntable: 1, detected: 2, both: 3, blind: 4, unmapped: 5 };
  return hot(b.facts) - hot(a.facts)
    || b.facts.findings - a.facts.findings
    || (a.facts.noTelemetry === b.facts.noTelemetry ? 0 : a.facts.noTelemetry ? -1 : 1)
    || rank[a.facts.cls] - rank[b.facts.cls]
    || a.technique.technique_id.localeCompare(b.technique.technique_id);
}

export interface ClassCounts extends Record<CoverageClass, number> {
  noTelemetry: number;
}

export function countClasses(facts: Iterable<TechniqueLayers>): ClassCounts {
  const counts: ClassCounts = { both: 0, detected: 0, hunted: 0, huntable: 0, blind: 0, unmapped: 0, noTelemetry: 0 };
  for (const f of facts) {
    counts[f.cls] += 1;
    if (f.noTelemetry) counts.noTelemetry += 1;
  }
  return counts;
}

// ----------------------------------------------------------------------------
// Presentation tokens (shared by the matrix, legend, panel and gaps table).
// ----------------------------------------------------------------------------

export const COVERAGE_COLOR = {
  both: '#2dd4bf',
  detected: '#4f8cff',
  hunted: '#a78bfa',
  huntable: '#f5a524',
  blind: '#6b7280',
  warn: '#f43f5e',
  ok: '#22c55e',
} as const;

export function classLabel(cls: CoverageClass, huntLayer: boolean): string {
  switch (cls) {
    case 'both': return 'Detected + hunted';
    case 'detected': return 'Detected';
    case 'hunted': return 'Hunted, no rule';
    case 'huntable': return huntLayer ? 'Huntable, no rule' : 'Telemetry, no rule';
    case 'blind': return 'Blind';
    case 'unmapped':
    default: return 'Unmapped';
  }
}

export function gapLabel(kind: GapKind, huntLayer: boolean): string {
  switch (kind) {
    case 'huntable_no_rule': return huntLayer ? 'huntable, no rule' : 'telemetry, no rule';
    case 'rule_no_telemetry': return 'rule, no telemetry';
    case 'no_coverage':
    default: return 'no coverage';
  }
}

export function telemetryLabel(t: TelemetryState): string {
  switch (t) {
    case 'active': return 'active';
    case 'stale': return 'stale';
    case 'missing': return 'not configured';
    case 'unknown': return 'health unknown';
    case 'unmapped':
    default: return 'no nano mapping';
  }
}

/** Fill color and strength for one cell under a view (design 4.2 table). */
export function cellFill(view: CoverageView, f: TechniqueLayers): { color: string | null; strength: number } {
  if (view === 'detections') {
    if (f.d === 'full') return { color: COVERAGE_COLOR.detected, strength: 1 };
    if (f.d === 'partial') return { color: COVERAGE_COLOR.detected, strength: 0.55 };
    if (f.d === 'review') return { color: COVERAGE_COLOR.detected, strength: 0.25 };
    if (f.t === 'active') return { color: COVERAGE_COLOR.huntable, strength: 0.8 };
    if (f.t === 'unmapped') return { color: null, strength: 0 };
    return { color: COVERAGE_COLOR.blind, strength: 0.6 };
  }
  if (view === 'hunts') {
    if (f.h === 'hunted') return { color: COVERAGE_COLOR.hunted, strength: 1 };
    if (f.h === 'scheduled') return { color: COVERAGE_COLOR.hunted, strength: 0.5 };
    if (f.h === 'drafted') return { color: COVERAGE_COLOR.hunted, strength: 0.25 };
    return { color: COVERAGE_COLOR.blind, strength: 0.6 };
  }
  switch (f.cls) {
    case 'both': return { color: COVERAGE_COLOR.both, strength: 1 };
    case 'detected': return { color: COVERAGE_COLOR.detected, strength: f.d === 'partial' ? 0.55 : 1 };
    case 'hunted': return { color: COVERAGE_COLOR.hunted, strength: 1 };
    case 'huntable': return { color: COVERAGE_COLOR.huntable, strength: 1 };
    case 'blind': return { color: COVERAGE_COLOR.blind, strength: 0.6 };
    case 'unmapped':
    default: return { color: null, strength: 0 };
  }
}

/** Hunts view dims techniques nano cannot map telemetry for. */
export function viewDims(view: CoverageView, f: TechniqueLayers): boolean {
  return view === 'hunts' && f.t === 'unmapped';
}
