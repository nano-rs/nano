// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * TypeScript types for MITRE ATT&CK coverage visualization
 */

export type CoverageLevel = 'none' | 'low' | 'medium' | 'high';

export interface CoveringRule {
  id: string;
  name: string;
  severity: string;
  mode: string;
  /** Source-type / parser identifier the rule queries (e.g. "aws_cloudtrail", "okta", "windows_sysmon"). May be empty if not derivable. */
  source?: string;
}

export type DataSourceReadiness = 'active' | 'stale' | 'unknown';

export interface RequiredDataSource {
  id: string;
  name: string;
  /** Whether nano can map this ATT&CK label to source_type identities. */
  mapping_known?: boolean;
  /** Whether a matching source identity is enabled and deployed. */
  configured?: boolean;
  /** Configuration + recent-ingestion readiness. Optional for rolling upgrades from older APIs. */
  readiness?: DataSourceReadiness;
  /** Most recent event within the retained telemetry window. */
  last_seen_at?: string | null;
  /** Compatibility alias from the API; true only for active readiness. */
  connected?: boolean;
}

export interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  is_subtechnique: boolean;
  parent_id?: string;
  tactic_ids: string[];
  rule_count: number;
  coverage_level: CoverageLevel;
  rules: CoveringRule[];
  /** ATT&CK-declared data sources plus configured-source and ingestion readiness. */
  data_sources?: RequiredDataSource[];
}

export interface TacticCoverage {
  tactic_id: string;
  tactic_name: string;
  short_name: string;
  total_techniques: number;
  covered_techniques: number;
}

export interface CoverageSummary {
  /** Parents and sub-techniques are counted as independent ATT&CK technique IDs. */
  coverage_unit: 'technique';
  total_techniques: number;
  covered_techniques: number;
  coverage_percentage: number;
  total_rules_with_mitre: number;
}

export interface MitreCoverageResponse {
  tactics: TacticCoverage[];
  techniques: TechniqueCoverage[];
  summary: CoverageSummary;
}

export interface CoverageFilters {
  severity: string[];
  mode: string[];
}

// ----------------------------------------------------------------------------
// Redesign tier vocabulary — derived client-side from `rules` filtered to live.
//   live count >= 2  → full
//   live count === 1 → partial
//   live count === 0 + any active data source → hot-gap
//   live count === 0 + no active data source  → gap
// ----------------------------------------------------------------------------

export type CoverageTier = 'full' | 'partial' | 'hot-gap' | 'gap';

export type StatusKey = 'live' | 'review' | 'disabled';

/**
 * Map the API's `mode` (alerting / live / staging) onto the redesign's status
 * vocabulary (live / review / disabled). The redesign distinguishes
 * "actively running" vs "draft/in-review" vs "off"; map staging→review and
 * alerting→live (alerting is a superset of live with notifications).
 */
export function statusOf(mode: string): StatusKey {
  const m = mode.toLowerCase();
  if (m === 'live' || m === 'alerting') return 'live';
  if (m === 'staging' || m === 'review') return 'review';
  return 'disabled';
}

export function readinessOf(source: RequiredDataSource): DataSourceReadiness {
  if (
    source.readiness === 'active'
    || source.readiness === 'stale'
    || source.readiness === 'unknown'
  ) {
    return source.readiness;
  }
  // Rolling-upgrade compatibility for an older API response. A false legacy
  // flag never becomes "missing" because it cannot distinguish stale from
  // unavailable health.
  return source.connected === true ? 'active' : 'unknown';
}

export function readinessLabel(source: RequiredDataSource): string {
  const readiness = readinessOf(source);
  if (readiness === 'active') return 'active';
  if (readiness === 'stale') return source.last_seen_at ? 'stale' : 'idle';
  if (source.mapping_known === false) return 'unknown';
  return source.configured === false ? 'not configured' : 'unknown';
}

export function isDataSourceActive(source: RequiredDataSource): boolean {
  return readinessOf(source) === 'active';
}

export function tierFor(t: TechniqueCoverage): CoverageTier {
  const live = (t.rules || []).filter((r) => statusOf(r.mode) === 'live').length;
  if (live >= 2) return 'full';
  if (live === 1) return 'partial';
  const hasActiveTelemetry = (t.data_sources || []).some(isDataSourceActive);
  return hasActiveTelemetry ? 'hot-gap' : 'gap';
}

export interface RedesignFilters {
  q: string;
  status: Set<StatusKey>;
  platforms: Set<string>;
  gapOnly: boolean;
}

export type Density = 'compact' | 'default' | 'roomy';

export interface TechniqueCoverageStats {
  total: number;
  covered: number;
  percentage: number;
  tiers: Record<CoverageTier, number>;
  gaps: TechniqueCoverage[];
}

/**
 * Summarize the UI's live-rule coverage contract. Every catalog technique ID
 * is independent, so parent coverage never rolls down to a sub-technique.
 */
export function summarizeTechniqueCoverage(
  techniques: readonly TechniqueCoverage[],
): TechniqueCoverageStats {
  const tiers: Record<CoverageTier, number> = {
    full: 0,
    partial: 0,
    'hot-gap': 0,
    gap: 0,
  };
  const gaps: TechniqueCoverage[] = [];

  techniques.forEach((technique) => {
    const tier = tierFor(technique);
    tiers[tier] += 1;
    if (tier === 'hot-gap' || tier === 'gap') gaps.push(technique);
  });

  const covered = tiers.full + tiers.partial;
  return {
    total: techniques.length,
    covered,
    percentage: techniques.length > 0 ? Math.round((covered / techniques.length) * 100) : 0,
    tiers,
    gaps,
  };
}

export function hasTechniqueFilters(filters: RedesignFilters): boolean {
  return filters.q.trim().length > 0
    || filters.status.size > 0
    || filters.platforms.size > 0
    || filters.gapOnly;
}

/** Apply filters to one coverage unit only; parent/child context is handled by the matrix. */
export function techniqueMatchesFilters(
  technique: TechniqueCoverage,
  filters: RedesignFilters,
): boolean {
  const tier = tierFor(technique);
  if (filters.gapOnly && (tier === 'full' || tier === 'partial')) return false;

  if (
    filters.status.size > 0
    && !(technique.rules || []).some((rule) => filters.status.has(statusOf(rule.mode)))
  ) {
    return false;
  }

  if (
    filters.platforms.size > 0
    && !(technique.rules || []).some(
      (rule) => rule.source && filters.platforms.has(rule.source),
    )
  ) {
    return false;
  }

  const query = filters.q.trim().toLowerCase();
  if (query.length > 0) {
    const haystack = [
      technique.technique_id,
      technique.technique_name,
      ...(technique.rules || []).map((rule) => rule.name),
    ].join(' ').toLowerCase();
    if (!haystack.includes(query)) return false;
  }

  return true;
}

export interface FilteredTechniqueGroup {
  parentMatches: boolean;
  subs: TechniqueCoverage[];
  visible: boolean;
}

/** Keep a parent row as context when one of its independently filtered children matches. */
export function filterTechniqueGroup(
  parent: TechniqueCoverage,
  subs: readonly TechniqueCoverage[],
  filters: RedesignFilters,
): FilteredTechniqueGroup {
  const parentMatches = techniqueMatchesFilters(parent, filters);
  const matchingSubs = subs.filter((sub) => techniqueMatchesFilters(sub, filters));
  return {
    parentMatches,
    subs: hasTechniqueFilters(filters) ? matchingSubs : [...subs],
    visible: parentMatches || matchingSubs.length > 0,
  };
}
