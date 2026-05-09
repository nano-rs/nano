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

export interface RequiredDataSource {
  id: string;
  name: string;
  connected: boolean;
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
  /** ATT&CK-declared data sources for this technique + whether nano has any active source mapped. */
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
//   live count === 0 + any connected data source → hot-gap
//   live count === 0 + no connected data source  → gap
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

export function tierFor(t: TechniqueCoverage): CoverageTier {
  const live = (t.rules || []).filter((r) => statusOf(r.mode) === 'live').length;
  if (live >= 2) return 'full';
  if (live === 1) return 'partial';
  const hasConnected = (t.data_sources || []).some((d) => d.connected);
  return hasConnected ? 'hot-gap' : 'gap';
}

export interface RedesignFilters {
  q: string;
  status: Set<StatusKey>;
  platforms: Set<string>;
  gapOnly: boolean;
}

export type Density = 'compact' | 'default' | 'roomy';
