// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5850: the SHAPE of the hunt layer on the unified MITRE Coverage page.
 *
 * Shape only, no logic. The data comes from the enterprise endpoint
 * `GET /api/hunts/technique-coverage?days=N`, read by the enterprise hook
 * `useHuntTechniqueCoverage` (open core gets a stub that always returns
 * `null`). The AGPL pure functions in `layers.ts` accept
 * `HuntTechniqueLayer | null`, so the open-core build compiles them with no
 * enterprise import.
 *
 * Mirrors `nanosiem_core::hunts::technique_coverage::HuntTechniqueCoverageResponse`.
 * The enterprise client also narrows the generated wire type onto these.
 */

/** Findings filed in the window, by class (the lead's own `class`). */
export interface HuntFindingClassCounts {
  lead: number;
  benign: number;
  duplicate: number;
  escalated: number;
}

/** Rule ideas for a technique, by state. `rejected` is never counted. */
export interface HuntRuleIdeaStateCounts {
  keep_hunting: number;
  ready: number;
  needs_lookup: number;
  sent: number;
}

/** One hunt that targets the technique (capped at 10 per technique). */
export interface HuntTechniqueHunt {
  /** Hunt TypeID (`pb_...`). */
  id: string;
  title: string;
  enabled: boolean;
  schedule_cron: string | null;
  /** Last successful sweep, all time (`hunt_specs.last_success_at`). */
  last_success_at: string | null;
  /** Finished sweeps of this hunt in the window. */
  sweeps_window: number;
  /** Every finding this hunt filed in the window, whatever technique it carries. */
  findings_window: number;
}

/** The hunt layer for one ATT&CK technique id. */
export interface HuntTechniqueLayer {
  /** Canonical technique id, already alias-resolved (v19 renumbers). */
  technique_id: string;
  /** Non-archived hunts targeting this technique. */
  hunts_total: number;
  /** Of those, enabled (on a schedule). */
  hunts_enabled: number;
  /** Up to 10, enabled first, then most recently successful. */
  hunts: HuntTechniqueHunt[];
  /** Most recent finished sweep of any hunt targeting it, all time. */
  last_hunted_at: string | null;
  /**
   * Finished sweeps in the window of hunts targeting this technique that
   * actually read data: held, error, cancelled and no_coverage sweeps (and
   * detection-trip sweeps) are excluded. `> 0` is what "hunted" means (H
   * layer `hunted`).
   */
  sweeps_window: number;
  /**
   * Findings in the window attributed to this technique: the lead's own
   * `mitre_technique` (what the agent FOUND), falling back to the hunt's target
   * when the lead carries none.
   */
  findings_window: HuntFindingClassCounts;
  /** Of `findings_window`, filed by hunts that target a different technique. */
  findings_from_other_hunts: number;
  rule_ideas: HuntRuleIdeaStateCounts;
}

/** The latest recon run, for the recon strip and the `regressed_to_blind` marker. */
export interface HuntReconStatus {
  last_run_at: string | null;
  next_run_at: string | null;
  degraded: boolean;
  /** Covered in the previous profile, blind now. */
  regressed_to_blind: string[];
}

/** Hunt data whose technique is null or unknown to the catalog after alias resolution. */
export interface HuntUnattributed {
  hunts: number;
  findings_window: number;
  rule_ideas: number;
}

/** `GET /api/hunts/technique-coverage?days=N`. */
export interface HuntTechniqueCoverageResponse {
  window_days: number;
  since: string;
  generated_at: string;
  /** `null` when recon has never run (or the caller cannot see the profile). */
  recon: HuntReconStatus | null;
  /** Only techniques with any hunt data; sorted by technique id. */
  techniques: HuntTechniqueLayer[];
  unattributed: HuntUnattributed;
}

/** Windows the page offers for the `hunted` filter. Default 30. */
export const HUNTED_WINDOWS = [7, 30, 90] as const;
export type HuntedWindow = (typeof HUNTED_WINDOWS)[number];
export const DEFAULT_HUNTED_WINDOW: HuntedWindow = 30;

/** What `useHuntTechniqueCoverage(days, enabled)` returns (enterprise hook and open stub). */
export interface HuntTechniqueCoverageState {
  /** Keyed by canonical technique id. `null` in open core, while disabled, or before the first load. */
  data: Map<string, HuntTechniqueLayer> | null;
  recon: HuntReconStatus | null;
  unattributed: HuntUnattributed | null;
  /** The window the server actually used. */
  windowDays: number | null;
  isLoading: boolean;
  error: Error | null;
}
