// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Parser-bundle rollout status (hosted-shared, NAN-2607; ledger NAN-2603,
 * build vocabulary NAN-2604). A publish / deploy / revert of a custom parser
 * files a rollout request; the platform builds it in a sandbox (`vector validate`
 * + `vector test`), signs it and rolls it to the tenant's parser cell:
 *
 *   pending → building → validated → rolling → live
 *
 * or `failed` (any pre-roll stage, with the stage and Vector's message) or
 * `rolled_back` (the roll-safety verify failed; the previous bundle keeps serving).
 */

import type { LogSourceVersion, ParserRolloutState, TenantParserRollout } from '@/lib/api/types';

/** The happy path, in order. */
export const ROLLOUT_STEPS: readonly ParserRolloutState[] = ['pending', 'building', 'validated', 'rolling', 'live'];

export const ROLLOUT_STATE_LABEL: Record<ParserRolloutState, string> = {
  pending: 'Queued',
  building: 'Building',
  validated: 'Validated',
  rolling: 'Rolling out',
  live: 'Live',
  failed: 'Failed',
  rolled_back: 'Rolled back',
};

const TERMINAL: ReadonlySet<ParserRolloutState> = new Set(['live', 'failed', 'rolled_back']);

/** Poll every 3 s while a rollout moves; stop once it is terminal. */
export const ROLLOUT_POLL_MS = 3_000;

export function isTerminal(rollout: Pick<TenantParserRollout, 'state'> | null | undefined): boolean {
  return !!rollout && TERMINAL.has(rollout.state);
}

/** React Query `refetchInterval` for a rollout (or a list of them). */
export function rolloutPollInterval(
  data: Pick<TenantParserRollout, 'state'> | Pick<TenantParserRollout, 'state'>[] | null | undefined,
): number | false {
  if (!data) return ROLLOUT_POLL_MS;
  const rows = Array.isArray(data) ? data : [data];
  return rows.some((r) => !TERMINAL.has(r.state)) ? ROLLOUT_POLL_MS : false;
}

export function rolloutStateLabel(state: string): string {
  return (ROLLOUT_STATE_LABEL as Record<string, string>)[state] ?? state.replace(/_/g, ' ');
}

/** Index of the state on the happy path; failed / rolled_back resolve to the step they stopped at. */
export function rolloutStepIndex(rollout: Pick<TenantParserRollout, 'state' | 'failure_stage' | 'roll_id'>): number {
  const direct = ROLLOUT_STEPS.indexOf(rollout.state);
  if (direct >= 0) return direct;
  if (rollout.state === 'rolled_back') return ROLLOUT_STEPS.indexOf('rolling');
  // failed: build stages stop at "building", post-build stages at "validated"/"rolling".
  const stage = rollout.failure_stage ?? '';
  if (['sign', 'roll'].includes(stage)) return ROLLOUT_STEPS.indexOf('validated');
  if (['render', 'verify', 'promote'].includes(stage) || rollout.roll_id) return ROLLOUT_STEPS.indexOf('rolling');
  return ROLLOUT_STEPS.indexOf('building');
}

const STAGE_LABEL: Record<string, string> = {
  inputs: 'inputs',
  sandbox: 'sandbox',
  overlay: 'overlay',
  structural_guard: 'structural guard',
  vector_validate: 'vector validate',
  vector_test: 'vector test',
  package: 'package',
  sign: 'sign',
  roll: 'roll',
  render: 'worker render',
  verify: 'verify',
  promote: 'promote',
};

export function failureStageLabel(stage: string | null | undefined): string | null {
  if (!stage) return null;
  return STAGE_LABEL[stage] ?? stage.replace(/_/g, ' ');
}

/**
 * NAN-3248: build stages where the tenant's own parsers are checked. A failure
 * here means "your parsers fail on this base"; a failure at a later stage
 * (package, sign, roll, render, verify, promote) is platform-side.
 */
const VALIDATION_STAGES: ReadonlySet<string> = new Set([
  'inputs',
  'sandbox',
  'overlay',
  'structural_guard',
  'vector_validate',
  'vector_test',
]);

export type FailureOrigin = 'validation' | 'platform' | 'unknown';

export function failureOrigin(stage: string | null | undefined): FailureOrigin {
  if (!stage) return 'unknown';
  return VALIDATION_STAGES.has(stage) ? 'validation' : 'platform';
}

/**
 * Human messages for the parser-roll error codes the enterprise crate returns
 * to the platform (shared_parser_bundle_roll.rs `parser_roll_error`), which the platform
 * records as an offer's / rollout's failure component and reason.
 */
const PARSER_ROLL_ERROR_MESSAGE: Record<string, string> = {
  parser_roll_conflict:
    'The platform roll conflicted with an already-recorded roll for this tenant. Your parsers were not the problem and nothing changed.',
  parser_roll_stale: 'The platform roll raced another change to your parser cell. Nothing changed; retrying is safe.',
  parser_roll_pending: 'Another parser roll was still in progress for your tenant. Nothing changed; retry once it finishes.',
  parser_roll_terminal: 'The platform roll referenced a roll or bundle that had already finished. Nothing changed.',
  parser_roll_forbidden: 'The platform could not roll parsers for this tenant (plan or provisioning not in force).',
  parser_roll_not_enrolled: 'The platform could not roll parsers: the tenant has no source enrollment yet.',
  parser_roll_not_found: 'The platform roll referenced a roll, request or offer that no longer exists.',
  parser_roll_unavailable: 'The platform roll service was unavailable. Nothing changed; retrying is safe.',
  parser_signing_key_not_registered: 'The platform could not sign the new parser bundle. Nothing changed.',
  tenant_parser_customized: 'A platform release never overwrites your customized parsers; merge the update instead.',
};

/** An error code (snake_case token) found in the failure fields, if any. */
export function failureErrorCode(
  failure: { failure_component?: string | null; failure_reason?: string | null },
): string | null {
  for (const v of [failure.failure_component, failure.failure_reason]) {
    const t = v?.trim();
    if (t && /^[a-z][a-z0-9_]*$/.test(t) && t.includes('_')) return t;
  }
  return null;
}

export function parserRollErrorMessage(code: string | null | undefined): string | null {
  return code ? (PARSER_ROLL_ERROR_MESSAGE[code] ?? null) : null;
}

/** 850 → "850ms", 12_400 → "12.4s", 125_000 → "2m 05s". */
export function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1_000).toFixed(ms < 10_000 ? 2 : 1).replace(/\.?0+$/, '')}s`;
  const total = Math.round(ms / 1_000);
  return `${Math.floor(total / 60)}m ${String(total % 60).padStart(2, '0')}s`;
}

/** `{build_ms: 1200, queue_ms: 400}` → `[['queue', '400ms'], ['build', '1.2s']]`, pipeline order first. */
export function formatStageTimings(timings: Record<string, unknown> | null | undefined): [string, string][] {
  if (!timings) return [];
  const order = ['queue', 'build', 'validate', 'test', 'sign', 'roll', 'render', 'verify', 'promote', 'total'];
  const rows = Object.entries(timings)
    .filter((entry): entry is [string, number] => typeof entry[1] === 'number')
    .map(([key, value]) => [key.replace(/_ms$/, ''), value] as const);
  rows.sort((a, b) => {
    const ia = order.indexOf(a[0]);
    const ib = order.indexOf(b[0]);
    return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib) || a[0].localeCompare(b[0]);
  });
  return rows.map(([key, value]) => [key.replace(/_/g, ' '), formatDurationMs(value)]);
}

export function shortSha(sha: string | null | undefined, length = 12): string {
  return sha ? sha.replace(/^sha256:/, '').slice(0, length) : '—';
}

/**
 * NAN-3298: which version of a hosted-shared log source actually serves ingest.
 *
 * Publishing makes a version *active* in the registry at once (`deployed_at`,
 * `is_active`), but it serves only once a parser-bundle roll carrying it is
 * promoted. Every roll builds from the tenant's active published versions at
 * build time, so a version serves once any tenant rollout requested at or
 * after its own request reached `live` (its own, or a later one for another
 * source). A failed / rolled-back roll leaves the previous bundle serving.
 */
export interface ParserServingState {
  /** false: no rollout tracks the active version (no custom parser) — the registry fields are the truth. */
  tracked: boolean;
  /** The version serving ingest; null when nothing this page knows of has gone live yet. */
  servingVersion: number | null;
  /** When the roll carrying `servingVersion` was promoted. */
  servingSince: string | null;
  /** The newest rollout, while it is still moving toward `live`. */
  inFlight: TenantParserRollout | null;
  /** The newest rollout, when it failed / rolled back and its version is not serving. */
  failed: TenantParserRollout | null;
}

const UNTRACKED: ParserServingState = { tracked: false, servingVersion: null, servingSince: null, inFlight: null, failed: null };

/** The (highest) version a rollout carries, or null for one without a publication (merge_base). */
export function rolloutVersion(r: Pick<TenantParserRollout, 'version_numbers'>): number | null {
  const v = r.version_numbers ?? [];
  return v.length ? Math.max(...v) : null;
}

/**
 * @param rollouts this source's rollouts, newest first (`listLogSourceRollouts`).
 * @param latestTenantLive the tenant's newest `live` rollout of any source (`listParserRollouts({states:['live'], limit:1})`).
 * @param activeVersion the registry's active version number.
 */
export function parserServingState(
  rollouts: TenantParserRollout[] | undefined,
  latestTenantLive: TenantParserRollout | null | undefined,
  activeVersion: number | undefined,
): ParserServingState {
  const own = (rollouts ?? []).filter((r) => rolloutVersion(r) != null);
  const latest = own[0];
  if (!latest) return UNTRACKED;
  const latestVersion = rolloutVersion(latest)!;
  // The active version never filed a rollout (e.g. published without a parser): nothing to track.
  if (activeVersion != null && !(latest.version_numbers ?? []).includes(activeVersion)) return UNTRACKED;

  let serving: TenantParserRollout | undefined;
  let servingSince: string | null = null;
  if (latest.state === 'live') {
    serving = latest;
    servingSince = latest.completed_at;
  } else if (latestTenantLive) {
    const liveAt = Date.parse(latestTenantLive.requested_at);
    // The newest of this source's requests filed before that roll was requested: its version was active when the roll built.
    serving = own.find((r) => Date.parse(r.requested_at) <= liveAt);
    if (serving) servingSince = serving.state === 'live' ? serving.completed_at : latestTenantLive.completed_at;
  }
  const servingVersion = serving ? rolloutVersion(serving) : null;
  const behind = servingVersion !== latestVersion;
  return {
    tracked: true,
    servingVersion,
    servingSince,
    inFlight: behind && !isTerminal(latest) ? latest : null,
    failed: behind && (latest.state === 'failed' || latest.state === 'rolled_back') ? latest : null,
  };
}

/** One-line failure text for a failed / rolled-back rollout: `verify probe: <reason>`. */
export function rolloutFailureText(r: Pick<TenantParserRollout, 'failure_stage' | 'failure_component' | 'failure_reason'>): string | null {
  if (!r.failure_reason) return null;
  const where = `${failureStageLabel(r.failure_stage) ?? ''}${r.failure_component ? ` ${r.failure_component}` : ''}`.trim();
  return where ? `${where}: ${r.failure_reason}` : r.failure_reason;
}

/** React Query keys. */
/**
 * Publish coalescing (design §7.6, NAN-2617): a pending publish/revert rolls
 * together with the tenant's other pending changes once the batch window
 * closes. `others` excludes this rollout; `secondsLeft` is never negative.
 */
export function rolloutBatchInfo(
  rollout: Pick<TenantParserRollout, 'id' | 'state' | 'batch'>,
  now: number = Date.now(),
): { others: number; rollsAfter: Date; secondsLeft: number; windowSeconds: number } | null {
  const batch = rollout.batch;
  if (rollout.state !== 'pending' || !batch) return null;
  const rollsAfter = new Date(batch.rolls_after);
  if (Number.isNaN(rollsAfter.getTime())) return null;
  return {
    others: batch.request_ids.filter((id) => id !== rollout.id).length,
    rollsAfter,
    secondsLeft: Math.max(0, Math.ceil((rollsAfter.getTime() - now) / 1000)),
    windowSeconds: batch.window_seconds,
  };
}

/** `HH:MM:SS` local time. */
export function clockTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export const PARSER_ROLLOUT_QUERY_KEY = (id: string) => ['parser-rollouts', id] as const;
export const LOG_SOURCE_ROLLOUTS_QUERY_KEY = (logSourceId: string) => ['parser-rollouts', 'log-source', logSourceId] as const;
export const PARSER_ROLLOUTS_QUERY_KEY = ['parser-rollouts', 'list'] as const;
export const PARSER_BASE_OFFERS_QUERY_KEY = ['parser-base-offers'] as const;
/** The tenant's newest `live` rollout; keyed on this source's newest rollout so a state change refetches it. */
export const LATEST_LIVE_ROLLOUT_QUERY_KEY = (latestId: string | undefined, latestState: string | undefined) =>
  ['parser-rollouts', 'list', 'latest-live', latestId ?? null, latestState ?? null] as const;

/** Newest rollout of a log source from a tenant-wide list. */
export function latestRolloutFor(rollouts: TenantParserRollout[] | undefined, logSourceId: string | undefined): TenantParserRollout | undefined {
  if (!rollouts || !logSourceId) return undefined;
  return rollouts
    .filter((r) => r.log_source_id === logSourceId)
    .sort((a, b) => b.requested_at.localeCompare(a.requested_at))[0];
}

/** The version a one-click revert goes back to: the newest non-active version below the active one. */
export function previousVersion(versions: LogSourceVersion[] | undefined): LogSourceVersion | undefined {
  if (!versions?.length) return undefined;
  const sorted = [...versions].sort((a, b) => b.version_number - a.version_number);
  const active = sorted.find((v) => v.is_active) ?? sorted[0];
  return sorted.find((v) => v.version_number < active.version_number);
}
