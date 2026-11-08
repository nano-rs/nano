// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-2361 layer 1: in-window artifact observation (ported to the ClickHouse
// product in G22 / NAN-4931).
//
// WHY THIS EXISTS
// The rarity chart's Y axis comes from the prevalence baseline, which on
// ClickHouse is a set of materialized-view aggregates (clickhouse/129) read
// through refreshed dictionaries, so a minutes-old artifact can have no
// baseline yet. The UI rendered that miss as hostCount 0 -- indistinguishable
// from "common and boring". (On main the lag was the lake snapshot's; the gap
// is the same.)
//
// The answer is sitting in the events the search already matched. This
// module asks for it directly: an equality-filtered `stats dc(host) by <path>`
// over the SAME window the user just searched.
//
// TRAPS THIS ENCODES:
//
// 1. Equality ORs only, never an existence filter (`file_hash=*`): equality is
//    the shape verified correct on both stores.
//
// 2. Host identity MUST mirror the baseline's, or the two layers count
//    different things and disagree on screen. The ClickHouse prevalence MVs
//    key on `if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))`.
//    NOT `coalesce`: UDM string columns are '' when absent and coalesce('')
//    collapses every host-less row into one host (measured on the G22 e2e
//    stack: two host-less IPs counted as 1).
//
// 3. Group keys may be arrays (an OCSF hash array); callers match by
//    CONTAINMENT rather than equality.
//
// `dc()` compiles to ClickHouse `uniqExact` (clickhouse_sql_gen/aggregation.rs),
// so these counts are exact, not HLL estimates.

// Relative + explicit `.ts` (rather than the `@/lib/...` alias used elsewhere)
// so this module resolves under `node --test`, which has neither alias
// resolution nor extensionless TS lookup. tsconfig sets
// `allowImportingTsExtensions`, so tsc and Vite accept it unchanged.
import { nplQuotedBody } from '../npl-quote.ts';

/** Max artifacts per query. Mirrors RARITY_BATCH_SIZE / backend MAX_BULK_ARTIFACTS. */
export const OBSERVATION_BATCH_SIZE = 100;

/**
 * UDM profile: fields that carry a file hash, exactly what the baseline
 * aggregates read (`hash_prevalence_file_hash_mv`,
 * `hash_prevalence_process_hash_mv`). Under the OCSF profile these UDM names
 * do NOT reach the OCSF hash arrays (measured on an OCSF stack: 0 rows for a
 * hash present in `process.file.hashes.value`), so OCSF uses
 * {@link OCSF_HASH_PATHS}; pick the set with {@link observationPathsFor}.
 */
export const HASH_PATHS = ['file_hash', 'process_hash'] as const;

/**
 * Fields that carry a domain: what the domain prevalence aggregates read
 * (`domain_prevalence_mv` on `dest_host`, `_query_mv`, `_url_domain_mv`).
 */
export const DOMAIN_PATHS = ['dest_host', 'query', 'url_domain'] as const;

/** OCSF profile (`ocsf_logs`): the hash arrays the OCSF baseline and the
    ingest stamper read. Equality on an array path is containment. */
export const OCSF_HASH_PATHS = [
  'file.hashes.value',
  'process.file.hashes.value',
  'actor.process.file.hashes.value',
] as const;

/** OCSF profile: the paths that carry a domain / hostname. */
export const OCSF_DOMAIN_PATHS = [
  'query.hostname',
  'http_request.url.hostname',
  'url.hostname',
  'dst_endpoint.hostname',
] as const;

/** OCSF host identity: device first, then the source endpoint (main's
    `coalesce(nullIf(device.hostname,''), nullIf(src_endpoint.hostname,''), 'unknown')`). */
export const OCSF_HOST_IDENTITY_EVAL =
  'eval __h=if(device.hostname!="", device.hostname, if(src_endpoint.hostname!="", src_endpoint.hostname, "unknown"))';

/**
 * Host identity, mirroring the baseline aggregates. Kept as a single exported
 * constant so a change to the aggregates has one obvious counterpart here.
 */
export const HOST_IDENTITY_EVAL =
  'eval __h=if(src_host!="", src_host, if(src_ip!="", src_ip, "unknown"))';

/** The event time field the window minimum is taken over. */
export const TIME_FIELD = 'timestamp';

/**
 * KNOWN LIMITATION, shared with the baseline: rows carrying neither
 * `src_host` nor `src_ip` all collapse into the single literal host
 * `'unknown'`, so an artifact seen only on such rows reports `hosts: 1`.
 */
export const HOST_IDENTITY_UNKNOWN_BUCKET = 'unknown';

export interface InWindowObservation {
  /** Exact distinct hosts (uniqExact) that touched this artifact in-window. */
  hosts: number;
  /** Raw event count in-window. Diagnostic; not plotted. */
  events: number;
  /** Earliest occurrence in-window, ms epoch. Distinct from environment first-seen. */
  firstInWindow: number | null;
}

/** One `stats` query over one OCSF path for one chunk of artifacts. */
export interface ObservationQuery {
  path: string;
  artifacts: string[];
  npl: string;
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Build the nPL for one path + artifact chunk.
 *
 * Shape (validated on the G22 e2e stack against the search API):
 *   <path>="a" OR <path>="b" | eval __h=if(src_host!="", ...) | stats dc(__h) as hosts,
 *     count as events, min(timestamp) as first_in_window by <path>
 */
export function buildObservationQuery(
  path: string,
  artifacts: string[],
  hostEval: string = HOST_IDENTITY_EVAL,
): ObservationQuery {
  const predicate = artifacts
    .map((value) => `${path}="${nplQuotedBody(value)}"`)
    .join(' OR ');
  const npl =
    `${predicate} | ${hostEval} | ` +
    `stats dc(__h) as hosts, count as events, min(${TIME_FIELD}) as first_in_window by ${path}`;
  return { path, artifacts, npl };
}

/**
 * Fan one artifact set out across every candidate path, chunked.
 *
 * An artifact can legitimately appear under more than one path (the same hash
 * as `file.hashes` on a write and `process.file.hashes` on an exec), so every
 * path is queried and the results merged per artifact.
 */
export function buildObservationQueries(
  artifacts: string[],
  paths: readonly string[],
  hostEval: string = HOST_IDENTITY_EVAL,
): ObservationQuery[] {
  if (artifacts.length === 0) return [];
  const queries: ObservationQuery[] = [];
  for (const path of paths) {
    for (const batch of chunk(artifacts, OBSERVATION_BATCH_SIZE)) {
      queries.push(buildObservationQuery(path, batch, hostEval));
    }
  }
  return queries;
}

/** The observation paths and host identity for the active schema profile
    (NAN-4931: the ClickHouse edition runs either UDM `logs` or OCSF
    `ocsf_logs`). */
export function observationPathsFor(isOcsf: boolean): {
  hashPaths: readonly string[];
  domainPaths: readonly string[];
  hostEval: string;
} {
  return isOcsf
    ? { hashPaths: OCSF_HASH_PATHS, domainPaths: OCSF_DOMAIN_PATHS, hostEval: OCSF_HOST_IDENTITY_EVAL }
    : { hashPaths: HASH_PATHS, domainPaths: DOMAIN_PATHS, hostEval: HOST_IDENTITY_EVAL };
}

/** Normalize a `stats … by <path>` group key, which may be a scalar or an array. */
function groupKeyValues(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return raw.filter((v): v is string => typeof v === 'string' && v.length > 0);
  }
  if (typeof raw === 'string' && raw.length > 0) return [raw];
  return [];
}

function toNumber(raw: unknown): number {
  if (typeof raw === 'number') return raw;
  if (typeof raw === 'string') {
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/**
 * Seconds-vs-milliseconds discrimination.
 *
 * The threshold is 1e11, not 1e12: epoch SECONDS only reach 1e11 in the year
 * 5138, while epoch MILLISECONDS passed it in 1973 -- so the two ranges cannot
 * collide, and a timestamp landing exactly on the boundary is not misread as
 * seconds and multiplied into the far future.
 */
const EPOCH_MS_FLOOR = 1e11;

function toEpochMs(raw: unknown): number | null {
  if (raw == null) return null;
  if (typeof raw === 'number') return raw >= EPOCH_MS_FLOOR ? raw : raw * 1000;
  const str = String(raw);
  // The backend's `min(time)` comes back as "YYYY-MM-DD HH:MM:SS.ffffff" with
  // no zone suffix. `Date.parse` on a bare string like that is interpreted as
  // LOCAL time by the browser, not UTC -- on any non-UTC machine that shifts
  // every timestamp by the viewer's offset (e.g. 4h on EDT), which is enough
  // to push every dot outside a short search window entirely. Only append
  // `Z` when there's no zone info already; treat everything else (already
  // has Z or +/-HH:MM) as parseable as-is.
  const hasZone = str.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(str);
  const parsed = Date.parse(hasZone ? str : `${str.replace(' ', 'T')}Z`);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Merge `stats` rows into per-artifact observations.
 *
 * Cross-path merge takes `max(hosts)` rather than a sum: the same host can
 * appear under several paths, and summing would double-count. This UNDERSTATES
 * when a hash is on disk for host A and executing on host B -- a deliberate,
 * documented approximation, chosen because overstating "how many machines have
 * this" is the dangerous direction for a rarity signal.
 */
export function mergeObservations(
  requested: string[],
  rows: Array<{ path: string; row: Record<string, unknown> }>,
): Map<string, InWindowObservation> {
  const wanted = new Map(requested.map((a) => [a.toLowerCase(), a]));
  const merged = new Map<string, InWindowObservation>();

  for (const { path, row } of rows) {
    const keys = groupKeyValues(row[path]);
    if (keys.length === 0) continue;
    const hosts = toNumber(row.hosts);
    const events = toNumber(row.events);
    const firstInWindow = toEpochMs(row.first_in_window);

    // Containment: a multi-element group key contributes to every requested
    // artifact it holds.
    for (const key of keys) {
      const canonical = wanted.get(key.toLowerCase());
      if (!canonical) continue;
      const existing = merged.get(canonical);
      if (!existing) {
        merged.set(canonical, { hosts, events, firstInWindow });
        continue;
      }
      existing.hosts = Math.max(existing.hosts, hosts);
      existing.events += events;
      if (
        firstInWindow != null &&
        (existing.firstInWindow == null || firstInWindow < existing.firstInWindow)
      ) {
        existing.firstInWindow = firstInWindow;
      }
    }
  }
  return merged;
}

/**
 * DISCOVERY mode: unlike `buildObservationQuery`, which asks "how many hosts
 * touched THIS KNOWN artifact", this asks "which artifacts appear at all" --
 * the caller's own search query, grouped by an artifact path, with no
 * artifact predicate. There is nothing to chunk: one query per path covers
 * the whole matched set, and `stats ... by <path>` bounds the result by
 * distinct-artifact CARDINALITY, not event count -- the same `limit` that
 * only covers a few seconds of raw events at real ingest volume covers the
 * full distinct-artifact population for the window, because most windows
 * have vastly fewer distinct artifacts than events.
 */
export function buildDiscoveryQuery(baseQuery: string, path: string): ObservationQuery {
  const trimmed = baseQuery.trim();
  const prefix = trimmed.length > 0 ? `${trimmed} | ` : '';
  const npl =
    `${prefix}${HOST_IDENTITY_EVAL} | ` +
    `stats dc(__h) as hosts, count as events, min(${TIME_FIELD}) as first_in_window by ${path}`;
  return { path, artifacts: [], npl };
}

export function buildDiscoveryQueries(
  baseQuery: string,
  paths: readonly string[],
): ObservationQuery[] {
  return paths.map((path) => buildDiscoveryQuery(baseQuery, path));
}

/** One discovery query's raw result: the rows it returned plus the true
 * distinct-artifact count the backend reports (`total_count`), which may
 * exceed `rows.length` when the query's own `limit` capped the groups. */
export interface DiscoveryQueryResult {
  path: string;
  rows: Array<Record<string, unknown>>;
  totalCount: number | null;
  /** The query for this path FAILED (e.g. admission-control 429 after retries).
   * Distinct from "returned no rows": a failed path means the discovered set is
   * incomplete in an unknown way, and the caller must say so — an empty result
   * with `failed` unset genuinely means nothing matched on this path. */
  failed?: boolean;
}

export interface DiscoveryResult {
  /** Discovered artifact -> merged observation, keyed lower-case (the value
   * as it appeared in the data; discovery has no caller-supplied casing to
   * restore). */
  observations: Map<string, InWindowObservation>;
  /** True if ANY path's query hit its own limit -- the discovered set is a
   * lower bound, not the complete population. */
  truncated: boolean;
  /** Sum of each path's true distinct-artifact count. Not the same as the
   * merged map's size (an artifact can appear under multiple paths), but a
   * reasonable "out of how many" figure for a sampling banner -- the same
   * approximation the events-based banner already made. */
  /** Per-path SUM of matched artifacts — an artifact on several paths counts
   *  once per path, so this is an upper bound on distinct artifacts, never a
   *  lower one. See the note where it is accumulated. */
  totalArtifacts: number;
  /** Paths whose discovery query FAILED outright. Any entry here means the
   * artifact list is silently missing whatever that path would have found;
   * callers must surface it — the truncation banner alone cannot, because a
   * failed path reports `totalCount: null` and never trips `truncated`. */
  failedPaths: string[];
}

/**
 * Merge discovery results across paths. Same cross-path semantics as
 * `mergeObservations` (max hosts, sum events, min first_in_window) -- the
 * only difference is there is no `requested` allow-list, since discovery is
 * what BUILDS the artifact list rather than looking up known ones.
 */
export function mergeDiscoveryResults(results: DiscoveryQueryResult[]): DiscoveryResult {
  const merged = new Map<string, InWindowObservation>();
  let truncated = false;
  let totalArtifacts = 0;
  const failedPaths: string[] = [];

  for (const { path, rows, totalCount, failed } of results) {
    if (failed) failedPaths.push(path);
    if (totalCount != null && totalCount > rows.length) truncated = true;
    // NAN-2361: this is a PER-PATH sum, so an artifact appearing on more than
    // one path (a domain seen as both a DNS question and a URL host is the
    // common case) is counted once per path. The UI presents it as "at least N
    // DISTINCT artifacts", which that sum cannot support — it is an upper bound
    // on distinctness, not a lower one. Kept as a coarse ceiling and renamed at
    // the call site rather than pretending to a precision we do not have; the
    // merged map below is the only true distinct count, but it is capped and so
    // cannot answer "how many exist".
    totalArtifacts += totalCount ?? rows.length;

    for (const row of rows) {
      const keys = groupKeyValues(row[path]);
      if (keys.length === 0) continue;
      const hosts = toNumber(row.hosts);
      const events = toNumber(row.events);
      const firstInWindow = toEpochMs(row.first_in_window);

      for (const key of keys) {
        const canonical = key.toLowerCase();
        const existing = merged.get(canonical);
        if (!existing) {
          merged.set(canonical, { hosts, events, firstInWindow });
          continue;
        }
        existing.hosts = Math.max(existing.hosts, hosts);
        existing.events += events;
        if (
          firstInWindow != null &&
          (existing.firstInWindow == null || firstInWindow < existing.firstInWindow)
        ) {
          existing.firstInWindow = firstInWindow;
        }
      }
    }
  }
  return { observations: merged, truncated, totalArtifacts, failedPaths };
}
