// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-2361 layer 1: in-window artifact observation.
//
// WHY THIS EXISTS
// The rarity chart's Y axis used to come from the immutable prevalence snapshot,
// which rebuilds per generation and therefore lags ingest by 30-90 minutes at
// 120 eps (the tail compactor withholds a generation-ready commit until 64 MB /
// hour-close / 900K staged rows, then the manager rate-limits promotion to one
// per 900s). An analyst triaging a minutes-old alert asked the chart "how many
// hosts touched this?" and got a snapshot miss, which the UI rendered as
// hostCount 0 -- indistinguishable from "common and boring".
//
// The answer was always sitting in the events the search already matched. This
// module asks for it directly: an equality-filtered `stats dc(host) by <path>`
// over the SAME window the user just searched. Measured at 87ms for 18
// artifacts over a 322,927-row window.
//
// THREE TRAPS THIS ENCODES (all found by measurement, not inspection):
//
// 1. NEVER use an existence filter (`file.hashes.value=*`). On the lake path it
//    is wrong in BOTH directions: it admits rows carrying no hashes at all (395
//    of 400 sampled) and drops ~55% of genuinely matching rows (13 hosts vs the
//    27 an equality filter finds for the same artifact and window). Equality
//    ORs are the only shape verified correct. Tracked separately as a lake
//    search-correctness bug.
//
// 2. Host identity MUST mirror the baseline builder's, or layers 1 and 2 count
//    different things and disagree on screen. `prevalence_build.rs`
//    (SQL_OBSERVATION_PART) keys on
//    `coalesce(nullIf(device.hostname,''), nullIf(src_endpoint.hostname,''), 'unknown')`.
//    A plain `dc(device.hostname)` returns 0 for OCSF classes that carry no
//    `device` object at all (verified against http_request rows).
//
// 3. Group keys for hash paths are the ARRAY, not the element -- `['9728...']`,
//    not `'9728...'`. Today's data is >=99% single-element SHA-256, but a future
//    `[md5, sha256]` array forms a composite key, so callers match by
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
 * OCSF paths that can carry a file hash.
 *
 * The baseline builder ingests only `file.hashes` and `process.file.hashes`;
 * the ingest stamper additionally reads `actor.process.file.hashes`. We query
 * the union so layer 1 is never blinder than either -- an artifact the stamper
 * flagged must be countable here.
 */
export const HASH_PATHS = [
  'file.hashes.value',
  'process.file.hashes.value',
  'actor.process.file.hashes.value',
] as const;

/**
 * OCSF paths that can carry a domain/hostname.
 *
 * `dst_endpoint.hostname` is frequently a `'-'` placeholder; it is included
 * because it is what the BASELINE builder reads, and omitting it would make
 * layer 1 disagree with layer 2 on exactly the artifacts that do have it.
 */
export const DOMAIN_PATHS = [
  'query.hostname',
  'http_request.url.hostname',
  'url.hostname',
  'dst_endpoint.hostname',
] as const;

/**
 * Host identity, mirroring the baseline builder. Kept as a single exported
 * constant so a future change to the builder has one obvious counterpart here.
 */
export const HOST_IDENTITY_EVAL =
  'eval __h=coalesce(device.hostname, src_endpoint.hostname, "unknown")';

/**
 * KNOWN LIMITATION, shared with the baseline builder.
 *
 * Rows carrying neither `device.hostname` nor `src_endpoint.hostname` all
 * collapse into the single literal host `'unknown'`. Measured on the live soak:
 * 96,597 of 322,720 events in a 45-minute window (30%) land in that bucket.
 *
 * So an artifact seen ONLY on host-less rows reports `hosts: 1` and reads as
 * rare when its true spread is unknown, not small. This is not introduced here
 * -- `prevalence_build.rs` coalesces identically, and deliberately: the two
 * layers must count the same notion of "host" or they visibly disagree on the
 * same artifact. Fixing it means giving host-less OCSF classes a real identity
 * at ingest, which is a schema question, not a chart one.
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

/**
 * The ingest stamp's newness flag, per artifact.
 *
 * NAN-2361: `is_new` is NOT "first ever seen". The stamper evaluates it against
 * the same lagging snapshot the query path reads, so during the 30-90 minute
 * catch-up EVERY occurrence of a fresh artifact is stamped new, not just the
 * first. Callers must therefore treat this as a per-ARTIFACT property (deduped
 * here) and pin any UI cue to the earliest occurrence, or a single new artifact
 * paints a ring on every dot it owns.
 */
export interface IngestStamp {
  isNew: boolean;
  /** Earliest event timestamp (ms) carrying this stamp, for pinning the cue. */
  earliestMs: number | null;
}

interface EnrichmentLike {
  name?: unknown;
  data?: Record<string, unknown> | null;
}

/**
 * Harvest per-artifact ingest stamps from loaded search rows.
 *
 * Rows without `enrichments` (ClickHouse/UDM tenants, and the fail-open cases
 * where the stamper had no snapshot) simply contribute nothing, which is why
 * this doubles as the lake-vs-CH gate: an empty map means no lake stamps, so
 * callers skip the whole layer rather than branching on backend identity.
 */
export function harvestIngestStamps(
  rows: Array<Record<string, unknown>>,
  timestampOf: (row: Record<string, unknown>) => number | null,
): Map<string, IngestStamp> {
  const stamps = new Map<string, IngestStamp>();
  for (const row of rows) {
    let enrichments = row.enrichments as unknown;
    if (typeof enrichments === 'string') {
      try {
        enrichments = JSON.parse(enrichments);
      } catch {
        continue;
      }
    }
    if (!Array.isArray(enrichments)) continue;
    const ts = timestampOf(row);
    for (const raw of enrichments as EnrichmentLike[]) {
      if (!raw || typeof raw !== 'object' || raw.name !== 'prevalence') continue;
      const data = raw.data;
      if (!data || typeof data !== 'object') continue;
      // `value` carries the artifact the stamp describes.
      const value = (raw as { value?: unknown }).value;
      if (typeof value !== 'string' || value.length === 0) continue;
      const key = value.toLowerCase();
      const isNew = data.is_new === true;
      const existing = stamps.get(key);
      if (!existing) {
        stamps.set(key, { isNew, earliestMs: ts });
        continue;
      }
      // Any occurrence asserting newness makes the artifact new; keep the
      // earliest timestamp so the ring lands on the first dot, not all of them.
      existing.isNew = existing.isNew || isNew;
      if (ts != null && (existing.earliestMs == null || ts < existing.earliestMs)) {
        existing.earliestMs = ts;
      }
    }
  }
  return stamps;
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Build the nPL for one path + artifact chunk.
 *
 * Shape (validated live at 87ms / 322,927 rows):
 *   <path>="a" OR <path>="b" | eval __h=coalesce(...) | stats dc(__h) as hosts,
 *     count as events, min(time) as first_in_window by <path>
 */
export function buildObservationQuery(path: string, artifacts: string[]): ObservationQuery {
  const predicate = artifacts
    .map((value) => `${path}="${nplQuotedBody(value)}"`)
    .join(' OR ');
  const npl =
    `${predicate} | ${HOST_IDENTITY_EVAL} | ` +
    `stats dc(__h) as hosts, count as events, min(time) as first_in_window by ${path}`;
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
): ObservationQuery[] {
  if (artifacts.length === 0) return [];
  const queries: ObservationQuery[] = [];
  for (const path of paths) {
    for (const batch of chunk(artifacts, OBSERVATION_BATCH_SIZE)) {
      queries.push(buildObservationQuery(path, batch));
    }
  }
  return queries;
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
    `stats dc(__h) as hosts, count as events, min(time) as first_in_window by ${path}`;
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
