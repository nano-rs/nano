// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — view-model helpers for the redesigned Parser Repositories page.
//
// The mockup carries fields that don't exist on the real `RepositoryParser` /
// `ParserRepository` shapes (per-parser transport, test runs, schema field
// list, drift detail, fine-grained import-mode state on the parser row). These
// helpers fold what the API does provide into the shape the new components
// consume, and gracefully default the rest.

import type {
  ParserRepository,
  ParserUpstreamUpdate,
  RepositoryParser,
} from '@/lib/api/parser-repositories';

export type RepoParserStatus =
  | 'AVAILABLE'
  | 'UPDATED'
  | 'IMPORTED'
  | 'DRIFT'
  | 'DELETED';

export type RepoTransport =
  | 'http'
  | 'vector'
  | 's3'
  | 'pubsub'
  | 'syslog'
  | 'kafka'
  | 'splunk_hec';

// Categories surface as colored chips. The set is deliberately small so the
// palette stays readable; anything else falls back to a neutral chip.
export type RepoParserCategory =
  | 'cloud'
  | 'security'
  | 'network'
  | 'endpoint'
  | 'web'
  | 'identity'
  | 'database'
  | 'application';

export interface RepoParserView {
  id: string;
  name: string;
  desc: string;
  path: string;
  status: RepoParserStatus;
  category: string | null;
  vendor: string | null;
  product: string | null;
  version: string | null;
  importedVersion: string | null;
  upstreamVersion: string | null;
  importMode: 'linked' | 'forked' | null;
  transport: RepoTransport | null;
  sourceType: string;
  commit: string;
  author: string;
  updated: string;
  raw: RepositoryParser;
  upstream?: ParserUpstreamUpdate;
}

export interface ParserRepoView {
  id: string;
  slug: string;
  org: string;
  name: string;
  url: string;
  branch: string;
  visibility: 'public' | 'private';
  builtin: boolean;
  total: number;
  counts: {
    available: number;
    needsUpdate: number;
    imported: number;
    drift: number;
    deleted: number;
  };
  lastCommit: { sha: string };
  lastSync: { ts: string | null; relative: string; result: 'ok' | 'warn' | 'failed' | 'pending' };
  nextSync: { in: string; cadence: string };
  autoSync: 'off' | 'hourly' | '4h' | 'daily';
  raw: ParserRepository;
}

export interface CategoryCount {
  id: 'all' | 'updated' | 'available' | 'imported' | 'drift' | 'deleted';
  label: string;
  count: number;
}

// ------------------------------------------------------------------
// Repo helpers
// ------------------------------------------------------------------

export function deriveSlug(repo: ParserRepository): { slug: string; org: string; name: string } {
  const m = repo.url.match(/[:/]([^/:]+)\/([^/]+?)(?:\.git)?$/);
  if (m) return { slug: `${m[1]}/${m[2]}`, org: m[1], name: m[2] };
  const slug = repo.slug || repo.name;
  const parts = slug.split('/');
  return parts.length >= 2
    ? { slug, org: parts[0], name: parts.slice(1).join('/') }
    : { slug, org: '', name: slug };
}

function shortSha(sha: string | null | undefined): string {
  return (sha || '').slice(0, 7) || '—';
}

function formatRelative(ts: string | null | undefined, nowMs = Date.now()): string {
  if (!ts) return 'never';
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return 'never';
  const sec = Math.max(0, Math.floor((nowMs - t) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function cadenceFromHours(hours: number | null | undefined): ParserRepoView['autoSync'] {
  if (!hours) return 'off';
  if (hours <= 1) return 'hourly';
  if (hours <= 4) return '4h';
  return 'daily';
}

function nextSyncIn(repo: ParserRepository, nowMs = Date.now()): string {
  if (!repo.auto_sync_enabled || !repo.last_synced_at) return '—';
  const last = Date.parse(repo.last_synced_at);
  if (Number.isNaN(last)) return '—';
  const next = last + (repo.sync_interval_hours || 1) * 3600 * 1000;
  const diff = Math.max(0, next - nowMs);
  const min = Math.floor(diff / 60000);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

export function buildRepoView(
  repo: ParserRepository,
  parsers: RepositoryParser[],
  upstream: ParserUpstreamUpdate[],
  nowMs = Date.now(),
): ParserRepoView {
  const { slug, org, name } = deriveSlug(repo);
  const imported = parsers.filter((p) => p.is_imported).length;
  const available = Math.max(0, parsers.length - imported);
  const needsUpdate = upstream.filter((u) => u.import_type !== 'forked').length;
  const drift = upstream.filter((u) => u.import_type === 'forked').length;
  const lastSyncResult: ParserRepoView['lastSync']['result'] =
    repo.last_sync_status === 'success'
      ? 'ok'
      : repo.last_sync_status === 'failed'
        ? 'failed'
        : repo.last_sync_status === 'syncing'
          ? 'pending'
          : 'pending';
  const isNanoBuiltin = /\bnanos?-sh\/parsers\b/.test(repo.url) || /\bnanos?-sh\/parsers\b/.test(slug);
  return {
    id: repo.id,
    slug,
    org,
    name,
    url: repo.url,
    branch: repo.branch || 'main',
    // Backend doesn't surface visibility yet — assume public unless URL is
    // a known private host. Consumers can override once that lands.
    visibility: 'public',
    builtin: isNanoBuiltin,
    total: repo.parser_count || parsers.length,
    counts: {
      available,
      imported,
      needsUpdate,
      drift,
      deleted: 0, // backend doesn't yet track upstream deletions for parsers
    },
    lastCommit: { sha: shortSha(repo.last_sync_commit) },
    lastSync: {
      ts: repo.last_synced_at,
      relative: formatRelative(repo.last_synced_at, nowMs),
      result: lastSyncResult,
    },
    nextSync: {
      in: nextSyncIn(repo, nowMs),
      cadence: cadenceFromHours(repo.sync_interval_hours),
    },
    autoSync: cadenceFromHours(repo.sync_interval_hours),
    raw: repo,
  };
}

// ------------------------------------------------------------------
// Parser helpers
// ------------------------------------------------------------------

const TRANSPORT_HINTS: Array<[RegExp, RepoTransport]> = [
  [/(^|_)s3(_|$)/i, 's3'],
  [/(^|_)pubsub|gcp/i, 'pubsub'],
  [/(^|_)kafka/i, 'kafka'],
  [/(^|_)splunk/i, 'splunk_hec'],
  [/(^|_)syslog|fortinet|cisco|paloalto|juniper/i, 'syslog'],
  [/(^|_)windows|sysmon|defender|vector_/i, 'vector'],
];

/** Heuristic transport inference from path/source-type until backend exposes it. */
export function inferTransport(parser: RepositoryParser): RepoTransport | null {
  const hay = `${parser.file_path} ${parser.name ?? ''}`.toLowerCase();
  for (const [re, t] of TRANSPORT_HINTS) {
    if (re.test(hay)) return t;
  }
  return 'http';
}

export function buildParserView(
  parser: RepositoryParser,
  upstreamByPath: Map<string, ParserUpstreamUpdate>,
  fallbackCommit: string,
): RepoParserView {
  const upstream = upstreamByPath.get(parser.file_path);
  const importMode: RepoParserView['importMode'] = upstream
    ? upstream.import_type === 'forked'
      ? 'forked'
      : 'linked'
    : parser.is_imported
      ? 'linked' // best-effort default; backend doesn't expose it on parser row
      : null;
  const status: RepoParserStatus = upstream && parser.is_imported
    ? importMode === 'forked'
      ? 'DRIFT'
      : 'UPDATED'
    : parser.is_imported
      ? 'IMPORTED'
      : 'AVAILABLE';

  const name =
    parser.display_name?.trim() ||
    parser.name?.trim() ||
    parser.file_path.split('/').pop()?.replace(/\.ya?ml$/i, '') ||
    parser.file_path;

  const sourceType = parser.name?.trim() || name;

  return {
    id: parser.id,
    name,
    desc: parser.description?.trim() || '—',
    path: parser.file_path,
    status,
    category: parser.category,
    vendor: parser.vendor,
    product: parser.product,
    version: parser.version,
    importedVersion: upstream?.version ?? null,
    upstreamVersion: upstream?.version ?? null,
    importMode,
    transport: inferTransport(parser),
    sourceType,
    commit: shortSha(parser.file_sha || fallbackCommit),
    author: '',
    updated: formatRelative(parser.updated_at),
    raw: parser,
    upstream,
  };
}

export function categoryCounts(parsers: RepoParserView[]): CategoryCount[] {
  const byStatus = (s: RepoParserStatus) => parsers.filter((p) => p.status === s).length;
  return [
    { id: 'all', label: 'All', count: parsers.length },
    { id: 'updated', label: 'Needs update', count: byStatus('UPDATED') },
    { id: 'available', label: 'Available', count: byStatus('AVAILABLE') },
    { id: 'imported', label: 'Imported', count: byStatus('IMPORTED') },
    { id: 'drift', label: 'Drift', count: byStatus('DRIFT') },
    { id: 'deleted', label: 'Removed', count: byStatus('DELETED') },
  ];
}

/** Pick a folder label for a file path: `parsers/aws_cloudtrail/parser.yaml` → `parsers/aws_cloudtrail`. */
export function folderOf(filePath: string): string {
  const parts = filePath.split('/');
  return parts.length > 1 ? parts.slice(0, -1).join('/') : '';
}
