// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 — view-model helpers for the redesigned Rule Repositories page.
//
// The mockup carries fields that don't exist on the real `RepositoryRule` /
// `RuleRepository` shapes (per-rule commit, author, NEW vs AVAILABLE, drift,
// test-run sparkline). These helpers fold what we do have into the shape the
// new components consume, and gracefully default the rest.

import type {
  RepositoryRule,
  RuleRepository,
  UpdatedRule,
} from '@/lib/api/rule-repositories';

export type RepoRuleStatus =
  | 'NEW'
  | 'UPDATED'
  | 'IMPORTED'
  | 'DRIFT'
  | 'DELETED'
  | 'AVAILABLE';

export type RepoSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface RepoRuleView {
  id: string;
  name: string;
  desc: string;
  path: string;
  status: RepoRuleStatus;
  severity: RepoSeverity;
  mitre: string[];
  source: string;
  destSource: string;
  commit: string;
  author: string;
  updated: string;
  raw: RepositoryRule;
  // present only when in `getUpstreamUpdates`
  upstream?: UpdatedRule;
}

export interface RepoView {
  id: string;
  slug: string;
  org: string;
  name: string;
  url: string;
  branch: string;
  visibility: 'public' | 'private';
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
  raw: RuleRepository;
}

const SEV_SET: ReadonlySet<RepoSeverity> = new Set(['critical', 'high', 'medium', 'low']);

export function normalizeSeverity(s: string | null | undefined): RepoSeverity {
  const lc = (s || '').toLowerCase();
  return SEV_SET.has(lc as RepoSeverity) ? (lc as RepoSeverity) : 'unknown';
}

export function deriveSlug(repo: RuleRepository): { slug: string; org: string; name: string } {
  // Pull org/name from URL if it looks like a github/gitlab URL, else fall back
  // to the slug/name on the record.
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

function cadenceFromHours(hours: number | null | undefined): RepoView['autoSync'] {
  if (!hours) return 'off';
  if (hours <= 1) return 'hourly';
  if (hours <= 4) return '4h';
  return 'daily';
}

function nextSyncIn(repo: RuleRepository, nowMs = Date.now()): string {
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
  repo: RuleRepository,
  rules: RepositoryRule[],
  upstream: UpdatedRule[],
  nowMs = Date.now(),
): RepoView {
  const { slug, org, name } = deriveSlug(repo);
  const imported = rules.filter((r) => r.is_imported).length;
  const upstreamModified = upstream.filter((u) => u.change_type === 'modified').length;
  const upstreamDeleted = upstream.filter((u) => u.change_type === 'deleted').length;
  const available = Math.max(0, rules.length - imported);
  const lastSyncResult: RepoView['lastSync']['result'] =
    repo.last_sync_status === 'success'
      ? 'ok'
      : repo.last_sync_status === 'failed'
        ? 'failed'
        : repo.last_sync_status === 'syncing'
          ? 'pending'
          : 'pending';
  return {
    id: repo.id,
    slug,
    org,
    name,
    url: repo.url,
    branch: repo.branch || 'main',
    // The API doesn't surface visibility yet; private GitHub URLs are still
    // treated as public from the UI's POV until that lands.
    visibility: 'public',
    total: repo.rule_count || rules.length,
    counts: {
      available,
      imported,
      needsUpdate: upstreamModified,
      drift: 0, // requires per-rule diff — see NAN-504 scope notes
      deleted: upstreamDeleted,
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

export function buildRuleView(
  rule: RepositoryRule,
  upstreamByPath: Map<string, UpdatedRule>,
  fallbackCommit: string,
): RepoRuleView {
  const upstream = upstreamByPath.get(rule.file_path);
  const status: RepoRuleStatus = upstream
    ? upstream.change_type === 'deleted'
      ? 'DELETED'
      : 'UPDATED'
    : rule.is_imported
      ? 'IMPORTED'
      : 'AVAILABLE';
  const source = rule.requires_source_types?.[0] || '—';
  const mitre: string[] = [
    ...(rule.mitre_techniques || []),
    ...(rule.mitre_tactics || []),
  ];
  const name = rule.title?.trim() || rule.file_path.split('/').pop()?.replace(/\.ya?ml$/i, '') || rule.file_path;
  return {
    id: rule.id,
    name,
    desc: rule.description?.trim() || '—',
    path: rule.file_path,
    status,
    severity: normalizeSeverity(rule.severity),
    mitre,
    source,
    destSource: source,
    commit: shortSha(rule.file_sha || fallbackCommit),
    author: '',
    updated: formatRelative(rule.updated_at),
    raw: rule,
    upstream,
  };
}

export const STATUS_LABEL: Record<RepoRuleStatus, string> = {
  NEW: 'NEW',
  UPDATED: 'UPDATED',
  IMPORTED: 'IMPORTED',
  DRIFT: 'DRIFT',
  DELETED: 'DELETED',
  AVAILABLE: 'AVAILABLE',
};

export interface CategoryCount {
  id: 'all' | 'new' | 'updated' | 'imported' | 'drift' | 'deleted';
  label: string;
  count: number;
}

export function categoryCounts(rules: RepoRuleView[]): CategoryCount[] {
  const byStatus = (s: RepoRuleStatus) => rules.filter((r) => r.status === s).length;
  return [
    { id: 'all', label: 'All', count: rules.length },
    { id: 'new', label: 'New', count: byStatus('NEW') },
    { id: 'updated', label: 'Updates', count: byStatus('UPDATED') },
    { id: 'imported', label: 'Imported', count: byStatus('IMPORTED') },
    { id: 'drift', label: 'Drift', count: byStatus('DRIFT') },
    { id: 'deleted', label: 'Deleted', count: byStatus('DELETED') },
  ];
}

// ------------------------------------------------------------------
// NPL source-type synthesis — rewrites `source_type=X` patterns in a
// proposed query before we ship it as `custom_npl`. Lifted from the old
// ImportRuleModal so per-rule individual mappings keep working.
// ------------------------------------------------------------------

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Apply per-source-type mappings (individual mode). Skips empty / `__skip__`. */
export function applySourceTypeMappings(
  query: string,
  mappings: Record<string, string>,
): string {
  let out = query;
  for (const [original, replacement] of Object.entries(mappings)) {
    if (!replacement || replacement === '__skip__') continue;
    const esc = escapeRegExp(original);
    const patterns = [
      new RegExp(`source_type\\s*=\\s*"${esc}"`, 'gi'),
      new RegExp(`source_type\\s*=\\s*'${esc}'`, 'gi'),
      new RegExp(`source_type\\s*=\\s*${esc}(?![a-zA-Z0-9_-])`, 'gi'),
    ];
    for (const p of patterns) out = out.replace(p, `source_type=${replacement}`);
  }
  return out;
}

/** Collapse the entire `source_type=A OR source_type=B …` chain to a single value. */
export function applyMergedSourceType(query: string, merged: string): string {
  if (!merged) return query;
  const chain = /\(?source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?(?:\s+OR\s+source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?)+\)?/gi;
  let out = query.replace(chain, `source_type=${merged}`);
  if (out === query) {
    // Fallback: rule has a single `source_type=X` predicate (no OR-chain).
    // Replace only the first occurrence so a stray reference later in the
    // pipeline (`stats by source_type=foo` etc.) isn't rewritten too.
    const single = /source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?/i;
    out = query.replace(single, `source_type=${merged}`);
  }
  return out;
}

/** Pick a folder label for a file path: `windows/process_creation/foo.yml` → `windows/process_creation`. */
export function folderOf(filePath: string): string {
  const parts = filePath.split('/');
  return parts.length > 1 ? parts.slice(0, -1).join('/') : '';
}
