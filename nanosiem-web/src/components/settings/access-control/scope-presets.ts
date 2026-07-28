// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * API-key scope presets — the pure, testable half of `ScopeSelector`.
 *
 * A preset is a MATCHER, not a scope list: it is resolved against the live
 * `/api/permissions` catalogue at runtime so it stays in sync with the backend.
 * That resolution is also the failure mode NAN-2226 found — a matcher naming an
 * id (or prefix) the catalogue has never contained contributes NOTHING and says
 * nothing about it. The preset does not error, it just quietly shrinks:
 *
 *   * `endsWith(':read')` — no permission in the system ends in `:read`.
 *   * `startsWith('rules:')` — the real prefix is `rule_repositories:`.
 *   * `events:ingest` / `search:read` — neither has ever existed. They came
 *     from `design-ref/shadcn/settings-data.jsx`, a static UI mock, and were
 *     copied into shipping code as though they were the real catalogue.
 *
 * The "Event ingest" preset was built entirely from that last pair, and is gone
 * rather than corrected: there is no ingest scope to name, because ingestion
 * does not traverse this API at all. Logs arrive over the Vector pipeline (see
 * `nanosiem-api/src/routes.rs`: "Log upload removed - logs go through Vector
 * ingestion pipeline"), so no API key can be scoped to ingest and a preset
 * offering to do so could only mislead.
 *
 * Live in a separate module from the component so `scope-presets.test.ts` can
 * check every id and prefix against the real catalogue without a DOM.
 */

/**
 * The minimal structural view of a catalogue entry a preset matches on.
 * `PermissionInfo` from `@/lib/api` satisfies it; declared locally so this
 * module stays dependency-free and testable under bare `node --test`.
 */
export interface ScopeCandidate {
  id: string;
}

export interface ScopePreset {
  id: string;
  label: string;
  desc: string;
  match: (p: ScopeCandidate) => boolean;
}

/**
 * Resource prefixes the detection CI/CD preset covers: the authored artifacts
 * (`detections:`, `parsers:`) plus the git repositories they sync through.
 * `rule_repositories:` is the real name of what was written as `rules:`.
 */
const DETECTION_CI_PREFIXES = [
  'detections:',
  'rule_repositories:',
  'parsers:',
  'parser_repositories:',
] as const;

export const SCOPE_PRESETS: ScopePreset[] = [
  {
    id: 'readonly',
    label: 'Read-only',
    desc: 'view-only access across resources',
    match: p => p.id.endsWith(':view'),
  },
  {
    id: 'detection-ci',
    label: 'Detection CI/CD',
    desc: 'rules, parsers + their repos',
    match: p => DETECTION_CI_PREFIXES.some(prefix => p.id.startsWith(prefix)),
  },
  {
    id: 'custom',
    label: 'Custom',
    desc: 'pick scopes individually',
    match: () => false,
  },
];

/** Resolve the scope ids a preset matches against the live catalogue. */
export function presetScopeIds(permissions: ScopeCandidate[], presetId: string): string[] {
  const preset = SCOPE_PRESETS.find(p => p.id === presetId);
  if (!preset || preset.id === 'custom') return [];
  return permissions.filter(p => preset.match(p)).map(p => p.id);
}

/** Pick the preset whose resolved scope-set exactly equals `scopes`, else 'custom'. */
export function derivePreset(permissions: ScopeCandidate[], scopes: string[]): string {
  const set = new Set(scopes);
  for (const preset of SCOPE_PRESETS) {
    if (preset.id === 'custom') continue;
    const ids = presetScopeIds(permissions, preset.id);
    if (ids.length > 0 && ids.length === set.size && ids.every(id => set.has(id))) {
      return preset.id;
    }
  }
  return 'custom';
}
