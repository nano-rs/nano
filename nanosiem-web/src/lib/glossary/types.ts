// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: the shape of one glossary entry. See ./index.ts.

export interface GlossaryEntry {
  /** The term as a reader sees it, e.g. "Sweep". Used as the default label. */
  term: string;
  /**
   * One plain sentence, 8th-grade reading level, definition first.
   * "A parser reads raw log lines and turns them into named fields." Not "Parsers let you...".
   */
  short: string;
  /** Optional one or two plain sentences of detail. Keep technical nuance here. */
  more?: string;
  /** A real docs page from DOCS_PAGES below. Never invent a URL. */
  docsHref?: string;
  /**
   * Guard pattern for glossary-guard.test.ts: when this matches JSX text in a
   * component file, that file must wrap the term with <Term id=...> at least
   * once. Only distinctive jargon gets a guard; everyday words (finding,
   * signal) don't, so the guard stays quiet on ordinary sentences.
   */
  guard?: RegExp;
  /**
   * Where the guard applies: path prefixes under src/, such as
   * 'enterprise/pages/Hunts/'. Use it for words that mean something else in
   * other areas ("budget" in hunts vs an SLO error budget). Omitted: the
   * whole app for open-core entries, src/enterprise/ for enterprise entries.
   */
  guardIn?: readonly string[];
}

export type GlossarySection = Readonly<Record<string, GlossaryEntry>>;

/** Give every guarded entry in a section the same guard scope. Keeps literal ids. */
export function scopeGuards<T extends GlossarySection>(guardIn: readonly string[], section: T): T {
  const out: Record<string, GlossaryEntry> = {};
  for (const [id, entry] of Object.entries(section)) out[id] = entry.guard && !entry.guardIn ? { ...entry, guardIn } : entry;
  return out as T;
}

/** The public docs site. Enterprise pages are listed in src/enterprise/lib/glossary/docs.ts. */
export const DOCS = 'https://nano.rs/docs/';

/**
 * Open-core docs pages that exist, checked against https://nano.rs/docs/sitemap.xml
 * on 2026-11-22. A docsHref must be one of these or one of the enterprise
 * pages in src/enterprise/lib/glossary/docs.ts (glossary.test.ts enforces it).
 * Add a page here only after you have loaded it.
 */
export const DOCS_PAGES = {
  ocsf: `${DOCS}concepts/ocsf-schema/`,
  ocsfFields: `${DOCS}reference/ocsf-fields/`,
  searchSyntax: `${DOCS}search-commands/syntax/`,
  searchCommands: `${DOCS}search-commands/`,
  searchQuickReference: `${DOCS}search-commands/quick-reference/`,
  prevalenceCommand: `${DOCS}search-commands/prevalence/`,
  baselineCommand: `${DOCS}search-commands/baseline/`,
  detections: `${DOCS}user-guide/detections/`,
  alerts: `${DOCS}user-guide/alerts/`,
  dashboards: `${DOCS}user-guide/dashboards/`,
  prevalence: `${DOCS}user-guide/prevalence/`,
  retroHunt: `${DOCS}user-guide/retro-hunt/`,
  scheduledReports: `${DOCS}user-guide/scheduled-reports/`,
  parserExtensions: `${DOCS}user-guide/parser-extensions/`,
  dataManagement: `${DOCS}user-guide/data-management/`,
  enrichments: `${DOCS}enrichments/`,
  integrations: `${DOCS}integrations/`,
  routingModel: `${DOCS}integrations/routing-model/`,
  cloudPull: `${DOCS}integrations/cloud-pull/`,
  hec: `${DOCS}integrations/hec/`,
  otlp: `${DOCS}integrations/otlp/`,
  directOcsf: `${DOCS}integrations/direct-ocsf/`,
  pipelines: `${DOCS}pipelines/`,
  pipelineSteps: `${DOCS}pipelines/step-reference/`,
  pipelineLiveCapture: `${DOCS}pipelines/live-capture/`,
  detectionAsCode: `${DOCS}settings/detection-as-code/`,
  settings: `${DOCS}settings/`,
  accessControl: `${DOCS}settings/access-control/`,
  sourceVisibility: `${DOCS}settings/source-visibility/`,
  storage: `${DOCS}settings/storage/`,
  diskPressure: `${DOCS}settings/disk-pressure/`,
  notifications: `${DOCS}settings/notifications/`,
  platformAudit: `${DOCS}settings/platform-audit/`,
  prevalenceSettings: `${DOCS}settings/prevalence/`,
  searchSettings: `${DOCS}settings/search/`,
  airGapped: `${DOCS}getting-started/air-gapped/`,
} as const;

export const KNOWN_DOCS_HREFS: ReadonlySet<string> = new Set(Object.values(DOCS_PAGES));
