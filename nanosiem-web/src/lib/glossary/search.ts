// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: Search, dashboards, alerts, reports and observability terms (open core).
// Plain English, 8th-grade reading level, definition first. See src/lib/glossary/types.ts.

import { DOCS_PAGES, type GlossarySection } from './types';

/** Observability words ("budget", "span", "monitor") mean other things elsewhere. */
const OBSERVABILITY = ['pages/observability/', 'components/observability/'] as const;
/** Search, alert and case surfaces, where these words carry the meaning below. */
const SEARCH_SURFACES = ['pages/Search', 'components/search/', ...OBSERVABILITY] as const;
const TRIAGE_SURFACES = ['pages/Alerts', 'components/alerts/', 'components/observability/'] as const;

export const SEARCH_GLOSSARY = {
  // ── Search ────────────────────────────────────────────────────────────────
  dataset: {
    term: 'Dataset',
    short: 'The dataset is the kind of data a search reads: logs, traces, metrics, risk or signals.',
    more: 'Logs is the default. Signals holds every time a detection rule matched.',
    docsHref: DOCS_PAGES.searchSyntax,
  },
  trace: {
    term: 'Trace',
    short: 'A trace follows one request as it moves through your apps and services.',
    more: 'Each step in a trace is a span.',
    docsHref: DOCS_PAGES.otlp,
  },
  span: {
    term: 'Span',
    short: 'A span is one step in a trace, such as one call to a database, with its start time and how long it took.',
    docsHref: DOCS_PAGES.otlp,
  },
  'core-field': {
    term: 'Core field',
    short: 'A core field is a main OCSF field that nano stores in its own column, so searches on it are fast.',
  },
  'extended-field': {
    term: 'Extended field',
    short: "An extended field is a valid field kept inside the event's stored data instead of its own column, so searches on it are slower.",
  },
  'base-scan': {
    term: 'Base scan',
    short: 'Base scan shows the fields of the events your search matched, before any | commands changed them.',
  },
  rarity: {
    term: 'Rarity',
    short: 'Rarity shows how few hosts have seen a value, such as a file hash, domain or IP.',
    more: 'Rare values are worth a closer look.',
    docsHref: DOCS_PAGES.prevalence,
    guard: /\brarity\b/i,
    guardIn: SEARCH_SURFACES,
  },
  tail: {
    term: 'tail -f',
    short: 'tail -f keeps the search running and adds new events as they arrive.',
    guard: /\btail -f\b/,
  },
  'saved-query': {
    term: 'Saved query',
    short: 'A saved query is a search you saved by name so you or your team can run it again.',
    guard: /\bsaved quer(y|ies)\b/i,
  },
  'generated-sql': {
    term: 'Generated SQL',
    short: 'Generated SQL is the database query nano built from your search, so you can see exactly what ran.',
    guard: /\bgenerated SQL\b/i,
  },
  'search-job': {
    term: 'Search job',
    short: 'A search job is a search that runs in the background, and its results are kept for 24 hours.',
    more: 'When the server is busy, new searches wait in a queue for a free slot.',
    guard: /\bsearch jobs?\b/i,
  },
  maxspan: {
    term: 'maxspan',
    short: 'maxspan is the longest time allowed from the first event to the last in one group of events.',
    docsHref: DOCS_PAGES.searchCommands,
    guard: /\bmaxspan\b/,
  },
  transaction: {
    term: 'Transaction',
    short: 'A transaction groups related events, such as one login session, into a single row.',
    docsHref: DOCS_PAGES.searchCommands,
  },
  sequence: {
    term: 'Sequence',
    short: 'A sequence finds events that happen in a set order, such as a failed login and then a success.',
    docsHref: DOCS_PAGES.searchCommands,
  },
  funnel: {
    term: 'Funnel',
    short: 'A funnel counts how many users or hosts reach each step of a chain and where they drop off.',
    docsHref: DOCS_PAGES.searchCommands,
  },
  lolbin: {
    term: 'LOLBin',
    short: 'A LOLBin is a normal system program that attackers often misuse, such as certutil or rundll32.',
    more: 'The name is short for "living off the land binary".',
    guard: /\blolbins?\b/i,
  },
  'cached-result': {
    term: 'Cached',
    short: 'Cached means these results were saved from an earlier run of the same search.',
    more: 'Refresh to run the search again.',
  },
  'retro-match': {
    term: 'Retro match',
    short: 'A retro match means a threat indicator learned later was found in older events.',
    docsHref: DOCS_PAGES.retroHunt,
  },

  // ── Alerts ────────────────────────────────────────────────────────────────
  alert: {
    term: 'Alert',
    short: 'An alert is raised when a rule in Alerting mode matches events, so an analyst can review it.',
    more: 'By default one alert holds all the matches from one run of the rule. Some rules raise one alert per event instead.',
    docsHref: DOCS_PAGES.alerts,
  },
  'alert-status': {
    term: 'Status',
    short: 'An alert moves from New (not looked at) to Acknowledged (someone is on it) to Closed (done).',
    docsHref: DOCS_PAGES.alerts,
  },
  disposition: {
    term: 'Disposition',
    short: 'The disposition is the final verdict you give when you close an alert, such as true positive or false positive.',
    more: 'True positive means a real threat, false positive means the rule was wrong, and benign means real but harmless activity.',
    docsHref: DOCS_PAGES.alerts,
    guard: /\bdisposition\b/i,
    guardIn: TRIAGE_SURFACES,
  },
  'detection-latency': {
    term: 'Latency',
    short: 'Latency is how long it took from the event happening to the alert being raised.',
    docsHref: DOCS_PAGES.alerts,
  },

  // ── Dashboards and reports ───────────────────────────────────────────────
  panel: {
    term: 'Panel',
    short: 'A panel is one chart or table on a dashboard, and each panel runs its own search.',
    docsHref: DOCS_PAGES.dashboards,
  },
  drilldown: {
    term: 'Drilldown',
    short: 'Drilldown lets you click a point in a chart to open the matching events in Search.',
    docsHref: DOCS_PAGES.dashboards,
    guard: /\bdrill ?down\b/i,
  },
  'dashboard-variable': {
    term: 'Variable',
    short: 'A dashboard variable is a value you pick at the top of the dashboard, such as a host, that every panel can use.',
    more: 'Use it in a panel query as $name.',
    docsHref: DOCS_PAGES.dashboards,
  },
  'dashboard-visibility': {
    term: 'Visibility',
    short: 'Visibility sets who can see a dashboard: only you, chosen groups, or everyone who can view dashboards.',
    docsHref: DOCS_PAGES.dashboards,
  },
  'scheduled-report': {
    term: 'Scheduled report',
    short: 'A scheduled report runs a search on a timer and saves or sends the results.',
    docsHref: DOCS_PAGES.scheduledReports,
    guard: /\bscheduled reports?\b/i,
  },
  'report-artifact': {
    term: 'Artifact',
    short: 'An artifact is a file a report run produced, such as a CSV of the results.',
    docsHref: DOCS_PAGES.scheduledReports,
  },

  // ── Observability ─────────────────────────────────────────────────────────
  slo: {
    term: 'SLO',
    short: 'An SLO (service level objective) is a goal for how reliable or fast a service should be, such as 99.9% of requests succeeding.',
    guard: /\bSLOs?\b/,
    guardIn: OBSERVABILITY,
  },
  sli: {
    term: 'SLI',
    short: 'The SLI (service level indicator) is what an SLO measures: whether requests succeed, or whether they are fast enough.',
    guard: /\bSLI\b/,
    guardIn: OBSERVABILITY,
  },
  'error-budget': {
    term: 'Error budget',
    short: 'The error budget is the share of requests an SLO allows to fail or run too slowly in its window, which is 100% minus the target.',
    more: 'For a 99.9% target, the budget is 0.1% of requests.',
    guard: /\b(error[- ])?budget\b/i,
    guardIn: OBSERVABILITY,
  },
  'burn-rate': {
    term: 'Burning budget',
    short: 'An SLO is burning its budget when less than a quarter of its error budget is left or its target is already missed.',
    guard: /\bburning budget\b/i,
    guardIn: OBSERVABILITY,
  },
  p75: {
    term: 'p75',
    short: 'p75 is the value that 75% of page loads are at or under, so it shows what most visitors experience.',
  },
  rum: {
    term: 'RUM',
    short: 'RUM (real user monitoring) measures what real visitors see in your web app: page views, speed and errors.',
    guard: /\bRUM\b/,
    guardIn: OBSERVABILITY,
  },
  lcp: {
    term: 'LCP',
    short: 'LCP (largest contentful paint) is how long a page takes to show its main content, and lower is better.',
    guard: /\bLCP\b/,
    guardIn: OBSERVABILITY,
  },
  'synthetic-check': {
    term: 'Synthetic check',
    short: 'A synthetic check requests a URL on a schedule and checks that it answers with the expected status code.',
    guard: /\bsynthetic checks?\b/i,
    guardIn: OBSERVABILITY,
  },
  'metric-monitor': {
    term: 'Monitor',
    short: 'A monitor watches a metric and raises an alert when it crosses a threshold you set.',
    guard: /\bmonitors?\b/i,
    guardIn: ['components/observability/MetricMonitor'],
  },
  'exemplar-trace': {
    term: 'Exemplar trace',
    short: 'An exemplar trace is a sample request picked to show a problem, such as the slowest one or one with an error.',
    guard: /\bexemplar traces?\b/i,
    guardIn: OBSERVABILITY,
  },
} as const satisfies GlossarySection;
