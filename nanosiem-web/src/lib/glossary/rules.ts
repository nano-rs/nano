// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: Rules, MITRE coverage, retro hunt, lookups and detection-as-code terms (open core).
// Plain English, 8th-grade reading level, definition first. See src/lib/glossary/types.ts.
//
// Meanings follow nanosiem-core/src/models/detection_rule.rs (modes, alert
// mode, cooldown), src/components/mitre/layers.ts (coverage classes) and the
// rules pages themselves.

import { DOCS_PAGES, type GlossarySection } from './types';

/** Where rules words like "lookback" or "baseline" mean the rules thing. */
const RULE_SURFACES = ['pages/Rules', 'pages/Matches', 'pages/RetroHunt', 'components/rules/', 'components/rule-editor/', 'components/matches/'] as const;
const COVERAGE_SURFACES = ['pages/MitreCoverage', 'components/mitre/'] as const;

export const RULES_GLOSSARY = {

  // ── MITRE coverage ─────────────────────────────────────────────────────
  'live-rule-coverage': {
    term: 'Live-rule coverage',
    short: 'Live-rule coverage is the share of ATT&CK techniques that have at least one rule in Live or Alerting mode.',
    more: 'Staging and paused rules show up but never count, and each sub-technique counts on its own.',
    guard: /\blive-rule coverage\b/i,
  },
  'cov-detected': {
    term: 'Detected',
    short: 'Detected means at least one rule in Live or Alerting mode covers this technique.',
  },
  'cov-telemetry-no-rule': {
    term: 'Telemetry, no rule',
    short: 'Telemetry, no rule means the data you need to see this technique is coming in, but no live rule covers it yet.',
    guard: /\btelemetry, no rule\b/i,
    guardIn: COVERAGE_SURFACES,
  },
  'cov-blind': {
    term: 'Blind',
    short: 'Blind means no live rule covers this technique and none of the data needed to see it is coming in.',
  },
  'cov-unmapped': {
    term: 'Unmapped',
    short: "Unmapped means nano can't tell which of your log sources would show this technique.",
    more: 'Either ATT&CK lists no data for it, or nano has no mapping for that data yet.',
  },
  'rule-no-telemetry': {
    term: 'Rule, no telemetry',
    short: "Rule, no telemetry means a live rule exists, but none of the data it needs arrived in the last 60 minutes, so it can't fire.",
    guard: /\brule, no telemetry\b/i,
    guardIn: COVERAGE_SURFACES,
  },
  'telemetry-state': {
    term: 'Telemetry state',
    short: 'Telemetry state shows whether the data for a technique is coming in: active (arriving now), stale (set up but quiet) or none (not set up).',
  },
  'sub-technique': {
    term: 'Sub-technique',
    short: 'A sub-technique is a more specific form of a technique, such as T1110.003 (password spraying) under T1110 (brute force).',
    guard: /\bsub-techniques?\b/i,
    guardIn: COVERAGE_SURFACES,
  },
  'data-component': {
    term: 'Data component',
    short: 'A data component is a kind of data ATT&CK says you need to see a technique, such as process creation or user sign-ins.',
    guard: /\bdata components?\b/i,
    guardIn: COVERAGE_SURFACES,
  },
  'techniques-unblinded': {
    term: 'Techniques unblinded',
    short: 'Techniques unblinded is how many blind techniques would get the data they need if you added this source.',
    guard: /\bunblinded\b/i,
    guardIn: COVERAGE_SURFACES,
  },
  'dropped-mapping': {
    term: 'Dropped mapping',
    short: "A dropped mapping is a rule's ATT&CK tag that a catalog update removed, so that rule no longer counts toward coverage.",
  },

  // ── Rules list and editor ──────────────────────────────────────────────
  'rule-severity': {
    term: 'Severity',
    short: 'Severity is how serious a match is, from informational up to critical, and it sets how urgently its alerts are handled.',
  },
  'silent-rule': {
    term: 'Silent rule',
    short: 'A silent rule is a running rule that has not matched anything in over 30 days, or ever.',
    more: 'It may be broken, or the data it needs may have stopped.',
    guard: /\bsilent rules?\b/i,
    guardIn: RULE_SURFACES,
  },
  'fleet-health': {
    term: 'Fleet health',
    short: 'Fleet health is the share of scheduled Live and Alerting rules that are running on time without errors.',
    more: 'Slow means its latest measured run took 5 seconds or more. Errors means it is more than 5 minutes overdue or its runs are failing.',
    guard: /\bfleet health\b/i,
  },
  'schedule-lag': {
    term: 'Lag',
    short: 'Lag is how long a scheduled rule that is due has been waiting for its run.',
    more: 'Behind counts rules waiting past a short grace period, and max is the longest wait. p95 means 95 out of 100 rules wait no longer than this.',
  },
  'retro-hunt': {
    term: 'Retro hunt',
    short: 'A retro hunt checks newly published threat intel against your past logs, to find attacks that happened before the intel existed.',
    docsHref: DOCS_PAGES.retroHunt,
    guard: /\bretro[- ]hunts?\b/i,
    guardIn: RULE_SURFACES,
  },
  'rule-lookback': {
    term: 'Lookback',
    short: 'Lookback is how far back in time a rule reads each time it runs, such as the last 15 minutes.',
    guard: /\blookback\b/i,
    guardIn: RULE_SURFACES,
  },
  'rule-dataset': {
    term: 'Dataset',
    short: 'The dataset is the kind of data a rule searches, such as logs, trace spans or metrics.',
    more: 'Only logs can run in real time; the others run on a schedule.',
  },
  'rule-cron': {
    term: 'Cron expression',
    short: 'A cron expression sets when a scheduled rule runs, using five fields: minute, hour, day of month, month and day of week.',
    more: 'For example, */5 * * * * means every 5 minutes.',
  },
  'rule-alert-mode': {
    term: 'Alert mode',
    short: 'Alert mode sets how matches become alerts: grouped (the default) puts every match from one run in one alert, and per event makes one alert for each matched event.',
  },
  'archived-rule': {
    term: 'Archived',
    short: 'An archived rule is stopped and read-only, but its matches, alerts and signals are kept.',
  },

  // ── Matches ────────────────────────────────────────────────────────────
  'rule-match': {
    term: 'Match',
    short: "A match is one time a rule's search found events that meet all of its conditions.",
  },
  'aggregate-match': {
    term: 'Aggregate match',
    short: 'An aggregate match is when a rule that counts events (with stats) crossed its limit for one user, host or IP.',
  },
  'contributing-events': {
    term: 'Contributing events',
    short: 'Contributing events are the raw log events that made the rule match.',
    guard: /\bcontributing events\b/i,
    guardIn: RULE_SURFACES,
  },
  'rule-condition': {
    term: 'Condition',
    short: "A condition is one test in the rule's search, such as status=500, and an event must pass every condition to match.",
    guard: /\brule conditions?\b/i,
    guardIn: RULE_SURFACES,
  },
  'match-baseline': {
    term: 'Baseline',
    short: "The baseline is this rule's normal number of matches from an earlier period, so you can spot a sudden jump or drop.",
    guard: /\bbaseline\b/i,
    guardIn: RULE_SURFACES,
  },
  'alert-rate': {
    term: 'Alert rate',
    short: 'Alert rate is the share of matches that became alerts.',
    guard: /\balert rate\b/i,
    guardIn: RULE_SURFACES,
  },
  'fp-disposition': {
    term: 'Disposition FP',
    short: 'Disposition FP counts this rule\'s matches that analysts marked as false positives: matches on harmless activity.',
  },
  mttd: {
    term: 'Mean time to detect',
    short: 'Mean time to detect is the average time from when an event happened to when this rule matched it.',
    guard: /\bmean time to detect\b/i,
    guardIn: RULE_SURFACES,
  },

  // ── Lookups and repositories ───────────────────────────────────────────
  'lookup-table': {
    term: 'Lookup table',
    short: 'A lookup table is a list you upload, like a spreadsheet, that searches and rules can use to add or check values.',
    more: 'For example, a table of office IP ranges can label each event with its site.',
    guard: /\blookup tables?\b/i,
    guardIn: ['pages/LookupTables', 'pages/LookupTableCreate'],
  },
  'lookup-primary-key': {
    term: 'Primary key',
    short: 'The primary key is the column that names each row, such as ip or user, so lookups and edits find the right row.',
    guard: /\bprimary key\b/i,
    guardIn: ['pages/LookupTable'],
  },
  'detection-as-code': {
    term: 'Detection-as-code',
    short: 'Detection-as-code means keeping rules as files in Git, so every change is reviewed and tracked like code.',
    docsHref: DOCS_PAGES.detectionAsCode,
    guard: /\bdetection-as-code\b/i,
  },
  'rule-repository': {
    term: 'Rule repository',
    short: 'A rule repository is a Git repo of ready-made rules that nano syncs, so you can pick rules and import them.',
    docsHref: DOCS_PAGES.detectionAsCode,
  },
  'push-target': {
    term: 'Push target',
    short: 'A push target is your own Git repo where nano opens a pull request when it proposes a rule change, so you review it like code.',
    more: 'After you merge it, your own pipeline deploys the rule.',
    docsHref: DOCS_PAGES.detectionAsCode,
    guard: /\bpush targets?\b/i,
  },
  'rule-upstream': {
    term: 'Upstream',
    short: 'Upstream is the original version of a rule in the repository you imported it from.',
  },
  'rule-drift': {
    term: 'Drift',
    short: 'Drift means your copy of an imported rule no longer matches the version in its repository.',
    guard: /\bdrift\b/i,
    guardIn: ['pages/RuleRepositories', 'components/repositories/'],
  },
  'source-mapping': {
    term: 'Source mapping',
    short: 'Source mapping swaps the log source types an imported rule expects for the ones you actually collect.',
    guard: /\bsource mapping\b/i,
    guardIn: ['pages/RuleRepositories', 'components/repositories/'],
  },
  'retro-watermark': {
    term: 'Watermark',
    short: 'The watermark is how far through the threat intel the last run got, so the next run picks up from there.',
    guard: /\bwatermark\b/i,
    guardIn: ['pages/RetroHunt'],
  },
} as const satisfies GlossarySection;
