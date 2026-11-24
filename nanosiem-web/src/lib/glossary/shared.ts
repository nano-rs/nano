// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: terms used across many areas of the app (open core). Area-specific
// terms live in their area's section file. Every `short` is one plain sentence
// at an 8th-grade reading level, definition first.

import { DOCS_PAGES, type GlossarySection } from './types';

export const SHARED_GLOSSARY = {
  ocsf: {
    term: 'OCSF',
    short: 'OCSF is a shared standard for how security logs are laid out, so the same field means the same thing in every source.',
    more: 'It stands for Open Cybersecurity Schema Framework. nano stores every event in OCSF fields.',
    docsHref: DOCS_PAGES.ocsf,
    guard: /\bOCSF\b/,
  },
  npl: {
    term: 'nPL',
    short: 'nPL is the search language in nano: a search, then commands joined by a pipe ( | ).',
    more: 'For example: failed login | stats count by user.',
    docsHref: DOCS_PAGES.searchSyntax,
    guard: /\bnPL\b/,
  },
  signal: {
    term: 'Signal',
    short: 'A signal is a saved record that a detection rule matched an event.',
    more: 'Signals are searchable, so you can see every time a rule fired, even when it made no alert.',
  },
  'detection-rule': {
    term: 'Detection rule',
    short: 'A detection rule is a saved search that runs on its own and flags events that look like an attack.',
    docsHref: DOCS_PAGES.detections,
  },
  'rule-mode': {
    term: 'Rule mode',
    short: 'A rule mode sets what a rule does when it matches: nothing yet, count only, or raise alerts.',
    more: 'Rules usually move from Staging to Live to Alerting. Paused stops the rule.',
  },
  'mode-staging': {
    term: 'Staging',
    short: 'Staging means the rule is still being written, so it does not run.',
  },
  'mode-live': {
    term: 'Live',
    short: 'Live means the rule runs and counts its matches, but it does not raise alerts yet.',
    more: 'Use it to test a rule on real data before it can page anyone.',
  },
  'mode-alerting': {
    term: 'Alerting',
    short: 'Alerting means the rule runs and raises alerts when it matches.',
    more: 'Its alert mode decides whether one run makes one grouped alert or one alert per matched event.',
  },
  'mode-paused': {
    term: 'Paused',
    short: 'Paused means the rule is stopped: it does not run and makes no alerts.',
  },
  'rule-scheduled': {
    term: 'Scheduled rule',
    short: 'A scheduled rule runs its search on a timer, every 5 minutes by default.',
  },
  'rule-realtime': {
    term: 'Real-time rule',
    short: 'A real-time rule checks events as they arrive, within about 10 to 30 seconds.',
    more: 'Only simple rules can run in real time. Rules with stats or joins run on a schedule.',
  },
  prevalence: {
    term: 'Prevalence',
    short: 'Prevalence is how common something is in your environment, such as how many hosts have seen a file or IP.',
    more: 'Rare things are more likely to be worth a look.',
    docsHref: DOCS_PAGES.prevalence,
    guard: /\bprevalence\b/i,
  },
  'mitre-attack': {
    term: 'MITRE ATT&CK',
    short: 'MITRE ATT&CK is a public list of the ways attackers work, grouped into tactics and techniques.',
  },
  tactic: {
    term: 'Tactic',
    short: "A tactic is an attacker's goal at one stage, such as getting in or moving to other hosts.",
  },
  technique: {
    term: 'Technique',
    short: 'A technique is one specific way an attacker reaches a goal, such as password spraying.',
    more: 'Each technique has an ID like T1110.',
  },
  'log-source': {
    term: 'Log source',
    short: 'A log source is one kind of log that comes into nano, such as Okta or Windows events.',
  },
  'source-type': {
    term: 'Source type',
    short: 'The source type is the short name nano gives each kind of log, such as okta or sysmon.',
    more: 'Search with source_type=okta to see only that source.',
  },
  parser: {
    term: 'Parser',
    short: 'A parser reads raw log lines and turns them into named fields that nano can search.',
  },
  'unmapped-field': {
    term: 'Unmapped field',
    short: 'An unmapped field is a value from the log that has no standard OCSF field, so nano keeps it in an extra field.',
    guard: /\bunmapped fields?\b/i,
  },
  'source-timezone': {
    term: 'Source timezone',
    short: 'The source timezone tells nano what time zone a log uses when its timestamps have no zone.',
    more: 'A zone written in the log itself always wins.',
    guard: /\bsource time ?zone\b/i,
  },
  telemetry: {
    term: 'Telemetry',
    short: 'Telemetry is the log data that comes in from your systems.',
  },
  enrichment: {
    term: 'Enrichment',
    short: 'Enrichment adds facts to an event as it comes in, such as the country of an IP address.',
    docsHref: DOCS_PAGES.enrichments,
  },
  ioc: {
    term: 'IOC',
    short: 'An IOC (indicator of compromise) is a known bad value, such as an IP, domain or file hash.',
    guard: /\bIOCs?\b/,
  },
  otlp: {
    term: 'OTLP',
    short: 'OTLP is the OpenTelemetry format that apps and agents use to send logs, traces and metrics.',
    docsHref: DOCS_PAGES.otlp,
    guard: /\bOTLP\b/,
  },
  'restricted-source': {
    term: 'Restricted',
    short: 'A restricted source is hidden from everyone except admins and the groups given access to it.',
    docsHref: DOCS_PAGES.sourceVisibility,
  },
  'rarity-threshold': {
    term: 'Rarity threshold',
    short: 'The rarity threshold is the host count below which a file hash, domain or IP counts as rare.',
    docsHref: DOCS_PAGES.prevalenceSettings,
    guard: /\brarity thresholds?\b/i,
  },
} as const satisfies GlossarySection;
