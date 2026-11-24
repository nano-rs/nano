// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: Log sources, parsers, pipelines, enrichment, prevalence and ingest terms (open core).
// Plain English, 8th-grade reading level, definition first. See src/lib/glossary/types.ts.

import { DOCS_PAGES, type GlossarySection } from './types';

/** Data surfaces: where data-area words like "input" or "release" mean what they mean here. */
const DATA_SURFACES = [
  'pages/LogSource',
  'pages/SourceConfigurationDetail',
  'pages/AddFeed',
  'pages/CloudPull',
  'pages/ConnectorFeeds',
  'pages/IngestCredentials',
  'pages/Pipelines',
  'pages/ParserRepositories',
  'pages/Marketplace',
  'pages/Upload',
  'pages/OnboardingWizard',
  'pages/Prevalence',
  'pages/LegacyIngestionRedirects',
  'components/log-sources/',
  'components/parser/',
  'components/parser-repositories/',
  'components/pipelines/',
  'components/add-data/',
  'components/credentials/',
  'components/marketplace/',
  'components/prevalence/',
  'components/connector-feeds/',
  'components/source-configs/',
  'components/routing/',
  'components/upload/',
] as const;

export const DATA_GLOSSARY = {
  // ── parsers and publishing ────────────────────────────────────────────────
  vrl: {
    term: 'VRL',
    short: 'VRL is the small programming language that parsers use to read raw logs and turn them into fields.',
    more: 'It comes from Vector, the open-source log collector inside nano.',
    guard: /\bVRL\b/,
    guardIn: DATA_SURFACES,
  },
  vector: {
    term: 'Vector',
    short: 'Vector is the open-source program inside nano that receives logs, runs parsers and saves the events.',
  },
  'source-draft': {
    term: 'Draft',
    short: "A draft is a saved change to a log source that doesn't touch incoming events until you publish it.",
  },
  publish: {
    term: 'Publish',
    short: 'Publishing makes your draft the live parser for incoming events and deploys it in the same step.',
    more: 'The old version stays in history, so you can go back.',
  },
  deploy: {
    term: 'Deploy',
    short: "Deploying sends a log source's published parser and settings to the log collector, so they start working.",
    more: 'A deploy uses the published version, so an unpublished draft never goes live.',
  },
  'parser-extension': {
    term: 'Parser extension',
    short: 'A parser extension is your own extra VRL that runs after a built-in parser, to add or fix fields without changing the parser.',
    docsHref: DOCS_PAGES.parserExtensions,
    guard: /\b(parser )?extension overlay\b/i,
    guardIn: DATA_SURFACES,
  },
  'parser-repository': {
    term: 'Parser repository',
    short: 'A parser repository is a Git repo or signed file of ready-made parsers that you can import.',
    guard: /\bparser repositor(y|ies)\b/i,
  },
  'test-lab': {
    term: 'Test lab',
    short: 'The test lab runs your parser on sample events, so you can check the fields it makes before you publish.',
  },
  'ocsf-sample-check': {
    term: 'OCSF sample check',
    short: 'Before a changed parser goes live, nano runs real sample events through it and checks that the result fits OCSF.',
    more: 'An earlier passing test of the same parser counts. A first go-live may skip the check, and that choice is recorded in the audit log.',
  },
  'raw-passthrough': {
    term: 'Not parsed',
    short: 'Not parsed means events are arriving but no parser reads them yet, so they are kept as raw text.',
    guard: /\bnot parsed\b/i,
  },

  // ── getting data in ───────────────────────────────────────────────────────
  input: {
    term: 'Input',
    short: 'An input is one way data reaches a log source: a sender pushing with a credential, or a feed nano pulls.',
    guard: /\binputs?\b/i,
    guardIn: ['pages/SourceConfigurationDetail', 'components/parser-repositories/', 'components/source-configs/'],
  },
  transport: {
    term: 'Transport',
    short: 'The transport is how events travel to nano, such as HTTPS, syslog, Kafka or a cloud pull.',
    guard: /\btransports?\b/i,
    guardIn: ['pages/AddFeed', 'components/add-data/', 'components/parser-repositories/'],
  },
  'ingest-credential': {
    term: 'Ingest credential',
    short: 'An ingest credential is a secret token that one sender uses to send logs into one log source.',
    more: 'Revoke it and nano stops accepting that sender.',
  },
  'install-token': {
    term: 'Install token',
    short: 'The install token is the shared token set up when nano was installed (VECTOR_AUTH_TOKEN).',
    more: 'Give each sender its own credential instead, so you can tell senders apart and cut off just one.',
  },
  'legacy-multiplex': {
    term: 'Legacy multiplex mode',
    short: 'Legacy multiplex mode lets every sender share the install token and name its own log source in each request.',
    more: 'It is being retired. Give each sender its own token instead.',
  },
  'source-key': {
    term: 'Source key',
    short: 'The source key is the name incoming events carry that tells nano which log source they belong to.',
    guard: /\bsource keys?\b/i,
  },
  'unassigned-source': {
    term: 'Unassigned source',
    short: 'An unassigned source is data that is arriving but no log source claims it yet, so nano cannot parse it.',
    guard: /\bunassigned sources?\b/i,
  },
  'ingest-endpoint': {
    term: 'Ingest endpoint',
    short: 'The ingest endpoint is the web address your senders use to send logs to nano.',
    guard: /\bingest (endpoint|host)\b/i,
  },
  hec: {
    term: 'HEC',
    short: 'HEC (HTTP Event Collector) is a Splunk-style way to send events to nano over HTTPS with a token.',
    docsHref: DOCS_PAGES.hec,
    // "Splunk HEC" as a product name in a picker is not the term on first use.
    guard: /(?<!Splunk )\bHEC\b/,
    guardIn: DATA_SURFACES,
  },
  'cloud-pull': {
    term: 'Cloud pull',
    short: 'Cloud pull means nano fetches logs from your cloud account, such as an S3 bucket, Pub/Sub or Event Hubs.',
    more: 'nano reads with the access you grant it. Nothing has to push to nano.',
    docsHref: DOCS_PAGES.cloudPull,
    guard: /\bcloud pull\b/i,
    guardIn: DATA_SURFACES,
  },
  'pull-feed': {
    term: 'Pull feed',
    short: "A pull feed is a log source nano fetches from a SaaS app's API on a schedule, such as Okta or Google Workspace.",
    more: 'A new log feed starts at current activity, while an identity feed runs a full directory sync. A feed only moves forward once its events are safely received.',
    guard: /\bpull feeds?\b/i,
    guardIn: DATA_SURFACES,
  },
  'routing-rule': {
    term: 'Routing rule',
    short: 'A routing rule sends matching events from an input to a parser, and rules are checked in order so the first match wins.',
    more: 'An optional default rule catches events that no other rule matches.',
    docsHref: DOCS_PAGES.routingModel,
    guard: /\brouting rules?\b/i,
    guardIn: DATA_SURFACES,
  },
  'network-namespace': {
    term: 'Network namespace',
    short: 'A network namespace keeps private IPs from different networks apart, so 10.0.0.5 at one site is not mixed up with 10.0.0.5 at another.',
    guard: /\bnetwork namespace\b/i,
  },
  'source-status': {
    term: 'Status',
    short: 'Status shows where a log source is: Draft (still being set up), Ready (set up, not deployed), Deployed (live) or Paused (turned off).',
  },
  'source-sampling': {
    term: 'Sampling',
    short: 'Sampling keeps only a set percentage of incoming events and drops the rest at random before they are stored.',
    more: 'Dropped events are gone for good, so avoid it on audit logs. An exclude condition keeps matching events.',
  },
  'stale-source': {
    term: 'Stale',
    short: 'A source is stale when no events have arrived for longer than its stale threshold.',
    more: 'The threshold is 15 minutes by default. For feeds that send less often, nano waits for their usual gap instead.',
  },
  eps: {
    term: 'EPS',
    short: 'EPS (events per second) is how many log events arrive each second.',
    guard: /\bEPS\b/,
    guardIn: DATA_SURFACES,
  },

  // ── Nano Pipe ─────────────────────────────────────────────────────────────
  pipeline: {
    term: 'Pipeline',
    short: 'A pipeline is a list of steps that clean up, filter or reshape events before they are stored.',
    more: "A pipeline is saved as the log source's parser, so you publish it the same way.",
    docsHref: DOCS_PAGES.pipelines,
  },
  'pipeline-release': {
    term: 'Release',
    short: 'A release is a published version of a pipeline that you can roll back to later.',
    more: 'Rolling back restores the settings, not events already stored.',
  },
  'draft-preview': {
    term: 'Preview',
    short: 'Preview runs your draft pipeline on a saved batch of events, so you can see the result before you publish.',
    more: "Nothing is stored, and nano's final cleanup step is skipped.",
    docsHref: DOCS_PAGES.pipelines,
  },
  'live-capture': {
    term: 'Live capture',
    short: 'Live capture grabs a small batch of real events as they arrive, so you can test your pipeline on them.',
    docsHref: DOCS_PAGES.pipelineLiveCapture,
    guard: /\blive (capture|tap)\b/i,
  },
  'step-parse': {
    term: 'Parse',
    short: 'Parse reads one field, such as JSON text, and splits it into separate fields.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-fields': {
    term: 'Field operations',
    short: 'Field operations rename, remove or set fields.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-mask': {
    term: 'Mask or hash',
    short: 'Mask or hash hides sensitive values, such as emails, before they are stored.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-split': {
    term: 'Split events',
    short: 'Split turns one event that holds a list into one event for each item.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-combine': {
    term: 'Combine or summarize',
    short: 'Combine merges events that share the same key fields into one summary event with a count.',
    more: 'A group closes when it reaches its size limit or after a few seconds with no new events.',
  },
  'step-filter': {
    term: 'Filter',
    short: "Filter drops events you don't need, or keeps only the ones you do.",
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-sample': {
    term: 'Sample',
    short: 'Sample cuts volume by keeping about 1 in N values of a chosen field and dropping events with the other values.',
    more: 'Events that share a value are always kept or dropped together. An exempt condition keeps matching events no matter what.',
  },
  'step-lookup': {
    term: 'Lookup',
    short: 'Lookup adds fields to an event by matching one of its values against a small table.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },
  'step-dedupe': {
    term: 'Dedupe',
    short: 'Dedupe drops an event when its chosen fields match an event it saw recently.',
    more: 'It remembers a set number of recent events, 1,000 by default.',
  },
  'step-route': {
    term: 'Route',
    short: 'Route sorts events into named branches by a condition or by the input they came from.',
    more: 'Later steps can treat each branch differently, and a branch can drop its events.',
  },
  'step-vrl': {
    term: 'Advanced VRL',
    short: 'Advanced VRL lets you write your own VRL code for a step that the other steps cannot do.',
    docsHref: DOCS_PAGES.pipelineSteps,
  },

  // ── enrichment feeds and the Marketplace ──────────────────────────────────
  'platform-feeds': {
    term: 'Platform feeds',
    short: "Platform feeds are nano's built-in reference data, such as IP locations, ThreatFox and Tor exit nodes, added to events as they arrive.",
    docsHref: DOCS_PAGES.enrichments,
  },
  'feed-bundle': {
    term: 'Feed bundle',
    short: 'A feed bundle is a signed file of reference data, such as IP locations or known bad IPs, that nano adds to events as they arrive.',
    docsHref: DOCS_PAGES.enrichments,
    guard: /\b(feed|data) bundles?\b/i,
  },
  'feed-hard-expiry': {
    term: 'Hard expiry',
    short: "Hard expiry is the date after which nano stops adding a feed's data to new events.",
    more: 'Values already added to older events stay searchable.',
  },
  'air-gapped': {
    term: 'Air-gapped',
    short: 'Air-gapped means this install has no internet access, so updates come from signed files instead of downloads.',
    docsHref: DOCS_PAGES.airGapped,
    guard: /\bair[- ]gapped\b/i,
    guardIn: DATA_SURFACES,
  },
  integration: {
    term: 'Integration',
    short: 'An integration connects nano to another product, to pull in its logs or to look up data from it.',
  },
  collector: {
    term: 'Collector',
    short: "A collector fetches logs from a SaaS app's API on a schedule and sends them into nano.",
  },
  'connector-spec': {
    term: 'Connector spec',
    short: "The connector spec is the built-in recipe a pull feed follows to read one app's API.",
    more: 'Adopting a newer spec resets the feed, so a log feed restarts at current activity and an identity feed runs a full sync.',
  },

  // ── prevalence ────────────────────────────────────────────────────────────
  artifact: {
    term: 'Artifact',
    short: 'An artifact is one thing seen in your logs that can be tracked, such as a file hash, domain, IP or process.',
  },
  'prevalence-hosts': {
    term: 'Hosts',
    short: 'Hosts is how many different computers saw this artifact in the last 30 days.',
    more: 'The time window only decides which artifacts are listed, not how hosts are counted.',
  },
  rare: {
    term: 'Rare',
    short: 'Rare means an artifact was seen on fewer hosts than the rarity threshold.',
    more: 'Rare things are more likely to be worth a look.',
  },
} as const satisfies GlossarySection;
