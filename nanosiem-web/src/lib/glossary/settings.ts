// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: Settings, access control, storage, health and admin terms (open core).
// Plain English, 8th-grade reading level, definition first. See src/lib/glossary/types.ts.
// Enterprise-only settings terms (SSO, SCIM, license, AI models, Agent Lane,
// cases, storage tiering) live in src/enterprise/lib/glossary/settings.ts.

import { DOCS_PAGES, scopeGuards, type GlossarySection } from './types';

/**
 * Settings words like "audit log" or "MFA" also show up on other pages, where
 * their owners wrap them. The guard checks these terms on open-core settings
 * and admin surfaces only.
 */
const SETTINGS_SURFACES = [
  'pages/Settings/',
  'components/settings/',
  'components/system-health/',
  'pages/SiemHealth.tsx',
  'pages/Setup.tsx',
  'pages/MfaSetup.tsx',
] as const;

export const SETTINGS_GLOSSARY = scopeGuards(SETTINGS_SURFACES, {
  // ── Access control ────────────────────────────────────────────────────────
  role: {
    term: 'Role',
    short: 'A role is a named set of permissions that you give to a user or a group to decide what they can do.',
    docsHref: DOCS_PAGES.accessControl,
  },
  permission: {
    term: 'Permission',
    short: 'A permission allows one action, such as viewing alerts or editing rules.',
    more: 'Permission names look like alerts:view. Roles bundle them together.',
    docsHref: DOCS_PAGES.accessControl,
  },
  'user-group': {
    term: 'Group',
    short: 'A group is a set of users who share the same default role and access.',
    docsHref: DOCS_PAGES.accessControl,
  },
  'default-role': {
    term: 'Default role',
    short: "A group's default role is the role every member of the group gets.",
  },
  'system-role': {
    term: 'System role',
    short: 'A system role comes with nano, and you can use it but not change or delete it.',
  },
  'api-key': {
    term: 'API key',
    short: 'An API key is a secret that lets a script or another tool call nano without a person signing in.',
    more: 'It can only do what its scopes allow. nano shows the secret once.',
    docsHref: DOCS_PAGES.accessControl,
  },
  'api-key-scope': {
    term: 'Scope',
    short: "A scope is one permission an API key may use, and a key with no scopes can't call any API.",
    more: 'A key never gets more than its owner has.',
  },
  'rate-limit': {
    term: 'Rate limit',
    short: 'A rate limit is the most requests per minute this key may send.',
  },
  session: {
    term: 'Session',
    short: 'A session is one signed-in browser or app, and revoking it signs that user out right away.',
  },
  mfa: {
    term: 'MFA',
    short: 'MFA (two-factor sign-in) asks for a code from an app on your phone as well as your password.',
    more: 'nano uses time-based codes (TOTP) from apps like Google Authenticator or 1Password.',
    guard: /\bMFA\b/,
  },
  'backup-codes': {
    term: 'Backup codes',
    short: 'Backup codes are one-time codes you can use to sign in if you lose your phone or authenticator app.',
    guard: /\bbackup codes\b/i,
  },
  'source-visibility': {
    term: 'Source visibility',
    short: 'Source visibility hides events from chosen log sources from everyone except the groups you allow and users who may see all sources.',
    more: 'With nothing restricted, everyone sees every source. Admins and anyone with source_scopes:view_all always see everything.',
    docsHref: DOCS_PAGES.sourceVisibility,
    guard: /\bsource visibility\b/i,
  },
  // ── Storage and health ────────────────────────────────────────────────────
  'event-retention': {
    term: 'Retention',
    short: 'Retention is how many days nano keeps events before it deletes them for good.',
    docsHref: DOCS_PAGES.storage,
  },
  'disk-pressure': {
    term: 'Disk pressure',
    short: 'Disk pressure is how full the disk that holds your events is.',
    more: 'Past the high mark (80% by default) nano deletes the oldest days first, and at 92% by default it pauses intake. It keeps the last 7 days by default.',
    docsHref: DOCS_PAGES.diskPressure,
    guard: /\bdisk pressure\b/i,
  },
  'pause-ingestion': {
    term: 'Pause ingestion',
    short: 'Pausing ingestion stops nano from taking in new events until you resume.',
    more: 'Senders are told to retry later and keep their data.',
  },
  'metadata-storage': {
    term: 'Metadata storage',
    short: 'Metadata storage holds everything except events, such as rules, alerts, dashboards, saved searches and settings.',
    more: 'It lives in PostgreSQL. Events live in ClickHouse.',
  },
  clickhouse: {
    term: 'ClickHouse',
    short: 'ClickHouse is the database where nano stores your events and runs searches.',
  },
  postgresql: {
    term: 'PostgreSQL',
    short: 'PostgreSQL is the database where nano stores settings, rules, alerts and users.',
  },
  backup: {
    term: 'Backup',
    short: 'A backup is a saved copy of the PostgreSQL database (settings, rules, alerts and users) that you can restore later.',
    more: 'It includes events only if you turned that on.',
  },
  'audit-log': {
    term: 'Audit log',
    short: 'The audit log records who did what in nano and when, such as sign-ins and rule changes.',
    docsHref: DOCS_PAGES.platformAudit,
    guard: /\baudit log\b/i,
  },
  'gdpr-anonymization': {
    term: 'Anonymization',
    short: 'Anonymization removes or scrambles the records that match one username, email or IP address in logs, identity observations, cloud activity and the user directory.',
    more: 'Matching OCSF event rows are deleted, not edited. It cannot be undone.',
    guard: /\banonymi[sz](e|ation)\b/i,
  },
  'lookup-url-allowlist': {
    term: 'Lookup URLs',
    short: 'Lookup URLs are the web hosts a search may download a lookup table from.',
    more: 'With no hosts listed, any public host is allowed.',
  },
  'siem-health-score': {
    term: 'Health score',
    short: 'The health score rates how well nano is working on a scale from 0 to 100, where higher is better.',
    more: 'Each stage, from taking in logs to sending alerts, has its own score too.',
  },
  'silent-source': {
    term: 'Silent source',
    short: 'A silent source sent events in the 24 hours before but none in the last 24 hours.',
    guard: /\bsilent sources?\b/i,
  },
  'stale-rule': {
    term: 'Stale rule',
    short: 'A stale rule has not matched anything in 30 days or more.',
    more: 'It may be broken or no longer needed.',
    guard: /\bstale rules?\b/i,
  },
  'noisy-rule': {
    term: 'Noisy rule',
    short: 'A noisy rule matches very often and may need tuning so real threats stand out.',
    guard: /\bnoisy rules?\b/i,
  },
  'field-coverage': {
    term: 'Field coverage',
    short: 'Field coverage is the share of events where a field has a value.',
    more: 'Low coverage can mean a parser problem.',
  },
  'health-event': {
    term: 'Health event',
    short: 'A health event is a problem nano found in itself, such as a collector or log source that stopped working.',
  },
  'setup-token': {
    term: 'Setup token',
    short: 'The setup token is a one-time code from the installer that proves you may create the first admin account.',
    guard: /\bsetup token\b/i,
  },
  'background-scheduler': {
    term: 'Background scheduler',
    short: 'A background scheduler runs a nano task on a timer, such as detection rules or enrichment updates.',
  },
  // ── Search settings ───────────────────────────────────────────────────────
  'admission-control': {
    term: 'Admission control',
    short: 'Admission control limits how many ad-hoc searches run at once, so extra searches wait in line or are turned away.',
    more: 'Detection rules are not limited by it.',
    guard: /\badmission control\b/i,
  },
  'priority-tier': {
    term: 'Priority tier',
    short: 'A priority tier groups searches by type, so each type gets its own time and memory limits.',
    more: 'Realtime is for detection rules, Interactive for analyst searches, and Analytics for long-running and background searches.',
  },
  'cost-guard': {
    term: 'Cost check',
    short: 'The cost check looks at a search before it runs and warns when it would read too much data.',
  },
  'query-mode': {
    term: 'Query mode',
    short: 'Query mode picks how you write searches: Standard uses nPL and Advanced uses SQL.',
  },
  // ── Notifications ─────────────────────────────────────────────────────────
  'notification-channel': {
    term: 'Notification channel',
    short: 'A notification channel is a place nano sends alerts and events, such as Slack, Teams, PagerDuty or a web address.',
    docsHref: DOCS_PAGES.notifications,
    guard: /\bnotification channels?\b/i,
  },
  'deep-link-base-url': {
    term: 'Deep link base URL',
    short: 'The deep link base URL is the web address of nano that starts every alert link, so the links open the right page.',
  },
  'signing-secret': {
    term: 'Signing secret',
    short: 'A signing secret lets the receiver check that a message really came from nano and was not changed.',
    guard: /\bsigning secret\b/i,
  },
  // ── Prevalence settings ───────────────────────────────────────────────────
  'cache-ttl': {
    term: 'Cache TTL',
    short: 'Cache TTL is how long nano reuses a lookup answer before it checks again, and 0 turns the cache off.',
    guard: /\bcache TTL\b/i,
  },
} as const satisfies GlossarySection);
