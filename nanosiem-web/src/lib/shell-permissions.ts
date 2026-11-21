// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5325: the permission each shell-wide read needs server-side. The app
 * shell (status bars, Home cards, Settings chrome) mounts for every role; a
 * read a role is refused costs a 403 and an `auth_denied` audit row on every
 * page load, burying real denials. Gate each read on these instead.
 */
export const SHELL_READ_PERMISSIONS = {
  /** GET /api/siem-health/reports/latest */
  siemHealth: 'settings:system',
  /** GET /api/log-sources/ingestion-history */
  ingestionHistory: 'log_sources:view',
  /** GET /api/system/config */
  systemConfig: 'settings:view',
  /** GET /api/audit */
  audit: 'audit:view',
  /** GET /api/cases/my */
  myCases: 'cases:view',
  /** GET /api/groups */
  groups: 'groups:view',
} as const;

/**
 * NAN-5724: `GET /api/settings/ai-availability` admits any ONE of these
 * (`AI_AVAILABILITY_READERS` in handlers/settings/ai_providers.rs). Home and
 * Search open for roles holding none, so they skip the read without them.
 */
export const AI_AVAILABILITY_READ_PERMISSIONS = [
  'settings:ai',
  'melod:chat',
  'melod:notebook',
  'melod:query',
  'melod:parser',
  'melod:detection',
  'melod:summarize',
  'melod:dashboard',
];
