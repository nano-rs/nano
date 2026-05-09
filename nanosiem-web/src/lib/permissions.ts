// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared permission display utilities
 *
 * Used by ApiKeyForm and RoleForm to render human-readable category names.
 * The backend returns raw category strings (e.g. "rule_repositories") —
 * this map provides friendly labels for the UI.
 */

export const CATEGORY_DISPLAY_NAMES: Record<string, string> = {
  search: 'Search',
  dashboards: 'Dashboards',
  notebooks: 'Notebooks',
  detections: 'Detection Rules',
  alerts: 'Alerts',
  cases: 'Cases',
  parsers: 'Parsers',
  log_sources: 'Log Sources',
  source_configs: 'Source Configurations',
  credentials: 'Credentials',
  feeds: 'Feeds',
  enrichments: 'Enrichments',
  lookup: 'Lookup Tables',
  upload: 'Upload',
  risk: 'Risk Analytics',
  prevalence: 'Prevalence',
  sessions: 'Sessions',
  settings: 'Settings',
  users: 'Users',
  groups: 'Groups',
  roles: 'Roles',
  apikeys: 'API Keys',
  audit: 'Audit',
  melod: 'pivt',
  mitre: 'MITRE ATT&CK',
  notifications: 'Notifications',
  rule_repositories: 'Rule Repositories',
  parser_repositories: 'Parser Repositories',
  gdpr: 'GDPR',
};

/** Convert a raw category key to a display name, with fallback for unknown categories */
export function categoryDisplayName(category: string): string {
  return CATEGORY_DISPLAY_NAMES[category]
    ?? category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
