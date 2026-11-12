// SPDX-License-Identifier: AGPL-3.0-or-later

// Radix Select refuses an empty-string item value (it throws and blanks the
// page), so "all" is a sentinel that maps to an absent filter.
export const ALL_FILTER = '__all__';

// Friendly labels for common actions. The Action filter lists every action
// the server has recorded (GET /api/audit/actions, NAN-5324); these only
// supply nicer labels and a baseline when that list is unavailable.
const AUDIT_ACTIONS = [
  { value: 'login_success', label: 'Login Success' },
  { value: 'login_failed', label: 'Login Failed' },
  { value: 'logout', label: 'Logout' },
  { value: 'auth_denied', label: 'Authorization Denied' },
  { value: 'sso_sign_in_denied', label: 'SSO Sign-in Denied' },
  { value: 'sso_group_grants_synchronized', label: 'SSO Group Grants Synchronized' },
  { value: 'token_refresh', label: 'Session Refreshed' },
  { value: 'user_created', label: 'User Created' },
  { value: 'user_updated', label: 'User Updated' },
  { value: 'user_deleted', label: 'User Deleted' },
  { value: 'rule_created', label: 'Rule Created' },
  { value: 'rule_updated', label: 'Rule Updated' },
  { value: 'rule_deleted', label: 'Rule Deleted' },
  { value: 'dashboard_created', label: 'Dashboard Created' },
  { value: 'dashboard_updated', label: 'Dashboard Updated' },
  { value: 'dashboard_deleted', label: 'Dashboard Deleted' },
  { value: 'alert_acknowledged', label: 'Alert Acknowledged' },
  { value: 'alert_closed', label: 'Alert Closed' },
  { value: 'apikey_created', label: 'API Key Created' },
  { value: 'apikey_updated', label: 'API Key Updated' },
  { value: 'apikey_enabled', label: 'API Key Enabled' },
  { value: 'apikey_disabled', label: 'API Key Disabled' },
  { value: 'apikey_deleted', label: 'API Key Deleted' },
  { value: 'session_terminated', label: 'Session Terminated' },
  { value: 'oidc_provider_created', label: 'OIDC Provider Created' },
];

function formatAction(action: string): string {
  return action
    .replace(/[._]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

/** Wait before sending a typed search to the server. */
export const AUDIT_SEARCH_DEBOUNCE_MS = 300;

/**
 * NAN-5324: Action filter options — every action the server recorded, plus
 * the known labelled actions and the currently selected one, sorted by label.
 */
export function auditActionOptions(recorded: string[], selected?: string): { value: string; label: string }[] {
  const labels = new Map(AUDIT_ACTIONS.map(a => [a.value, a.label]));
  const values = new Set<string>([...labels.keys(), ...recorded.filter(Boolean)]);
  if (selected) values.add(selected);
  const options = [...values]
    .map(value => ({ value, label: labels.get(value) ?? formatAction(value) }))
    .sort((a, b) => a.label.localeCompare(b.label));
  return [{ value: ALL_FILTER, label: 'All Actions' }, ...options];
}
