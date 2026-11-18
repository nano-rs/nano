// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Notification channel event types. The built-ins have fixed labels; the
 * server may register more (extensions, e.g. on enterprise builds), listed by
 * GET /api/settings/webhooks/event-types. An unknown name gets a readable
 * label from its own name, so this file names no extension.
 */

export interface WebhookEventType {
  name: string;
  extension: boolean;
}

export const BUILTIN_EVENT_TYPES: { value: string; label: string }[] = [
  { value: 'siem_alert', label: 'SIEM alerts' },
  { value: 'obs_alert', label: 'Observability alerts' },
  { value: 'case', label: 'Cases' },
  { value: 'report', label: 'Scheduled reports' },
  { value: 'system_health', label: 'System health' },
];

const BUILTIN_LABEL: Record<string, string> = Object.fromEntries(BUILTIN_EVENT_TYPES.map((o) => [o.value, o.label]));

/** "hunt_escalation" -> "Hunt escalations": words, first letter capitalized, plural. */
export function eventTypeLabel(name: string): string {
  if (BUILTIN_LABEL[name]) return BUILTIN_LABEL[name];
  const words = name.replace(/[._-]+/g, ' ').trim().toLowerCase();
  if (!words) return name;
  const plural = words.endsWith('s') || words.endsWith('ed') ? words : `${words}s`;
  return plural.charAt(0).toUpperCase() + plural.slice(1);
}

/**
 * The checkbox options: the server's list when it answered, else the
 * built-ins (an older server, or the request failed). Built-ins keep their
 * order; extensions follow, in the server's order, without duplicates.
 */
export function eventTypeOptions(fromServer: WebhookEventType[] | null | undefined): { value: string; label: string; extension: boolean }[] {
  if (!fromServer || fromServer.length === 0) return BUILTIN_EVENT_TYPES.map((o) => ({ ...o, extension: false }));
  const seen = new Set<string>();
  const out: { value: string; label: string; extension: boolean }[] = [];
  const ordered = [...fromServer.filter((t) => !t.extension), ...fromServer.filter((t) => t.extension)];
  for (const t of ordered) {
    if (!t.name || seen.has(t.name)) continue;
    seen.add(t.name);
    out.push({ value: t.name, label: eventTypeLabel(t.name), extension: t.extension });
  }
  return out;
}
