// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Resolve the text shown in an event inspector's Raw tab.
 *
 * OCSF preserves the original line in `raw_data`; UDM uses `message`, and
 * older rows may expose `_raw`. Structured telemetry without any raw-text
 * field is represented by its real ingested fields instead.
 */
export const RAW_TEXT_FIELDS = ['raw_data', 'message', '_raw'] as const;

export interface RawView {
  text: string;
  synthetic: boolean;
}

export function resolveRawView(fields: Record<string, unknown> | undefined): RawView | null {
  if (!fields) return null;
  for (const key of RAW_TEXT_FIELDS) {
    const value = fields[key];
    if (typeof value === 'string' && value.trim() !== '') {
      return { text: value, synthetic: false };
    }
  }

  const structured: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (key.startsWith('_') || key === 'id' || key === 'timestamp') continue;
    if (value == null || value === '') continue;
    structured[key] = value;
  }
  return Object.keys(structured).length > 0
    ? { text: JSON.stringify(structured, null, 2), synthetic: true }
    : null;
}
