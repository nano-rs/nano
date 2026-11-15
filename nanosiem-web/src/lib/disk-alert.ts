// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-5450: shared by the admin disk banner and the Settings -> Storage notice. */
import type { DiskVolumeHealth } from './api/siem-health';

export const DISK_ALERT_QUERY_KEY = ['system', 'disk-alert'] as const;
export const DISK_FULL_RUNBOOK_URL = 'https://nano.rs/docs/administration/disk-full-recovery';
/** A critical banner snoozed by an admin comes back after this long. */
export const DISK_BANNER_SNOOZE_MS = 60 * 60_000;
export const DISK_BANNER_SNOOZED_KEY = 'nano.disk-banner.snoozed-until';

const COMPONENT_LABEL: Record<DiskVolumeHealth['component'], string> = {
  clickhouse: 'ClickHouse disk',
  postgres: 'PostgreSQL volume',
  vector_buffer: 'Vector buffers',
};

/** `ClickHouse disk default on ch-0`. */
export function diskLabel(v: DiskVolumeHealth): string {
  return [COMPONENT_LABEL[v.component], v.name, v.host ? `on ${v.host}` : ''].filter(Boolean).join(' ');
}

/** `45 minutes`, `7 hours`, `3 days` (mirrors the server's human_hours). */
export function hoursText(h: number): string {
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} minutes`;
  if (h < 48) {
    const n = Math.round(h);
    return `${n} hour${n === 1 ? '' : 's'}`;
  }
  return `${Math.round(h / 24)} days`;
}

export function percentText(fraction: number | undefined): string {
  return fraction === undefined ? 'unknown' : `${(fraction * 100).toFixed(1)}%`;
}
