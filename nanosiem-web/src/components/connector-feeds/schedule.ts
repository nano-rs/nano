// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5903: the schedule field's placeholder reads as a default, not as a
 * filled-in value: "Default: every 5 minutes" instead of a raw cron.
 */

/** Plain English for the simple cron shapes connector specs use; the raw cron otherwise. */
export function describeCron(cron: string): string {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return cron;
  const [min, hour, dom, mon, dow] = parts;
  if (dom !== '*' || mon !== '*' || dow !== '*') return cron;
  const every = (n: number, unit: string) => (n === 1 ? `every ${unit}` : `every ${n} ${unit}s`);
  if (hour === '*') {
    if (min === '*') return 'every minute';
    const step = /^\*\/(\d+)$/.exec(min);
    if (step) return every(Number(step[1]), 'minute');
    if (/^\d+$/.test(min)) return 'every hour';
  }
  if (/^\d+$/.test(min)) {
    const step = /^\*\/(\d+)$/.exec(hour);
    if (step) return every(Number(step[1]), 'hour');
  }
  return cron;
}

/** "Default: every 5 minutes". A spec with no schedule runs every 5 minutes. */
export function scheduleDefaultText(specSchedule: string | null): string {
  return `Default: ${describeCron(specSchedule ?? '*/5 * * * *')}`;
}
