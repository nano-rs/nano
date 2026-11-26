// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest';
import { describeCron, scheduleDefaultText } from './schedule';

it('reads the connector schedules as plain English', () => {
  expect(scheduleDefaultText('*/5 * * * *')).toBe('Default: every 5 minutes');
  expect(scheduleDefaultText('*/2 * * * *')).toBe('Default: every 2 minutes');
  expect(scheduleDefaultText('0 * * * *')).toBe('Default: every hour');
  expect(scheduleDefaultText(null)).toBe('Default: every 5 minutes');
  expect(describeCron('0 */6 * * *')).toBe('every 6 hours');
  expect(describeCron('* * * * *')).toBe('every minute');
  // Anything else stays the cron itself rather than a wrong sentence.
  expect(describeCron('0 9 * * 1')).toBe('0 9 * * 1');
});
