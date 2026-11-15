// @vitest-environment jsdom
// NAN-5450: the SIEM Health disk panel lists every data volume with its level.

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { DiskPanel } from './SiemHealth';
import type { DiskHealthReport } from '@/lib/api/siem-health';

afterEach(cleanup);

const report: DiskHealthReport = {
  status: 'critical',
  warn_fraction: 0.8,
  critical_fraction: 0.9,
  checked_at: '2026-11-14T00:00:00Z',
  notes: ['PostgreSQL free space is not visible over SQL.'],
  volumes: [
    {
      component: 'clickhouse',
      name: 'default',
      total_bytes: 1000,
      used_bytes: 930,
      free_bytes: 70,
      usage_fraction: 0.93,
      level: 'critical',
      detail: '93.0% used',
    },
    { component: 'postgres', name: 'database', used_bytes: 10, level: 'unknown', detail: 'database 10 B' },
    {
      component: 'vector_buffer',
      host: 'vector-0',
      name: 'disk_buffers',
      total_bytes: 100,
      used_bytes: 10,
      free_bytes: 90,
      usage_fraction: 0.1,
      level: 'ok',
      detail: '1 disk buffers',
    },
  ],
};

test('lists each volume with usage, level and the probe notes', () => {
  render(<DiskPanel disk={report} />);
  expect(screen.getByText('1 volume at or above 80%')).toBeTruthy();
  expect(screen.getByText('93.0%')).toBeTruthy();
  expect(screen.getByText('unknown')).toBeTruthy();
  expect(screen.getByText('10.0%')).toBeTruthy();
  expect(screen.getByText('Vector buffers')).toBeTruthy();
  expect(screen.getByText('PostgreSQL free space is not visible over SQL.')).toBeTruthy();
});
