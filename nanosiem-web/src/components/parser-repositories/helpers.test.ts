// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';

import type { ParserRepository } from '@/lib/api/parser-repositories';

import { buildRepoView } from './helpers';

const NOW = Date.parse('2026-10-07T12:00:00Z');

function repo(overrides: Partial<ParserRepository> = {}): ParserRepository {
  return {
    id: 'r1',
    name: 'nano parsers',
    slug: 'nano-parsers',
    description: null,
    url: 'https://github.com/nano-rs/parsers',
    branch: 'main',
    parsers_path: 'parsers/',
    auto_sync_enabled: true,
    sync_interval_hours: 24,
    last_synced_at: '2026-10-07T10:00:00Z',
    last_sync_commit: '11a84e7',
    last_sync_status: 'success',
    last_sync_error: null,
    parser_count: 72,
    enabled: true,
    created_at: '2026-10-04T00:00:00Z',
    updated_at: '2026-10-04T00:00:00Z',
    created_by: null,
    ...overrides,
  };
}

describe('parser repo next sync (NAN-3199)', () => {
  it('counts down while the next sync is in the future', () => {
    const view = buildRepoView(repo(), [], [], NOW);
    expect(view.nextSync).toEqual({ in: '22h 0m', cadence: 'daily', overdue: false });
  });

  it('reports a past-due sync as overdue, never "0m"', () => {
    const view = buildRepoView(repo({ last_synced_at: '2026-10-05T08:00:00Z' }), [], [], NOW);
    expect(view.nextSync.in).toBe('overdue');
    expect(view.nextSync.overdue).toBe(true);
  });

  it('surfaces a recorded failure', () => {
    const view = buildRepoView(
      repo({ last_synced_at: '2026-10-05T08:00:00Z', last_sync_status: 'failed', last_sync_error: 'GitHub: 502' }),
      [],
      [],
      NOW,
    );
    expect(view.lastSync.result).toBe('failed');
    expect(view.nextSync.overdue).toBe(true);
  });
});
