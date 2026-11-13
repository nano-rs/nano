// NAN-5329: permission-matrix rows are named after the resource, not one of its actions.
import { describe, it, expect, vi } from 'vitest';

vi.mock('@/lib/api', () => ({ api: {} }));

import { buildMatrix } from './role-matrix';

const perm = (id: string, name: string, category: string) => ({ id, name, description: '', category });

describe('buildMatrix row labels (NAN-5329)', () => {
  it('labels rows by resource', () => {
    const rows = buildMatrix([
      perm('alerts:acknowledge', 'Acknowledge alerts', 'alerts'),
      perm('alerts:view', 'View alerts', 'alerts'),
      perm('apikeys:create', 'Create API keys', 'apikeys'),
      perm('log_sources:create', 'Create Log sources', 'log_sources'),
    ] as never);
    const byRes = Object.fromEntries(rows.map((r) => [r.resource, r.label]));
    expect(byRes).toEqual({ alerts: 'Alerts', apikeys: 'API Keys', log_sources: 'Log Sources' });
  });
});
