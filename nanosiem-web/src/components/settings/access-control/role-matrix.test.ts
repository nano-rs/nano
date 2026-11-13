import { describe, expect, it } from 'vitest';
import { buildMatrix } from './role-matrix';
import type { PermissionInfo } from '@/lib/api';

const p = (id: string, name: string, category: string) =>
  ({ id, name, description: '', category }) as PermissionInfo;

// NAN-5326: rows are named after the resource, not one of its actions.
describe('buildMatrix', () => {
  it('labels rows by resource and shows the AI row as pivt', () => {
    const rows = buildMatrix([
      p('alerts:acknowledge', 'Acknowledge Alerts', 'alerts'),
      p('alerts:view', 'View Alerts', 'alerts'),
      p('melod:chat', 'Chat with AI', 'melod'),
    ]);
    const byRes = Object.fromEntries(rows.map((r) => [r.resource, r.label]));
    expect(byRes.alerts).toBe('Alerts');
    expect(byRes.melod).toBe('pivt');
  });
});
