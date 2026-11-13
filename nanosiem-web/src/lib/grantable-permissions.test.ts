import { describe, it, expect } from 'vitest';
import { canToggleGrant, grantableOnly } from './grantable-permissions';

const held = new Set(['search:execute', 'log_sources:view']);
const canGrant = (id: string) => held.has(id);

describe('grantable permissions (NAN-5329)', () => {
  it('blocks ticking a permission the creator does not hold', () => {
    expect(canToggleGrant('users:create', false, canGrant)).toBe(false);
    expect(canToggleGrant('search:execute', false, canGrant)).toBe(true);
  });
  it('always allows clearing an already-selected permission', () => {
    expect(canToggleGrant('users:create', true, canGrant)).toBe(true);
  });
  it('bulk select keeps only grantable ids', () => {
    expect(grantableOnly(['users:create', 'search:execute', 'log_sources:view'], canGrant)).toEqual([
      'search:execute',
      'log_sources:view',
    ]);
  });
});
