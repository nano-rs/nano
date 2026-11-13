// NAN-5329: editing a key must not silently drop scopes the editor cannot grant.
import { describe, it, expect } from 'vitest';
import { initialPresetId, presetScopeIds, type ScopeCandidate } from './scope-presets';

const catalogue: ScopeCandidate[] = [{ id: 'alerts:view' }, { id: 'rules:view' }, { id: 'alerts:edit' }];

describe('initialPresetId (NAN-5329)', () => {
  const readonly = presetScopeIds(catalogue, 'readonly');

  it('opens on the matching preset when the editor can grant all of it', () => {
    expect(readonly.length).toBeGreaterThan(0);
    expect(initialPresetId(catalogue, readonly, 'custom', () => true)).toBe('readonly');
  });

  it('opens on custom when the editor holds only part of the matching preset', () => {
    const lacks = readonly[0];
    expect(initialPresetId(catalogue, readonly, 'custom', (id) => id !== lacks)).toBe('custom');
  });

  it('uses the default preset for a new key', () => {
    expect(initialPresetId(catalogue, [], 'readonly', () => false)).toBe('readonly');
  });
});
