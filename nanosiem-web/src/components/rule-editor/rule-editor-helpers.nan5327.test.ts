import { describe, expect, it } from 'vitest';
import { MODE_META, displayMode, folderOf } from './helpers';

// NAN-5327
describe('folderOf', () => {
  it('uses the explicit folder', () => {
    expect(folderOf({ folder: 'Hunting' })).toBe('Hunting');
  });
  it('is Uncategorized when the rule has no folder (matches the meta row / API), never a tactic guess', () => {
    expect(folderOf({ folder: null as unknown as string })).toBe('Uncategorized');
    expect(folderOf({ folder: '  ' })).toBe('Uncategorized');
  });
});

describe('displayMode', () => {
  it('keeps alerting distinct from live', () => {
    expect(displayMode('alerting')).toBe('alerting');
    expect(displayMode('live')).toBe('live');
    expect(MODE_META[displayMode('alerting')].label).toBe('ALERTING');
    expect(MODE_META[displayMode('live')].label).toBe('LIVE');
  });
  it('maps paused / staging / unknown', () => {
    expect(displayMode('paused')).toBe('paused');
    expect(displayMode('staging')).toBe('staging');
    expect(displayMode(undefined)).toBe('staging');
  });
});
