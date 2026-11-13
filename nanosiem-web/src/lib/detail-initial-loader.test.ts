import { describe, it, expect } from 'vitest';
import { showInitialLoader } from './detail-initial-loader';

describe('showInitialLoader (NAN-5329)', () => {
  it('shows the loader on first load', () => {
    expect(showInitialLoader(true, null, 'lsrc_a')).toBe(true);
  });
  it('keeps the page mounted during a refetch of the same record', () => {
    expect(showInitialLoader(true, { id: 'lsrc_a' }, 'lsrc_a')).toBe(false);
  });
  it('shows the loader when switching to another record', () => {
    expect(showInitialLoader(true, { id: 'lsrc_a' }, 'lsrc_b')).toBe(true);
  });
  it('never shows it once loaded', () => {
    expect(showInitialLoader(false, null, 'lsrc_a')).toBe(false);
  });
});
