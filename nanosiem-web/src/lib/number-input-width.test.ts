import { describe, it, expect } from 'vitest';
import { numberInputWidth } from './number-input-width';

describe('numberInputWidth (NAN-5329)', () => {
  it('fits every digit of the max', () => {
    expect(numberInputWidth(10_000_000)).toBe('calc(8ch + 2.75rem)');
    expect(numberInputWidth(1_000_000)).toBe('calc(7ch + 2.75rem)');
  });
  it('has a small floor', () => {
    expect(numberInputWidth(5)).toBe('calc(3ch + 2.75rem)');
  });
});
