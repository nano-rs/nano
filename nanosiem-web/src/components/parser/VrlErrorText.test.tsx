// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import { VrlErrorText } from './VrlErrorText';

describe('VrlErrorText (NAN-5329)', () => {
  it('keeps multi-line VRL diagnostics preformatted', () => {
    const err = 'error[E203]: syntax error\n  ┌─ :326:1773\n  │\n326 │ }\n  │ ^';
    const { getByTestId } = render(<VrlErrorText error={err} />);
    const el = getByTestId('vrl-error-text');
    expect(el.tagName).toBe('PRE');
    expect(el.className).toContain('whitespace-pre');
    expect(el.textContent).toBe(err);
  });
});
