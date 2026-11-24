// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest';
import { vrlErrorToastDescription } from './vrl-error-toast';

const COMPILER_DUMP = [
  'error[E103]: unhandled fallible assignment\n  ┌─ :2:20\n  │\n2 │ .actor.user.name = upcase(.user)\n'
  + '  │ -------------- ^^^^^^^^^^^^^ this expression is fallible\n  = see https://errors.vrl.dev/103',
];

it('summarizes instead of dumping the compiler output (NAN-5834)', () => {
  const text = vrlErrorToastDescription(COMPILER_DUMP);
  expect(text).toBe('1 error. See Diagnostics for details.');
  expect(text).not.toContain('\n');
});

it('counts errors and ignores blank ones', () => {
  expect(vrlErrorToastDescription(['a', ' ', 'b'])).toBe('2 errors. See Diagnostics for details.');
  expect(vrlErrorToastDescription([])).toBe('See Diagnostics for details.');
});
