// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { expect, it } from 'vitest';
import { liftToasts } from './toast-lift';

const lifted = () => document.documentElement.hasAttribute('data-toast-lift');

it('lifts while any bar holds it, and releases once (NAN-5834)', () => {
  expect(lifted()).toBe(false);
  const a = liftToasts();
  const b = liftToasts();
  expect(lifted()).toBe(true);
  a();
  a(); // a double release must not drop b's hold
  expect(lifted()).toBe(true);
  b();
  expect(lifted()).toBe(false);
});
