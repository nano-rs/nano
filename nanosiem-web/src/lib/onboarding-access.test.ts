// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, test } from 'vitest';
import { shouldRedirectToSetup } from './onboarding-access';

const base = { isDemoUser: false, canRunSetup: true, hasProgress: false, progressLoading: false, seenThisSession: false };

test('an admin on first visit is sent to instance setup', () => {
  expect(shouldRedirectToSetup(base)).toBe(true);
});

test('NAN-5309: a role without settings:view is never sent to instance setup', () => {
  expect(shouldRedirectToSetup({ ...base, canRunSetup: false })).toBe(false);
});

test('no redirect once seen, while loading, with progress, or for demo users', () => {
  expect(shouldRedirectToSetup({ ...base, seenThisSession: true })).toBe(false);
  expect(shouldRedirectToSetup({ ...base, progressLoading: true })).toBe(false);
  expect(shouldRedirectToSetup({ ...base, hasProgress: true })).toBe(false);
  expect(shouldRedirectToSetup({ ...base, isDemoUser: true })).toBe(false);
});
