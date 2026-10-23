// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4152: the demo banner follows `demo.active` from /api/auth/me. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

const auth = vi.hoisted(() => ({ value: {} as Record<string, unknown> }));
const getSessionStatus = vi.hoisted(() => vi.fn());

vi.mock('../contexts/AuthContext', () => ({ useAuth: () => auth.value }));
vi.mock('../lib/api', () => ({ api: { demo: { getSessionStatus } } }));

import { DemoBanner } from './DemoBanner';
import { isDemoIdentity } from '../lib/shared-demo';

function signIn(user: { roles: string[]; demo?: { active: boolean; expires_at: string } }) {
  auth.value = { user, isDemoUser: isDemoIdentity(user) };
}

beforeEach(() => getSessionStatus.mockReset());
afterEach(cleanup);

describe('DemoBanner', () => {
  it('is hidden for a normal member (no demo on /me)', () => {
    signIn({ roles: ['analyst'] });
    const { container } = render(<DemoBanner />);
    expect(container.innerHTML).toBe('');
    expect(getSessionStatus).not.toHaveBeenCalled();
  });

  it('is visible with demo.active, timed from expires_at, with the sign-up CTA', () => {
    const expiresAt = new Date(Date.now() + 5.5 * 3_600_000).toISOString();
    signIn({ roles: ['analyst'], demo: { active: true, expires_at: expiresAt } });
    render(<DemoBanner />);
    expect(screen.getByTestId('demo-banner')).toBeTruthy();
    expect(screen.getByText('5h remaining')).toBeTruthy();
    expect(screen.getByRole('link', { name: /Get Full Access/ }).getAttribute('href')).toBe('https://nano.rs');
    // The shared runtime has no Saturn status endpoint.
    expect(getSessionStatus).not.toHaveBeenCalled();
  });
});
