// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// #7030: a fired-detection pivot that lands on login keeps its query, window
// and fragment, so Search opens on the match window after sign-in.
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ProtectedRoute } from './ProtectedRoute';
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ isAuthenticated: false, isLoading: false, hasPermission: () => true }) }));
afterEach(cleanup);
function LoginProbe() {
  const location = useLocation();
  return <output>{(location.state as { from?: string } | null)?.from}</output>;
}
it('retains query, absolute bounds, and fragment through the unauthenticated redirect', async () => {
  const entry = '/search?legacy=1#q=error&start=2026-10-17T12:00:00Z&end=2026-10-17T13:00:00Z';
  render(<MemoryRouter initialEntries={[entry]}><Routes>
    <Route path="/search" element={<ProtectedRoute>Search</ProtectedRoute>} />
    <Route path="/login" element={<LoginProbe />} />
  </Routes></MemoryRouter>);
  expect((await screen.findByRole('status')).textContent).toBe(entry);
});
