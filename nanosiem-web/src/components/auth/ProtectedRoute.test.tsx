// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ProtectedRoute } from './ProtectedRoute';
import { safeReturnPath } from '@/lib/tenant-auth-shell';
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ isAuthenticated: false, isLoading: false }) }));
afterEach(cleanup);
function LoginProbe() {
  const location = useLocation();
  return <output>{safeReturnPath(location.state?.from)}</output>;
}
it('retains query, absolute bounds, and fragment through the unauthenticated redirect', async () => {
  const entry = '/search?q=error&start=2026-10-17T12:00:00Z&end=2026-10-17T13:00:00Z#events';
  render(<MemoryRouter initialEntries={[entry]}><Routes>
    <Route path="/search" element={<ProtectedRoute>Search</ProtectedRoute>} />
    <Route path="/login" element={<LoginProbe />} />
  </Routes></MemoryRouter>);
  expect((await screen.findByRole('status')).textContent).toBe(entry);
});
