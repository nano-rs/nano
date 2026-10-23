// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { BrowserTelemetry, browserPageCategory } from './BrowserTelemetry';
const record = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
const state = vi.hoisted(() => ({ isAuthenticated: true }));
vi.mock('@/lib/api', () => ({ api: { observability: { recordBrowserPageview: record } } }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => state }));
afterEach(() => { cleanup(); vi.useRealTimers(); vi.clearAllMocks(); state.isAuthenticated = true; });
it('never exports URLs, IDs or queries', () => {
  expect(browserPageCategory('/cases/case_private?query=secret')).toBe('cases');
  expect(browserPageCategory('/unknown/private-id')).toBe('other');
  expect(browserPageCategory('/')).toBe('home');
});
it('sends one authenticated page category after mount and never a credential', async () => {
  vi.useFakeTimers();
  render(<MemoryRouter initialEntries={['/search?query=private']}><BrowserTelemetry /></MemoryRouter>);
  await vi.advanceTimersByTimeAsync(1000);
  expect(record).toHaveBeenCalledExactlyOnceWith('search');
});
it('does not send anonymous navigation', async () => {
  vi.useFakeTimers(); state.isAuthenticated = false;
  render(<MemoryRouter><BrowserTelemetry /></MemoryRouter>);
  await vi.advanceTimersByTimeAsync(1000);
  expect(record).not.toHaveBeenCalled();
});
