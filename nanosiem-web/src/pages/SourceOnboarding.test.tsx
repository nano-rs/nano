// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SourceOnboarding } from './SourceOnboarding';

const mocks = vi.hoisted(() => ({ read: vi.fn(), toast: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { sourceOnboarding: { read: mocks.read } } }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: { deployment_mode: 'enterprise_shared' }, hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));

const emptyPlan = { sources: [], waves: [], liveSources: [], settings: { groupBy: 'wave', completeGate: true, autoSuggest: true } };
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<MemoryRouter initialEntries={['/ingestion/log-sources/onboarding']}><QueryClientProvider client={client}><SourceOnboarding /></QueryClientProvider></MemoryRouter>);
  return client;
}
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('shows loading without claiming the plan is empty', () => {
  mocks.read.mockReturnValue(new Promise(() => {}));
  const client = mount();
  expect(screen.getByText('Loading plan…')).toBeTruthy();
  expect(screen.queryByText(/No sources planned yet/)).toBeNull();
  client.clear();
});

it('renders an empty plan inside the shared Log sources shell', async () => {
  mocks.read.mockResolvedValue(emptyPlan);
  const client = mount();
  expect(await screen.findByText(/No sources planned yet/)).toBeTruthy();
  const page = screen.getByTestId('source-onboarding-page');
  // NAN-3769: same full-width shell as Log sources / Credentials ...
  expect(page.getAttribute('data-page-shell')).toBe('log-sources');
  expect(page.className).toContain('-m-3');
  expect(page.querySelector('.mx-auto, [class*="max-w-[1440px]"]')).toBeNull();
  // ... with the standard title + meta row and the Log sources tabs.
  expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Onboarding plan');
  expect(screen.getByText('0 planned')).toBeTruthy();
  expect(screen.getByRole('navigation', { name: 'Log sources' })).toBeTruthy();
  client.clear();
});

it('does not render a second breadcrumb under the app header', async () => {
  mocks.read.mockResolvedValue(emptyPlan);
  const client = mount();
  await screen.findByText(/No sources planned yet/);
  expect(screen.queryByText(/Ingestion \/ Log sources/)).toBeNull();
  expect(screen.queryByText('Source onboarding')).toBeNull();
  client.clear();
});

it('shows an API error and lets the user retry successfully', async () => {
  mocks.read.mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValue(emptyPlan);
  const client = mount();
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.queryByText(/No sources planned yet/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await waitFor(() => expect(screen.getByText(/No sources planned yet/)).toBeTruthy());
  expect(mocks.read).toHaveBeenCalledTimes(2);
  client.clear();
});

const wavePlan = {
  ...emptyPlan,
  waves: [{ id: 'w1', name: 'Wave 1', target: '2026-10-31', order: 0 }],
  sources: [{
    id: 's1', name: 'Okta System Log', vendor: 'Okta', expectedType: null, waveId: 'w1', priority: 1, owner: 'jsmith', target: null, notes: '',
    linkedLogSourceId: null, completed: false, completedAt: null, completedBy: null, dismissedLogSourceIds: [], suggestion: null, live: null,
    progress: { c1: false, c2: false, c3: false, c4: false, c5: false, issue: false, ready: false, stage: 'Not connected', late: false, parsingKnown: false },
    rulesNeeded: 0, rules: [], effectiveTarget: '2026-10-31',
  }],
};

it('uses the shared Select and DatePicker instead of native controls (NAN-3792)', async () => {
  mocks.read.mockResolvedValue(wavePlan);
  const client = mount();
  await screen.findByText('Okta System Log');
  const page = screen.getByTestId('source-onboarding-page');
  expect(page.querySelector('select:not([aria-hidden="true"]), input[type="date"]')).toBeNull();
  // Group by is a labelled Radix combobox showing the persisted setting.
  const groupBy = screen.getByRole('combobox', { name: 'Group by' });
  expect(groupBy.textContent).toContain('Wave');
  // Wave target uses the shared date picker trigger (mono day, not a native input).
  const waveTarget = screen.getByRole('button', { name: 'Target for Wave 1' });
  expect(waveTarget.textContent).toContain('2026-10-31');
  // Detail sheet: wave + priority are comboboxes, target is a date picker.
  fireEvent.click(screen.getByRole('button', { name: /Okta System Log/ }));
  const sheet = await screen.findByRole('dialog');
  // Radix renders an aria-hidden native select for form autofill; only visible natives count.
  expect(sheet.querySelector('select:not([aria-hidden="true"]), input[type="date"]')).toBeNull();
  expect(screen.getByRole('combobox', { name: 'Wave' }).textContent).toContain('Wave 1');
  expect(screen.getByRole('combobox', { name: 'Priority' }).textContent).toContain('P1');
  expect(screen.getByRole('button', { name: 'Target' }).textContent).toContain('Inherit wave target');
  client.clear();
});
