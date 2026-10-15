// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3280: /observability and /observability/:tab had no breadcrumb config,
// so the TopBar title (`useCurrentPageTitle`) fell back to "Home".

import { afterEach, describe, it, expect, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { AppBreadcrumbs, useCurrentPageTitle } from './AppBreadcrumbs';
import { ObservabilityConsole } from '@/pages/observability/ObservabilityConsole';

vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: {} }) }));
// Stub the console's data hooks and tab bodies; only the header is under test.
vi.mock('@/hooks/use-telemetry-availability', () => ({
  useTelemetryAvailability: () => ({ loading: true, telemetry: null, unavailable: false }),
}));
const Empty = { default: () => null };
vi.mock('@/pages/observability/tabs/ServicesTab', () => Empty);
vi.mock('@/pages/observability/tabs/TracesTab', () => Empty);
vi.mock('@/pages/observability/tabs/MetricsTab', () => Empty);
vi.mock('@/pages/observability/tabs/InfraTab', () => Empty);
vi.mock('@/pages/observability/tabs/RumTab', () => Empty);
vi.mock('@/pages/observability/tabs/SyntheticsTab', () => Empty);
vi.mock('@/pages/observability/tabs/AlertsTab', () => Empty);
vi.mock('@/pages/observability/tabs/SlosTab', () => Empty);
vi.mock('@/pages/observability/ServiceDetail', () => ({ ServiceDetail: () => null }));
vi.mock('@/components/ui/date-time-range-picker', () => ({ DateTimeRangePicker: () => null }));

function TopBarStub() {
  const title = useCurrentPageTitle();
  return (
    <div>
      <span data-testid="title">{title}</span>
      <div data-testid="trail">
        <AppBreadcrumbs />
      </div>
    </div>
  );
}

function renderAt(path: string, page: React.ReactNode = <ObservabilityConsole />) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <BreadcrumbProvider>
        <TopBarStub />
        <Routes>
          <Route path="/observability" element={page} />
          <Route path="/observability/:tab" element={page} />
          <Route path="*" element={null} />
        </Routes>
      </BreadcrumbProvider>
    </MemoryRouter>,
  );
}

describe('AppBreadcrumbs — observability header (NAN-3280)', () => {
  afterEach(cleanup);

  it('titles bare /observability "Observability", not "Home"', () => {
    renderAt('/observability');
    expect(screen.getByTestId('title').textContent).toBe('Observability');
    expect(screen.getByTestId('trail').textContent).toContain('Home');
  });

  it.each([
    ['services', 'Services'],
    ['traces', 'Traces'],
    ['metrics', 'Metrics'],
    ['infrastructure', 'Infrastructure'],
    ['rum', 'RUM'],
    ['synthetics', 'Synthetics'],
    ['alerts', 'Alerts'],
    ['slos', 'SLOs'],
  ])('titles /observability/%s with the tab under an Observability parent', async (tab, label) => {
    renderAt(`/observability/${tab}`);
    await waitFor(() => expect(screen.getByTestId('title').textContent).toBe(label));
    const parent = screen.getByRole('link', { name: 'Observability' });
    expect(parent.getAttribute('href')).toBe('/observability');
  });

  it('titles a service drill-in with the service name', async () => {
    renderAt('/observability/services?service=checkout');
    await waitFor(() => expect(screen.getByTestId('title').textContent).toBe('checkout'));
    expect(screen.getByRole('link', { name: 'Observability' })).toBeTruthy();
  });

  it.each([
    ['/reports', 'Reports'],
    ['/settings', 'Settings'],
    ['/settings/notifications', 'Notifications'],
    ['/settings/source-scopes', 'Source Visibility'],
    ['/rules/retro-hunt/new', 'New retro-hunt'],
  ])('no longer falls back to "Home" on %s', (path, label) => {
    renderAt(path, null);
    expect(screen.getByTestId('title').textContent).toBe(label);
  });
});
