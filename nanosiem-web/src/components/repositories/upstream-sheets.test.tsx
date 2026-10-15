// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

vi.mock('@/lib/api', () => ({
  api: {
    ruleRepositories: {
      getUpstreamDiff: vi.fn(async () => ({
        file_path: 'rules/windows/lsass_access.yml',
        current_query: 'a\nb\nc\n',
        upstream_query: 'a\nB\nc\n',
      })),
    },
    listGroups: vi.fn(async () => ({ groups: [] })),
    dashboards: { shareDashboard: vi.fn() },
  },
}));

import { UpstreamMergeModal } from './UpstreamMergeModal';
import { DashboardShareDialog } from '@/components/dashboard/DashboardShareDialog';

beforeAll(() => {
  // jsdom lacks matchMedia (useIsMobile) — desktop by default.
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
});

afterEach(cleanup);

const allowed = { allowed: true, missing: [], reason: null };

function withQuery(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

describe('NAN-3209 sheet / dialog conversions', () => {
  it('UpstreamMergeModal renders in a DetailSheet with file path meta and footer actions', async () => {
    const onOpenChange = vi.fn();
    render(
      withQuery(
        <UpstreamMergeModal
          detectionRuleId="r1"
          open
          onOpenChange={onOpenChange}
          onApplyMerge={() => {}}
          diffAccess={allowed}
        />,
      ),
    );
    const sheet = document.querySelector('[data-detail-sheet]') as HTMLElement;
    expect(sheet).not.toBeNull();
    expect(sheet.getAttribute('data-size')).toBe('xl');
    expect(screen.getByRole('dialog', { name: 'Merge Upstream Changes' })).toBe(sheet);
    await screen.findByText('rules/windows/lsass_access.yml');
    expect(screen.getByRole('button', { name: /Apply Merged Changes/ })).toBeTruthy();

    // A hunk decision makes the sheet dirty: Esc asks before discarding.
    fireEvent.click(await screen.findByRole('button', { name: /Accept All/ }));
    fireEvent.keyDown(sheet, { key: 'Escape' });
    await screen.findByText('Discard merge decisions?');
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it('DashboardShareDialog renders a centered dialog, not a sheet', async () => {
    render(
      <DashboardShareDialog
        open
        onOpenChange={() => {}}
        dashboardId="d1"
        dashboardName="SOC overview"
        currentVisibility="private"
        currentSharedGroups={[]}
        isOwner
        onShare={() => {}}
      />,
    );
    const dialog = screen.getByRole('dialog', { name: 'Dashboard Permissions' });
    expect(dialog.hasAttribute('data-detail-sheet')).toBe(false);
    expect(document.querySelector('[data-detail-sheet]')).toBeNull();
    expect(screen.getByText('Visibility for "SOC overview"')).toBeTruthy();
    await waitFor(() => expect(screen.getByRole('button', { name: /Save/ })).toBeTruthy());
  });

  it('DashboardShareDialog view-only variant is also a centered dialog', () => {
    render(
      <DashboardShareDialog
        open
        onOpenChange={() => {}}
        dashboardId="d1"
        dashboardName="SOC overview"
        currentVisibility="private"
        currentSharedGroups={[]}
        isOwner={false}
        onShare={() => {}}
      />,
    );
    expect(screen.getByRole('dialog', { name: 'Dashboard Permissions' })).toBeTruthy();
    expect(screen.getByText('View only')).toBeTruthy();
    expect(document.querySelector('[data-detail-sheet]')).toBeNull();
  });
});
