// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5724: pages open without settings:view read the air-gap / managed flags
 * from `GET /api/system/deployment` (any signed-in user), never from
 * `/api/system/config` (settings:view). useAirGap fails CLOSED: egress
 * controls stay withheld until the flag is known to be false.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReactNode } from 'react';

const getDeploymentFlags = vi.fn(async () => ({ air_gap: false, managed: true }));
const getSystemConfig = vi.fn(async () => ({ air_gap: true }));
vi.mock('@/lib/api', async (orig) => {
  const actual = await orig<typeof import('@/lib/api')>();
  return {
    ...actual,
    api: { ...actual.api, getDeploymentFlags: () => getDeploymentFlags(), getSystemConfig: () => getSystemConfig() },
  };
});

import { useAirGap, useDeploymentFlags } from './use-air-gap';

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 1 } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

afterEach(() => {
  cleanup();
  getDeploymentFlags.mockClear();
  getSystemConfig.mockClear();
});

describe('useDeploymentFlags / useAirGap (NAN-5724)', () => {
  it('reads /api/system/deployment, not /api/system/config', async () => {
    const { result } = renderHook(() => useDeploymentFlags(), { wrapper });
    await waitFor(() => expect(result.current).toEqual({ airGap: false, managed: true }));
    expect(getSystemConfig).not.toHaveBeenCalled();
  });

  it('withholds egress controls until the flag is known to be false', async () => {
    const { result } = renderHook(() => useAirGap(), { wrapper });
    expect(result.current).toBe(true);
    await waitFor(() => expect(result.current).toBe(false));
  });

  it('stays closed while the read fails', async () => {
    getDeploymentFlags.mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useAirGap(), { wrapper });
    await waitFor(() => expect(getDeploymentFlags.mock.calls.length).toBeGreaterThanOrEqual(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current).toBe(true);
    getDeploymentFlags.mockReset();
    getDeploymentFlags.mockImplementation(async () => ({ air_gap: false, managed: true }));
  });

  it('is true on an air-gapped install', async () => {
    getDeploymentFlags.mockResolvedValueOnce({ air_gap: true, managed: false });
    const { result } = renderHook(() => useAirGap(), { wrapper });
    await waitFor(() => expect(getDeploymentFlags).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 10));
    expect(result.current).toBe(true);
  });
});

describe('pages open without settings:view do not read /api/system/config (NAN-5724)', () => {
  const pages = [
    'pages/RuleRepositories.tsx',
    'pages/ParserRepositories.tsx',
    'enterprise/pages/PlaybookRepositories.tsx',
    'pages/Marketplace.tsx',
    'components/marketplace/MarketplaceDrawer.tsx',
  ];
  it.each(pages)('%s uses useAirGap', (rel) => {
    const src = readFileSync(resolve(__dirname, '..', rel), 'utf8');
    expect(src).not.toMatch(/getSystemConfig|useSystemConfig/);
    expect(src).toMatch(/useAirGap\(\)/);
  });

  it.each([
    'enterprise/pages/Settings/MelodSettings.tsx',
    'components/layout/settings/SettingsRail.tsx',
    'pages/Settings/SettingsLanding.tsx',
  ])('%s reads deployment flags, not system config', (rel) => {
    const src = readFileSync(resolve(__dirname, '..', rel), 'utf8');
    expect(src).not.toMatch(/getSystemConfig|useSystemConfig/);
    expect(src).toMatch(/useDeploymentFlags\(\)/);
  });
});
