// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-4132: the parser side panel's pivt tab exists only when AI does.
// Open core has no AI; an unknown capability is treated as none.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, renderHook, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { LogSourceAiPanel } from './LogSourceDetail';
import { useParserSidePanelTabs } from '@/components/log-sources/parserSidePanelTabs';

const mocks = vi.hoisted(() => ({
  capabilities: {} as Record<string, boolean>,
  melodStatus: vi.fn(),
}));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: mocks.capabilities }) }));
vi.mock('@/hooks/use-api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-api')>()),
  useMelodStatus: mocks.melodStatus,
}));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({ start: vi.fn(), loading: false }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: { getSchemaFields: async () => ({ schema: 'ocsf', fields: [] }) },
}));

beforeEach(() => {
  mocks.capabilities = {};
  mocks.melodStatus.mockReset().mockReturnValue({ data: null, loading: false });
});
afterEach(cleanup);

it('open core (no melod): no pivt tab, and a stale ai selection falls back to Test events', () => {
  const { result } = renderHook(() => useParserSidePanelTabs('ai'));
  expect(result.current.aiAvailable).toBe(false);
  expect(result.current.tabs.map((t) => t.label)).toEqual(['Test events', 'Diagnostics']);
  expect(result.current.active).toBe('test');
});

it('enterprise with AI: the pivt tab is still offered and selectable', () => {
  mocks.capabilities = { melod: true };
  const { result } = renderHook(() => useParserSidePanelTabs('ai'));
  expect(result.current.aiAvailable).toBe(true);
  expect(result.current.tabs.map((t) => t.label)).toEqual(['pivt', 'Test events', 'Diagnostics']);
  expect(result.current.active).toBe('ai');
});

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LogSourceAiPanel parserId="feed_x" sourceName="x" sourceType="x" currentVrl="." onVrlUpdate={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

it('open core: the AI panel skips the ai-availability probe', () => {
  mocks.melodStatus.mockReturnValue({ data: { connected: true }, loading: false });
  renderPanel();
  expect(mocks.melodStatus).toHaveBeenCalledWith({ skip: true });
  expect(screen.getByText('pivt not configured')).toBeTruthy();
});

it('enterprise with AI: the AI panel probes availability', () => {
  mocks.capabilities = { melod: true };
  renderPanel();
  expect(mocks.melodStatus).toHaveBeenCalledWith({ skip: false });
});
