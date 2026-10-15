// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3844: ingest mode is unknown until /api/capabilities answers. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    tenantRuntime: { key: 'dedicated', scope: { kind: 'dedicated' } },
  }),
}));

import { CapabilitiesProvider } from './CapabilitiesProvider';
import { useIngestGate } from '@/hooks/use-capabilities';

function Probe() {
  const gate = useIngestGate();
  return <span data-testid="mode">{`${gate.mode}:${gate.blocked}`}</span>;
}

function renderProvider() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CapabilitiesProvider>
          <Probe />
        </CapabilitiesProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function respond(body: unknown, ok = true) {
  let resolve!: (r: Response) => void;
  const pending = new Promise<Response>((r) => { resolve = r; });
  vi.stubGlobal('fetch', vi.fn(() => pending));
  return () => resolve({ ok, status: ok ? 200 : 500, json: async () => body } as Response);
}

const BODY = { edition: 'open', version: 't', capabilities: {} };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('is unknown (blocked) while loading, then tenzir_only', async () => {
  const answer = respond({ ...BODY, ingestMode: 'tenzir_only' });
  renderProvider();
  expect(screen.getByTestId('mode').textContent).toBe('unknown:true');
  answer();
  await waitFor(() => expect(screen.getByTestId('mode').textContent).toBe('tenzir_only:true'));
});

it('opens up once the API says vector', async () => {
  const answer = respond({ ...BODY, ingestMode: 'vector' });
  renderProvider();
  answer();
  await waitFor(() => expect(screen.getByTestId('mode').textContent).toBe('vector:false'));
});

it('treats an older API without ingestMode as vector', async () => {
  const answer = respond(BODY);
  renderProvider();
  answer();
  await waitFor(() => expect(screen.getByTestId('mode').textContent).toBe('vector:false'));
});

it('falls back to vector when the fetch fails, so surfaces are not locked for good', async () => {
  const answer = respond({}, false);
  renderProvider();
  answer();
  // The provider retries once (about 1 s) before it gives up.
  await waitFor(() => expect(screen.getByTestId('mode').textContent).toBe('vector:false'), { timeout: 4000 });
});
