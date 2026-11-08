// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4941: the retired ingestion pages redirect into Log Sources, keeping the item. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const flaky = vi.hoisted(() => ({ failures: 0 }));
vi.mock('@/lib/api', () => {
  class ApiClientError extends Error {
    constructor(message: string, public code?: string, public details?: unknown, public status?: number) { super(message); }
  }
  return {
    ApiClientError,
    api: {
      getCredential: async (id: string) => {
        if (id === 'cred_okta') return { id, name: 'Okta', provider: 'okta', active_version: 1 };
        if (id === 'cred_aws') return { id, name: 'AWS', provider: 'aws_s3', active_version: 1 };
        if (id === 'cred_flaky_okta') {
          if (flaky.failures > 0) { flaky.failures -= 1; throw new ApiClientError('Service unavailable', 'UNAVAILABLE', undefined, 503); }
          return { id, name: 'Okta', provider: 'okta', active_version: 1 };
        }
        throw new ApiClientError('Credential not found', 'NOT_FOUND', undefined, 404);
      },
    },
  };
});
import {
  LegacyCredentialNewRedirect,
  LegacyCredentialRedirect,
  LegacyPullFeedsRedirect,
  LegacySourceConfigRedirect,
} from './LegacyIngestionRedirects';
import { credentialTarget } from '@/lib/ingestion-paths';

afterEach(cleanup);

function Where() {
  const { pathname, search } = useLocation();
  return <div data-testid="where">{pathname + search}</div>;
}

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/ingestion/source-configurations" element={<LegacySourceConfigRedirect />} />
          <Route path="/ingestion/source-configurations/:id" element={<LegacySourceConfigRedirect />} />
          <Route path="/ingestion/credentials" element={<LegacyCredentialRedirect />} />
          <Route path="/ingestion/credentials/new" element={<LegacyCredentialNewRedirect />} />
          <Route path="/ingestion/credentials/:id" element={<LegacyCredentialRedirect />} />
          <Route path="/ingestion/pull-feeds" element={<LegacyPullFeedsRedirect />} />
          <Route path="/ingestion/connector-feeds" element={<LegacyPullFeedsRedirect />} />
          <Route path="/ingestion/log-sources/*" element={<Where />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('legacy ingestion links', () => {
  it.each([
    ['/ingestion/source-configurations', '/ingestion/log-sources/cloud-pull'],
    ['/ingestion/source-configurations/sc_123', '/ingestion/log-sources/inputs/sc_123'],
    ['/ingestion/credentials', '/ingestion/log-sources/cloud-pull'],
    ['/ingestion/credentials?add=gcp_pubsub', '/ingestion/log-sources/cloud-pull?add=gcp_pubsub'],
    ['/ingestion/credentials/new', '/ingestion/log-sources/cloud-pull?add=aws_s3'],
    ['/ingestion/credentials/cred_aws', '/ingestion/log-sources/cloud-pull?cred=cred_aws'],
    ['/ingestion/credentials/cred_okta', '/ingestion/log-sources/pull-feeds?cred=cred_okta'],
    ['/ingestion/credentials?cred=cred_okta', '/ingestion/log-sources/pull-feeds?cred=cred_okta'],
    ['/ingestion/pull-feeds', '/ingestion/log-sources/pull-feeds'],
    ['/ingestion/connector-feeds', '/ingestion/log-sources/pull-feeds'],
  ])('%s → %s', async (from, to) => {
    renderAt(from);
    expect((await screen.findByTestId('where')).textContent).toBe(to);
  });
});

describe('credentialTarget', () => {
  it('drops ?add= for a connector provider, which is entered with its feed', () => {
    expect(credentialTarget('okta', { add: 'okta' })).toBe('/ingestion/log-sources/pull-feeds');
    expect(credentialTarget('azure_event_hubs', { add: 'azure_event_hubs' })).toBe('/ingestion/log-sources/cloud-pull?add=azure_event_hubs');
  });
});

describe('legacy credential lookup failures (NAN-4941 review P2)', () => {
  it('a confirmed 404 says the credential is gone instead of guessing a destination', async () => {
    renderAt('/ingestion/credentials/cred_gone');
    const box = await screen.findByTestId('legacy-credential-not-found');
    expect(box.textContent).toContain('cred_gone');
    expect(screen.queryByTestId('where')).toBeNull();
  });

  it('a transient failure keeps the id, offers a retry, and lands on the right tab once the lookup succeeds', async () => {
    flaky.failures = 1;
    renderAt('/ingestion/credentials/cred_flaky_okta');
    const box = await screen.findByTestId('legacy-credential-error');
    expect(box.textContent).toContain('cred_flaky_okta');
    expect(screen.queryByTestId('where')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect((await screen.findByTestId('where')).textContent).toBe('/ingestion/log-sources/pull-feeds?cred=cred_flaky_okta');
  });
});
