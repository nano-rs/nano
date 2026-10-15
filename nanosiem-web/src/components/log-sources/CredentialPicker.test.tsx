// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3620: the stored-credential picker is replaced by a Cloud pull pointer on hosted-shared. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { CredentialPicker } from './CredentialPicker';

const mocks = vi.hoisted(() => ({ shared: false, listCredentials: vi.fn() }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => mocks.shared }));
vi.mock('@/lib/api', () => ({ api: { listCredentials: mocks.listCredentials } }));

function renderPicker() {
  return render(
    <MemoryRouter>
      <CredentialPicker provider="aws_s3" value={undefined} onChange={() => {}} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mocks.listCredentials.mockReset();
  mocks.listCredentials.mockResolvedValue({
    credentials: [{ id: 'cred_1', name: 'prod-s3', provider: 'aws_s3', description: null, region: 'us-east-1' }],
    total: 1,
  });
});
afterEach(() => cleanup());

describe('CredentialPicker', () => {
  it('on hosted-shared shows a Cloud pull pointer and never lists or links stored credentials', () => {
    mocks.shared = true;
    const { container } = renderPicker();
    expect(screen.getByTestId('credential-picker-retired')).toBeTruthy();
    const link = screen.getByRole('link', { name: 'Log Sources → Cloud pull' });
    expect(link.getAttribute('href')).toBe('/ingestion/log-sources/cloud-pull');
    expect(mocks.listCredentials).not.toHaveBeenCalled();
    expect(container.querySelector('a[href^="/ingestion/credentials"]')).toBeNull();
    expect(screen.queryByText('Create new')).toBeNull();
  });

  it('on open core and dedicated lists stored credentials with a create link', async () => {
    mocks.shared = false;
    const { container } = renderPicker();
    await waitFor(() => expect(mocks.listCredentials).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('credential-picker-retired')).toBeNull();
    expect(screen.getByText('Create new')).toBeTruthy();
    expect(container.querySelector('a[href="/ingestion/credentials?add=aws_s3"]')).not.toBeNull();
  });
});
