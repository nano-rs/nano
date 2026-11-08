// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/** NAN-4914: connector vendor credentials (okta, google_workspace, slack,
 *  saas_api) can be rotated from the Credentials page. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { CloudCredential } from '@/lib/api/types';
import type { ConnectorSpecInfo } from '@/lib/api/connector-feeds';
import {
  connectorSecretFields,
  connectorSecretsPayload,
  connectorSecretsValid,
} from '../connector-credentials';

const specs: ConnectorSpecInfo[] = [
  { name: 'okta_system_log', display_name: 'Okta', kind: 'collector', credential_provider: 'okta', source_type: 'okta', schedule: '*/2 * * * *', config_fields: ['OKTA_DOMAIN'], optional_config_fields: [], credential_fields: ['API_TOKEN'] },
  { name: 'google_workspace', display_name: 'GWS', kind: 'collector', credential_provider: 'google_workspace', source_type: 'gws_{{item}}', schedule: '*/5 * * * *', config_fields: ['ADMIN_EMAIL', 'STREAMS'], optional_config_fields: [], credential_fields: ['CLIENT_EMAIL', 'PRIVATE_KEY'] },
  { name: 'slack', display_name: 'Slack', kind: 'collector', credential_provider: 'slack', source_type: 'slack_access_log', schedule: '0 * * * *', config_fields: ['TEAM_ID'], optional_config_fields: [], credential_fields: ['USER_TOKEN'] },
  { name: 'netskope', display_name: 'Netskope', kind: 'collector', credential_provider: 'saas_api', source_type: 'netskope_{{item}}', schedule: '*/5 * * * *', config_fields: ['TENANT_HOST'], optional_config_fields: [], credential_fields: ['API_TOKEN'] },
];

vi.mock('@/lib/api', () => ({
  api: { connectorFeeds: { listSpecs: () => Promise.resolve(specs) } },
}));

import { RotateCredentialForm } from '@/components/credentials/CredentialsManager';

function cred(provider: string): CloudCredential {
  return {
    id: 'cred_x', name: `${provider} cred`, provider, description: null, region: null, external_id: null,
    environment: null, expires_at: null, last_used_at: null, active_version: 1,
    created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
  } as unknown as CloudCredential;
}

function renderForm(provider: string, onSubmit = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RotateCredentialForm cred={cred(provider)} submitting={false} onCancel={() => {}} onSubmit={onSubmit} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return onSubmit;
}

afterEach(cleanup);

describe('connector credential fields', () => {
  it('come from the connector spec, GWS as a key file', () => {
    expect(connectorSecretFields('okta', specs)).toEqual(['API_TOKEN']);
    expect(connectorSecretFields('slack', specs)).toEqual(['USER_TOKEN']);
    expect(connectorSecretFields('saas_api', specs)).toEqual(['API_TOKEN']);
    expect(connectorSecretFields('google_workspace', specs)).toEqual(['credentials_json']);
    expect(connectorSecretsValid(['API_TOKEN'], { API_TOKEN: '  ' })).toBe(false);
    expect(connectorSecretsPayload(['API_TOKEN'], { API_TOKEN: ' t ', EXTRA: 'x' })).toEqual({ API_TOKEN: 't' });
  });

  it.each(['okta', 'slack', 'saas_api'])('rotates a %s token', async (provider) => {
    const onSubmit = renderForm(provider);
    const field = await screen.findByLabelText(provider === 'slack' ? 'USER_TOKEN' : 'API_TOKEN');
    const submit = screen.getByRole('button', { name: /rotate/i });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(field, { target: { value: 'new-token' } });
    await waitFor(() => expect((submit as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(submit);
    const key = provider === 'slack' ? 'USER_TOKEN' : 'API_TOKEN';
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ credentials: { [key]: 'new-token' } }));
  });

  it('rotates a Google Workspace credential with a new service-account key', async () => {
    const onSubmit = renderForm('google_workspace');
    const key = JSON.stringify({ client_email: 'sa@p.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' });
    fireEvent.change(await screen.findByLabelText(/service account key/i), { target: { value: key } });
    fireEvent.click(screen.getByRole('button', { name: /rotate/i }));
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ credentials: { credentials_json: key } }));
  });
});
