// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-2593: the Issue step. A fake SIEM API seals the token to the browser's
 * real WebCrypto public key (the platform algorithm), so these tests drive
 * key generation, reveal-once and local decryption end to end.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { IngestCredentialRequestInput, SenderTemplateCatalog, TenantIngestEndpoint } from '@/lib/api/types';
import { sealToRevealKey } from '@/lib/credential-seal.fixture';
import { IssueCredentialPanel } from './IssueCredentialPanel';

const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const HOST = `${TENANT}.ingest.nano.rs`;

const state = vi.hoisted(() => ({
  permissions: new Set<string>(['log_sources:deploy', 'log_sources:view']),
  restricted: [] as Array<{ source_type: string }>,
  requests: [] as IngestCredentialRequestInput[],
  sealed: new Map<string, string>(),
  revealed: new Set<string>(),
  tokens: [] as string[],
  refuseWith: null as string | null,
  /** The issuance guard's verdict the precheck returns; 'fail' = the endpoint errors (older API). */
  verdict: null as string | null | 'fail',
  prechecks: [] as Array<{ kind: string; source_slugs: string[] }>,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_me' }, hasPermission: (p: string) => state.permissions.has(p) }),
}));

vi.mock('@/lib/api', () => {
  class ApiClientError extends Error {
    constructor(message: string, public code: string, public details?: unknown, public status?: number) {
      super(message);
    }
  }
  const requestId = (n: number) => `0f6f5a1e-7c2b-4d1a-8e3f-${String(n).padStart(12, '0')}`;
  const reveal = (id: string, extra: object = {}) => {
    const input = state.requests[Number(id.slice(-12)) - 1];
    return {
      request_id: id, tenant_id: TENANT, state: 'issued', kind: 'source', protocol: input.protocol, label: input.label,
      source_slugs: input.source_slugs, credential_id: `cred-${id.slice(-2)}`, sealed_token_ready: !state.revealed.has(id),
      revealed_at: state.revealed.has(id) ? '2026-09-22T00:00:00Z' : null, sealed_token: null, ...extra,
    };
  };
  return {
    ApiClientError,
    api: {
      sourceScopes: { listRestricted: vi.fn(async () => ({ restricted: state.restricted })) },
      precheckIngestCredential: vi.fn(async (input: { kind: string; source_slugs: string[] }) => {
        state.prechecks.push(input);
        if (state.verdict === 'fail') throw new ApiClientError('Not Found', 'NOT_FOUND', undefined, 404);
        const v = state.verdict;
        return {
          verdict: v,
          allowed: v === null,
          needs_acknowledgement: v === 'restricted_sources_unacknowledged',
          blocked: v !== null && v !== 'restricted_sources_unacknowledged',
        };
      }),
      getSenderTemplates: vi.fn(async (): Promise<SenderTemplateCatalog> => ({
        version: 1,
        placeholders: [],
        templates: [
          { id: 'curl-hec', sender: 'curl', sender_name: 'curl', protocol: 'hec', credential_kinds: ['source'], format: 'shell',
            title: 'Send a test event (HEC)', description: 'One event.',
            body: 'curl -sS "{{hec_url}}" -H "Authorization: Splunk {{token}}"' },
          { id: 'vector-hec', sender: 'vector', sender_name: 'Vector', protocol: 'hec', credential_kinds: ['source'], format: 'toml',
            title: 'Vector', description: 'Sink.', body: '[sinks.nano_{{label}}]\ndefault_token = "{{token}}"' },
        ],
      })),
      requestIngestCredential: vi.fn(async (input: IngestCredentialRequestInput) => {
        if (state.refuseWith) throw new ApiClientError(state.refuseWith, 'FORBIDDEN', undefined, 403);
        state.requests.push(input);
        const id = requestId(state.requests.length);
        const token = `nano_tok_${state.requests.length}_abcdefghijklmnopqrstuvwxyz0123456789`;
        state.tokens.push(token);
        state.sealed.set(id, sealToRevealKey(input.reveal_public_key, token, id, TENANT));
        return { id, protocol: input.protocol, label: input.label, state: 'pending', requested_by: 'user_me', requested_at: '',
          updated_at: '', kind: 'source', source_slugs: input.source_slugs, restricted_sources_acknowledged: false, sealed_token_ready: false };
      }),
      getIngestCredentialRequest: vi.fn(async (id: string) => reveal(id)),
      // NAN-2599: the first-event checklist after the token is copied.
      getIngestCredentialActivity: vi.fn(async (credentialId: string) => ({
        credential_id: credentialId, window_hours: 1, redacted: false,
        edge: { first_accepted_at: '2026-09-22T00:00:04Z', last_accepted_at: '2026-09-22T00:00:04Z', last_rejected_at: null,
          last_rejection_class: null, last_rejection_status: null, requests_24h: 1, events_24h: 1, bytes_24h: 100,
          unknown_event_requests_24h: 0, sampled_at: null, recorded_at: null },
        lake: { events: 0, bytes: 0, parse_failures: 0, first_event_at: null, last_event_at: null, first_searchable_at: null,
          last_searchable_at: null, sources: [], hours: [] },
        first_event: { received_at_edge: '2026-09-22T00:00:04Z', searchable_at: null, state: 'received' },
      })),
      revealIngestCredential: vi.fn(async (id: string) => {
        if (state.revealed.has(id)) throw new ApiClientError('Gone: already_revealed: gone', 'GONE', undefined, 410);
        state.revealed.add(id);
        return reveal(id, { sealed_token: state.sealed.get(id), sealed_token_ready: false });
      }),
    },
  };
});

import { api } from '@/lib/api';

const endpoint: TenantIngestEndpoint = {
  hostname: HOST, base_url: `https://${HOST}`, hec_url: `https://${HOST}/services/collector/event`,
  otlp_logs_url: `https://${HOST}/v1/logs`, otlp_traces_url: `https://${HOST}/v1/traces`, otlp_metrics_url: `https://${HOST}/v1/metrics`,
  otlp_telemetry_ingested: false, nano_https_url: `https://${HOST}/ingest`, hec_health_url: `https://${HOST}/services/collector/health`,
  endpoint_state: 'ready', sources: [], credential_issuance: { managed_by_platform: false, reason: '', detail: '' },
  ingress_contract: { version: 1, credential_kinds: ['source'], collector_credentials: false, source_declarations: [] },
};
const source = { slug: 'palo_alto_traffic', protocols: ['hec' as const], enrolled: true };

let client: QueryClient;
function renderPanel(src: typeof source = source) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IssueCredentialPanel endpoint={endpoint} source={src} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const writeText = vi.fn(async (text: string) => { void text; });

beforeEach(() => {
  state.permissions = new Set(['log_sources:deploy', 'log_sources:view']);
  state.restricted = [];
  state.requests = [];
  state.sealed.clear();
  state.revealed.clear();
  state.tokens = [];
  state.refuseWith = null;
  state.verdict = null;
  state.prechecks = [];
  writeText.mockClear();
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
  vi.mocked(api.revealIngestCredential).mockClear();
});
afterEach(cleanup);

async function issue() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /issue (another )?credential/i }));
  });
}

describe('IssueCredentialPanel (NAN-2593)', () => {
  it('reveals once, decrypts in the browser, focuses Copy and fills the snippets', async () => {
    renderPanel();
    await issue();
    const token = await screen.findByLabelText('Ingest token');
    expect((token as HTMLInputElement).value).toBe(state.tokens[0]);
    expect(api.revealIngestCredential).toHaveBeenCalledTimes(1);
    expect(state.requests[0]).toMatchObject({ protocol: 'hec', kind: 'source', source_slugs: ['palo_alto_traffic'], label: 'palo_alto_traffic-hec', reveal_key_alg: 'x25519' });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Copy token' })));

    const snippet = await screen.findByTestId('sender-snippet-body');
    expect(snippet.textContent).toBe(`curl -sS "https://${HOST}/services/collector/event" -H "Authorization: Splunk ${state.tokens[0]}"`);
    fireEvent.click(screen.getByRole('tab', { name: 'Vector' }));
    expect(screen.getByTestId('sender-snippet-body').textContent).toContain('[sinks.nano_palo_alto_traffic_hec]');

    // The token never enters the query cache or browser storage.
    const cached = JSON.stringify(client.getQueryCache().getAll().map((q) => q.state.data));
    expect(cached).not.toContain(state.tokens[0]);
    expect(JSON.stringify({ ...localStorage })).not.toContain(state.tokens[0]);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(state.tokens[0]);
  });

  it('never discards an unsaved token: re-issuing stacks, and hiding an uncopied one asks first', async () => {
    renderPanel();
    await issue();
    await screen.findByLabelText('Ingest token');
    await issue();
    await waitFor(() => expect(screen.getAllByLabelText('Ingest token')).toHaveLength(2));
    const values = screen.getAllByLabelText('Ingest token').map((el) => (el as HTMLInputElement).value);
    expect(values).toEqual([state.tokens[1], state.tokens[0]]);

    // Hide the older, uncopied token: a confirmation, and "Keep it" keeps it.
    const older = screen.getAllByTestId('one-time-token')[1];
    fireEvent.click(within(older).getByRole('button', { name: /i've saved it/i }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toMatch(/never be shown again/);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep it' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(screen.getAllByLabelText('Ingest token')).toHaveLength(2);

    // Once copied, "I've saved it" hides it without asking.
    const newer = screen.getAllByTestId('one-time-token')[0];
    await act(async () => {
      fireEvent.click(within(newer).getByRole('button', { name: 'Copy token' }));
    });
    expect(writeText).toHaveBeenCalledWith(state.tokens[1]);
    fireEvent.click(within(newer).getByRole('button', { name: /i've saved it/i }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(screen.getAllByLabelText('Ingest token').map((el) => (el as HTMLInputElement).value)).toEqual([state.tokens[0]]);
  });

  it('starts the first-event checklist once the token is copied, and keeps it after the token is hidden (NAN-2599)', async () => {
    renderPanel();
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(screen.queryByTestId('first-event-panel')).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy token' }));
    });
    const panel = await screen.findByTestId('first-event-panel');
    await waitFor(() => expect(api.getIngestCredentialActivity).toHaveBeenCalledWith('cred-01', 1));
    await waitFor(() => expect(within(panel).getByTestId('first-event-step-received').getAttribute('data-state')).toBe('done'));
    expect(within(panel).getByTestId('first-event-step-searchable').getAttribute('data-state')).toBe('active');
    fireEvent.click(screen.getByRole('button', { name: /i've saved it/i }));
    expect(screen.queryByLabelText('Ingest token')).toBeNull();
    expect(screen.getByTestId('first-event-panel')).toBeTruthy();
  });

  // NAN-2617: the UI follows the server's issuance guard (decision b), not "any restricted source".
  it('a restricted source the issuer is not restricted from needs no acknowledgement', async () => {
    state.permissions.add('source_scopes:view');
    state.restricted = [{ source_type: 'palo_alto_traffic' }];
    state.verdict = null;
    renderPanel();
    await waitFor(() => expect(state.prechecks).toEqual([{ kind: 'source', source_slugs: ['palo_alto_traffic'] }]));
    expect(screen.queryByTestId('restricted-ack')).toBeNull();
    const button = screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0].restricted_sources_acknowledged).toBeUndefined();
  });

  it('source_restricted from the precheck blocks with the source_scopes:manage copy', async () => {
    state.verdict = 'source_restricted';
    renderPanel();
    const box = await screen.findByTestId('restricted-ack');
    expect(box.textContent).toMatch(/needs the source_scopes:manage permission/);
    expect(within(box).queryByRole('checkbox')).toBeNull();
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('restricted_sources_unacknowledged from the precheck requires the explicit acknowledgement', async () => {
    state.permissions.add('source_scopes:manage');
    state.verdict = 'restricted_sources_unacknowledged';
    renderPanel();
    const box = await screen.findByTestId('restricted-ack');
    expect(box.textContent).toMatch(/\(you have it\) and your\s+acknowledgement/);
    const button = screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(within(box).getByRole('checkbox'));
    expect(button.disabled).toBe(false);
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0].restricted_sources_acknowledged).toBe(true);
  });

  it('another precheck refusal is shown up front and blocks issuing', async () => {
    state.verdict = 'membership_inactive';
    renderPanel();
    const blocked = await screen.findByTestId('precheck-blocked');
    expect(blocked.textContent).toMatch(/Membership inactive/);
    expect(screen.queryByTestId('restricted-ack')).toBeNull();
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('a failed precheck (older API) asks for nothing up front and relies on the server refusal', async () => {
    state.permissions.add('source_scopes:view');
    state.restricted = [{ source_type: 'palo_alto_traffic' }];
    state.verdict = 'fail';
    renderPanel();
    await waitFor(() => expect(state.prechecks.length).toBe(1));
    expect(screen.queryByTestId('restricted-ack')).toBeNull();
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('turns a 403 reason code into clear copy and offers the acknowledgement it asks for', async () => {
    state.permissions.add('source_scopes:manage');
    state.refuseWith = 'Forbidden: ingest_credential_refused: restricted_sources_unacknowledged';
    renderPanel();
    await issue();
    const box = await screen.findByTestId('restricted-ack');
    expect(screen.queryByRole('alert')).toBeNull();
    state.refuseWith = null;
    fireEvent.click(within(box).getByRole('checkbox'));
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0].restricted_sources_acknowledged).toBe(true);
  });

  it('shows why a refused request failed', async () => {
    state.refuseWith = 'Forbidden: ingest_credential_refused: source_restricted';
    renderPanel();
    await issue();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(/Source is hidden from you/);
    expect(screen.queryByLabelText('Ingest token')).toBeNull();
  });

  it('warns that a source still rolling out is issued once enrolled', async () => {
    renderPanel({ slug: 'my_app', protocols: [], enrolled: false } as unknown as typeof source);
    expect(screen.getByText(/still rolling out to your parser cell/)).toBeTruthy();
    expect(screen.getAllByRole('radio').map((r) => r.textContent)).toEqual(['HEC', 'HTTPS JSON']);
  });
});
