// @vitest-environment jsdom
import { beforeAll, afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { UnassignedSources } from './UnassignedSources';

const api = vi.hoisted(() => ({ listIngestCredentials: vi.fn(), getIngestEndpoint: vi.fn(), assignIngestSource: vi.fn() }));
vi.mock('@/lib/api', () => ({ api }));
afterEach(cleanup);
beforeAll(() => {
  Element.prototype.scrollIntoView ??= () => {};
  Element.prototype.hasPointerCapture ??= () => false;
});

function setup(canAssign = true) {
  api.listIngestCredentials.mockResolvedValue({ credentials: [{ credential_id: 'credential-1', kind: 'source', protocol: 'nano_https',
    label: 'unknown-nano-https', state: 'active', source_slugs: ['unknown'], routes: [{ state: 'active', source_slug: 'unknown' }],
    activity: { lake_events_24h: 123, last_seen_at: new Date().toISOString(), redacted: false } }], requests: [] });
  api.getIngestEndpoint.mockResolvedValue({ sources: [{ source_slug: 'vercel', protocol: 'nano_https', label: 'route template: vercel', route_state: 'active' }] });
  api.assignIngestSource.mockReset().mockResolvedValue({ credential_id: 'credential-1', source_slug: 'vercel', label: 'Vercel' });
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter><table><tbody><UnassignedSources sources={[]} canAssign={canAssign} /></tbody></table></MemoryRouter>
  </QueryClientProvider>);
}

describe('NAN-4847 unassigned sources', () => {
  it('shows an unknown credential without any registry entry and assigns the SAME credential', async () => {
    setup();
    await screen.findByText('unknown-nano-https');
    expect(screen.getByText('123')).toBeTruthy();
    expect(screen.getByText('Unassigned').closest('tr')?.querySelector('button')?.textContent).toBe('Assign source type');
    expect(screen.getAllByRole('table')).toHaveLength(1);
    expect(screen.queryByText('Additional ingest sources')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Assign source type' }));
    await screen.findByRole('combobox', { name: 'Source type' });
    fireEvent.change(screen.getByLabelText('Credential name'), { target: { value: 'Vercel' } });
    expect(screen.getByText(/Historical events and batches already accepted/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Assign source' }));
    await waitFor(() => expect(api.assignIngestSource).toHaveBeenCalledWith('credential-1', 'vercel', 'Vercel'));
    expect(screen.queryByText(/token is sealed/)).toBeNull();
  });

  it('keeps the unknown row visible for readers without deploy permission', async () => {
    setup(false);
    await screen.findByText('unknown-nano-https');
    expect(screen.queryByRole('button', { name: 'Assign source type' })).toBeNull();
  });
});
