// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3038: the IOC lists page lists counts + publication state, creates a
 * list from pasted indicators and publishes without any enrichment code.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { IocListSummary } from '@/lib/api/ioc-lists';
import { uploadFormatFor } from '@/lib/api/ioc-lists';
import { IocLists } from './IocLists';
import { expiryInstant } from './IocExpirySelect';

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  remove: vi.fn(),
  publish: vi.fn(),
  indicators: vi.fn(),
}));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
const limits = { indicators_per_list: 8000, indicators_per_tenant: 25000, list_count: 50, upload_bytes: 8 * 1024 * 1024 };
vi.mock('@/lib/api', () => ({ api: { iocLists: { ...mocks, list: async () => ({ lists: await mocks.list(), limits }) } } }));

const summary: IocListSummary = {
  id: '5fb667bb-2a93-4f33-9b60-72d683bd0dde',
  name: 'apt-infra',
  description: 'campaign infrastructure',
  indicator_count: 3,
  counts: { ip: 2, domain: 1 },
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  last_published_at: null,
  last_published_count: null,
  publish_pending: true,
  publish_state: 'never',
  publish_started_at: null,
  publish_error: null,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <IocLists />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('IocLists', () => {
  it('renders lists with per-type counts and an unpublished state', async () => {
    mocks.list.mockResolvedValue([summary]);
    renderPage();
    expect(await screen.findByText('apt-infra')).toBeTruthy();
    expect(screen.getByText('never')).toBeTruthy();
    expect(screen.getByText('campaign infrastructure')).toBeTruthy();
  });

  it('shows usage against tenant limits and upload maximum', async () => {
    mocks.list.mockResolvedValue([summary]);
    renderPage();
    expect(await screen.findByText('1 / 50')).toBeTruthy();
    expect(screen.getByText('3 / 25,000')).toBeTruthy();
    fireEvent.click(screen.getByText('New IOC list'));
    expect(screen.getByText(/max file 8 MiB/)).toBeTruthy();
  });

  it('rejects oversized files before reading or sending them', async () => {
    mocks.list.mockResolvedValue([]);
    renderPage();
    fireEvent.click(await screen.findByText('New IOC list'));
    const file = new File(['x'], 'huge.csv');
    Object.defineProperty(file, 'size', { value: limits.upload_bytes + 1 });
    const read = vi.fn();
    Object.defineProperty(file, 'text', { value: read });
    fireEvent.change(screen.getByLabelText('IOC file'), { target: { files: [file] } });
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('8,388,608 byte file limit'));
    expect(read).not.toHaveBeenCalled();
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('shows a server capacity refusal in the upload panel', async () => {
    mocks.list.mockResolvedValue([]);
    mocks.create.mockRejectedValue(new Error('IOC indicators_per_tenant limit 25000 exceeded: current usage 24999, attempted 25001'));
    renderPage();
    fireEvent.click(await screen.findByText('New IOC list'));
    fireEvent.change(screen.getByPlaceholderText('apt29-infra'), { target: { value: 'campaign' } });
    fireEvent.change(document.querySelector('textarea')!, { target: { value: 'a.example' } });
    fireEvent.click(screen.getByText('Create'));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('current usage 24999, attempted 25001'));
  });

  it('publishes a list', async () => {
    mocks.list.mockResolvedValue([summary]);
    mocks.publish.mockResolvedValue({ list: { ...summary, publish_state: 'publishing' }, started: true });
    renderPage();
    fireEvent.click(await screen.findByLabelText('Publish'));
    await waitFor(() => expect(mocks.publish).toHaveBeenCalledWith(summary.id));
  });

  // NAN-3882: publish answers at once; the row shows the background state
  // instead of a button spinning on one long request.
  it('shows a running publication and stops at its outcome', async () => {
    mocks.list
      .mockResolvedValueOnce([{ ...summary, publish_state: 'publishing', publish_started_at: new Date().toISOString() }])
      .mockResolvedValue([{ ...summary, publish_state: 'failed', publish_error: 'Tenant enrichment coordinator unavailable; retry the publish' }]);
    renderPage();
    expect(await screen.findByText('publishing…')).toBeTruthy();
    expect(screen.getByLabelText('Publishing…')).toBeTruthy();
    const failed = await screen.findByText('failed', {}, { timeout: 4000 });
    expect(failed.getAttribute('title')).toContain('coordinator unavailable');
    expect(screen.getByLabelText('Publish')).toBeTruthy();
  });

  it('shows the last successful publication', async () => {
    mocks.list.mockResolvedValue([{
      ...summary, indicator_count: 47036, counts: { ip: 47036 }, publish_state: 'published', publish_pending: false,
      last_published_at: new Date(Date.now() - 5 * 3600_000).toISOString(), last_published_count: 47036,
    }]);
    renderPage();
    expect(await screen.findByText(/5h ago/)).toBeTruthy();
  });

  it('explains the flow in a popover, not page copy', async () => {
    mocks.list.mockResolvedValue([summary]);
    renderPage();
    await screen.findByText('apt-infra');
    expect(screen.queryByText('How IOC lists work')).toBeNull();
    fireEvent.click(screen.getByLabelText('How IOC lists work'));
    expect(await screen.findByText('How IOC lists work')).toBeTruthy();
  });

  it('opens a paged, server-searched viewer for a list', async () => {
    mocks.list.mockResolvedValue([summary]);
    const entry = (value: string) => ({
      value, ioc_type: 'ip', risk_score: 75, tags: ['c2'], expires_at: null, note: null, added_at: new Date().toISOString(), expired: false,
    });
    mocks.indicators
      .mockResolvedValueOnce({ indicators: [entry('45.33.32.156'), entry('45.33.32.157')], next_cursor: 'r2', scanned: 2, scan_limited: false })
      .mockResolvedValueOnce({ indicators: [entry('10.0.0.1')], next_cursor: null, scanned: 1, scan_limited: false })
      .mockResolvedValue({ indicators: [entry('45.33.32.156')], next_cursor: null, scanned: 1, scan_limited: false });
    renderPage();
    fireEvent.click(await screen.findByLabelText('View apt-infra indicators'));
    expect(await screen.findByText('45.33.32.157')).toBeTruthy();
    expect(mocks.indicators).toHaveBeenCalledWith(summary.id, expect.objectContaining({ after: null, limit: 100, hide_expired: true }));
    fireEvent.click(screen.getByText('load more'));
    expect(await screen.findByText('10.0.0.1')).toBeTruthy();
    expect(mocks.indicators).toHaveBeenLastCalledWith(summary.id, expect.objectContaining({ after: 'r2' }));
    fireEvent.change(screen.getByLabelText('Search indicators'), { target: { value: '45.33.32.156' } });
    await waitFor(() =>
      expect(mocks.indicators).toHaveBeenLastCalledWith(summary.id, expect.objectContaining({ q: '45.33.32.156', match: 'prefix', after: null })),
    );
  });

  it('creates a list from pasted indicators', async () => {
    mocks.list.mockResolvedValue([]);
    mocks.create.mockResolvedValue(summary);
    renderPage();
    fireEvent.click(await screen.findByText('New IOC list'));
    fireEvent.change(screen.getByPlaceholderText('apt29-infra'), { target: { value: 'apt-infra' } });
    fireEvent.change(document.querySelector('textarea')!, {
      target: { value: '45.33.32.156\nevil[.]example' },
    });
    fireEvent.click(screen.getByText('Create'));
    await waitFor(() => expect(mocks.create).toHaveBeenCalled());
    const request = mocks.create.mock.calls[0][0];
    expect(request.name).toBe('apt-infra');
    expect(request.format).toBe('text');
    expect(request.default_risk_score).toBe(75);
  });

  // NAN-3882: optional expiry + context on import.
  it('sends the chosen expiry and context with an import', async () => {
    mocks.list.mockResolvedValue([]);
    mocks.create.mockResolvedValue(summary);
    renderPage();
    fireEvent.click(await screen.findByText('New IOC list'));
    fireEvent.change(screen.getByPlaceholderText('apt29-infra'), { target: { value: 'ir-2291' } });
    fireEvent.change(document.querySelector('textarea')!, { target: { value: '45.33.32.156' } });
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: '30d' } });
    fireEvent.change(screen.getByPlaceholderText('optional: incident or case ref'), { target: { value: 'IR-2291' } });
    const before = Date.now();
    fireEvent.click(screen.getByText('Create'));
    await waitFor(() => expect(mocks.create).toHaveBeenCalled());
    const request = mocks.create.mock.calls[0][0];
    const days = (new Date(request.default_expires_at).getTime() - before) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThan(30.1);
    expect(request.default_note).toBe('IR-2291');
  });

  it('defaults to never expiring and blocks a past custom expiry', async () => {
    mocks.list.mockResolvedValue([]);
    mocks.create.mockResolvedValue(summary);
    renderPage();
    fireEvent.click(await screen.findByText('New IOC list'));
    fireEvent.change(screen.getByPlaceholderText('apt29-infra'), { target: { value: 'x' } });
    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('never');
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'custom' } });
    fireEvent.change(screen.getByLabelText('Expires at'), { target: { value: '2020-01-01T00:00' } });
    expect((screen.getByText('Create').closest('button') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'never' } });
    fireEvent.click(screen.getByText('Create'));
    await waitFor(() => expect(mocks.create).toHaveBeenCalled());
    expect(mocks.create.mock.calls[0][0].default_expires_at).toBeUndefined();
  });

  it('computes expiry instants', () => {
    const now = new Date('2026-10-15T12:00:00Z');
    expect(expiryInstant({ choice: 'never', custom: '' }, now)).toBeNull();
    expect(expiryInstant({ choice: '7d', custom: '' }, now)).toBe('2026-10-22T12:00:00.000Z');
    expect(expiryInstant({ choice: '90d', custom: '' }, now)).toBe('2027-01-13T12:00:00.000Z');
    expect(expiryInstant({ choice: 'custom', custom: '' }, now)).toBeUndefined();
    expect(expiryInstant({ choice: 'custom', custom: 'not a date' }, now)).toBeUndefined();
    expect(expiryInstant({ choice: 'custom', custom: '2020-01-01T00:00' }, now)).toBeUndefined();
    expect(expiryInstant({ choice: 'custom', custom: '2027-01-01T00:00' }, now)).toBe(new Date('2027-01-01T00:00').toISOString());
  });

  it('greys expired entries, can show them, and purges with confirmation', async () => {
    const withExpired = { ...summary, with_expiry: 2, expired_count: 1, next_expiry_at: null };
    mocks.list.mockResolvedValue([withExpired]);
    mocks.update.mockResolvedValue({ ...withExpired, indicator_count: 2, expired_count: 0 });
    mocks.indicators
      .mockResolvedValueOnce({
        indicators: [{ value: '45.33.32.156', ioc_type: 'ip', risk_score: 75, tags: [], expires_at: null, note: null, added_at: new Date().toISOString(), expired: false }],
        next_cursor: null, scanned: 2, scan_limited: false,
      })
      .mockResolvedValue({
        indicators: [{ value: '10.9.9.9', ioc_type: 'ip', risk_score: 75, tags: [], expires_at: '2026-01-01T00:00:00Z', note: 'IR-1', added_at: new Date().toISOString(), expired: true }],
        next_cursor: null, scanned: 2, scan_limited: false,
      });
    renderPage();
    fireEvent.click(await screen.findByLabelText('View apt-infra indicators'));
    expect(await screen.findByText('45.33.32.156')).toBeTruthy();
    fireEvent.click(screen.getByLabelText('Hide expired'));
    const expired = await screen.findByText('10.9.9.9');
    expect(expired.closest('[data-expired]')).toBeTruthy();
    expect(screen.getByText('2026-01-01 00:00')).toBeTruthy();
    expect(mocks.indicators).toHaveBeenLastCalledWith(summary.id, expect.objectContaining({ hide_expired: false }));
    fireEvent.click(screen.getByText('purge expired'));
    fireEvent.click(await screen.findByText('Purge'));
    await waitFor(() => expect(mocks.update).toHaveBeenCalledWith(summary.id, { purge_expired: true }));
  });

  it('sets and clears a whole-list expiry', async () => {
    mocks.list.mockResolvedValue([summary]);
    mocks.update.mockResolvedValue(summary);
    mocks.indicators.mockResolvedValue({ indicators: [], next_cursor: null, scanned: 0, scan_limited: false });
    renderPage();
    fireEvent.click(await screen.findByLabelText('View apt-infra indicators'));
    fireEvent.click(await screen.findByText('set expiry'));
    await waitFor(() =>
      expect(mocks.update).toHaveBeenCalledWith(summary.id, { expiry: { action: 'set', expires_at: expect.any(String) } }),
    );
    fireEvent.click(screen.getByText('clear expiry'));
    await waitFor(() => expect(mocks.update).toHaveBeenLastCalledWith(summary.id, { expiry: { action: 'clear' } }));
  });

  it('infers the upload format from the file name', () => {
    expect(uploadFormatFor('iocs.CSV')).toBe('csv');
    expect(uploadFormatFor('feed.json')).toBe('json');
    expect(uploadFormatFor('list.txt')).toBe('text');
    expect(uploadFormatFor('unknown.dat')).toBe('csv');
  });
});
