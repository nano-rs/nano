// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2617: the LogSourceDetail samples editor calls PUT /api/log-sources/{id}/samples. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { TenantParserSamples } from '@/lib/api/types';
import { ParserSamplesEditor } from './ParserSamplesEditor';
import { checkSamples } from '@/lib/parser-samples';

const mocks = vi.hoisted(() => ({
  permissions: new Set<string>(['log_sources:view', 'log_sources:edit']),
  toast: vi.fn(),
  getLogSourceSamples: vi.fn(),
  putLogSourceSamples: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_me' }, hasPermission: (p: string) => mocks.permissions.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/lib/api', () => ({
  api: { getLogSourceSamples: mocks.getLogSourceSamples, putLogSourceSamples: mocks.putLogSourceSamples },
}));

function samples(over: Partial<TenantParserSamples> = {}): TenantParserSamples {
  return {
    log_source_id: 'lsrc_1', publication_id: '22222222-2222-4222-8222-222222222222', version_id: 7, version_number: 3,
    samples: ['{"a":1}', 'raw line'], updated_at: '2026-09-22T12:00:00Z', max_samples: 32, max_sample_bytes: 65_536, ...over,
  };
}

function renderEditor() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ParserSamplesEditor logSourceId="lsrc_1" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.permissions = new Set(['log_sources:view', 'log_sources:edit']);
  mocks.toast.mockReset();
  mocks.getLogSourceSamples.mockReset().mockResolvedValue(samples());
  mocks.putLogSourceSamples.mockReset().mockImplementation(async (_id: string, s: string[]) => samples({ samples: s }));
});
afterEach(cleanup);

describe('checkSamples', () => {
  it('trims, drops blanks and bounds by UTF-8 bytes and count, like the server', () => {
    const r = checkSamples(['  a  ', '', 'é'.repeat(3)], 32, 5);
    expect(r.samples).toEqual(['a', 'ééé']);
    expect(r.problems[2]).toMatch(/6 bytes; the limit is 5/);
    expect(checkSamples(['a', 'b', 'c'], 2, 10).tooMany).toBe(true);
  });
});

describe('ParserSamplesEditor', () => {
  it('loads the saved samples, edits, adds, removes and saves them with PUT', async () => {
    renderEditor();
    const first = (await screen.findByLabelText('Sample 1')) as HTMLTextAreaElement;
    expect(first.value).toBe('{"a":1}');
    expect(screen.getByTestId('parser-samples-count').textContent).toBe('2/32');
    const save = screen.getByRole('button', { name: /save samples/i }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);

    fireEvent.change(first, { target: { value: '{"a":2}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Remove sample 2' }));
    fireEvent.click(screen.getByRole('button', { name: /add sample/i }));
    fireEvent.change(screen.getByLabelText('Sample 2'), { target: { value: '  third  ' } });
    expect(save.disabled).toBe(false);
    fireEvent.click(save);

    await waitFor(() => expect(mocks.putLogSourceSamples).toHaveBeenCalledWith('lsrc_1', ['{"a":2}', 'third']));
    await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Samples saved' })));
    // The server copy replaces the drafts: clean again.
    await waitFor(() => expect((screen.getByLabelText('Sample 2') as HTMLTextAreaElement).value).toBe('third'));
    expect((screen.getByRole('button', { name: /save samples/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('refuses an oversized sample before sending, and Revert restores the saved copy', async () => {
    mocks.getLogSourceSamples.mockResolvedValue(samples({ max_sample_bytes: 8 }));
    renderEditor();
    const first = (await screen.findByLabelText('Sample 1')) as HTMLTextAreaElement;
    fireEvent.change(first, { target: { value: '0123456789' } });
    expect(screen.getByRole('alert').textContent).toMatch(/10 bytes; the limit is 8/);
    expect((screen.getByRole('button', { name: /save samples/i }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: /revert/i }));
    expect((screen.getByLabelText('Sample 1') as HTMLTextAreaElement).value).toBe('{"a":1}');
    expect(mocks.putLogSourceSamples).not.toHaveBeenCalled();
  });

  it('shows the server refusal when a save fails', async () => {
    mocks.putLogSourceSamples.mockRejectedValue(new Error('at most 32 parser samples per source'));
    renderEditor();
    fireEvent.change(await screen.findByLabelText('Sample 1'), { target: { value: 'changed' } });
    fireEvent.click(screen.getByRole('button', { name: /save samples/i }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Save failed: at most 32 parser samples/);
  });

  it('explains there is nothing to save before the source is published', async () => {
    mocks.getLogSourceSamples.mockResolvedValue(samples({ publication_id: null, version_id: null, version_number: null, samples: [] }));
    renderEditor();
    expect((await screen.findByTestId('parser-samples-unpublished')).textContent).toMatch(/Publish or deploy the parser first/);
    expect(screen.queryByRole('button', { name: /save samples/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /add sample/i })).toBeNull();
  });

  it('is read-only without log_sources:edit', async () => {
    mocks.permissions = new Set(['log_sources:view']);
    renderEditor();
    const first = (await screen.findByLabelText('Sample 1')) as HTMLTextAreaElement;
    expect(first.readOnly).toBe(true);
    expect(screen.getByText(/editing samples needs/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /save samples/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /remove sample/i })).toBeNull();
  });
});
