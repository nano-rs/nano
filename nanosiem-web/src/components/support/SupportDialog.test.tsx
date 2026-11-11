// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5253: Help > Report a bug opens anywhere, sends nothing on its own, and
// offers copy/download only when air-gapped.

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const mock = vi.hoisted(() => ({ airgap: false, edition: 'enterprise' as 'enterprise' | 'open', licenceCalls: 0 }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilitiesOptional: () => ({ edition: mock.edition, version: '2.0.11', capabilities: {} }),
}));
vi.mock('@/lib/api', () => ({
  api: {
    getLicenseStatus: async () => {
      mock.licenceCalls += 1;
      return { airgap: mock.airgap, installation_id: 'inst_0123456789abcdefghjkmnpqrs',
        deployment_id: 'deploy_01h455vb4pex5vsknk084sn02q' };
    },
  },
}));
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { SupportDialogHost } from './SupportDialog';
import { decodeFeedbackPayload, openSupportDialog, recordFailedCall, resetSupportCapture } from '@/lib/support-diagnostics';

let clipboard = '';

function renderHost() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SupportDialogHost />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  clipboard = '';
  mock.airgap = false;
  mock.edition = 'enterprise';
  mock.licenceCalls = 0;
  localStorage.clear();
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: async (text: string) => { clipboard = text; } },
  });
  resetSupportCapture();
});

afterEach(() => cleanup());

test('opens from the event, attaches failed calls, and copies a filled report', async () => {
  recordFailedCall({ at: '2026-11-10T19:05:00.000Z', method: 'PUT', path: '/api/rules/rule_01', status: 500,
    requestId: 'req-abc-123', durationMs: 42 });
  renderHost();
  expect(screen.queryByRole('dialog')).toBeNull();
  act(() => openSupportDialog('bug'));
  expect(await screen.findByRole('dialog')).toBeTruthy();
  expect(screen.getByText('1 failed calls', { exact: false })).toBeTruthy();

  const copyButton = screen.getByRole('button', { name: /copy report/i }) as HTMLButtonElement;
  expect(copyButton.disabled).toBe(true);
  fireEvent.change(screen.getByPlaceholderText(/Steps, and the exact error/), { target: { value: 'Rule save returns 500' } });
  fireEvent.change(screen.getByPlaceholderText(/rule: …/), { target: { value: 'rule: Brute force > 10' } });
  await screen.findByText('inst_0123456789abcdefghjkmnpqrs');
  fireEvent.click(copyButton);
  await waitFor(() => expect(clipboard).toContain('Rule save returns 500'));
  expect(clipboard).toContain('rule: Brute force > 10');
  expect(clipboard).toContain('500 PUT /api/rules/rule_01 request_id=req-abc-123');
  expect(clipboard).toContain('nano version: 2.0.11');
  expect(clipboard).toContain('installation: inst_0123456789abcdefghjkmnpqrs');
  expect(screen.getByRole('button', { name: /^email$/i })).toBeTruthy();
});

test('air-gapped installs get copy and download only', async () => {
  mock.airgap = true;
  renderHost();
  act(() => openSupportDialog('support'));
  await screen.findByRole('dialog');
  await waitFor(() => expect(screen.queryByRole('button', { name: /^email$/i })).toBeNull());
  expect(screen.queryByRole('button', { name: /open support request/i })).toBeNull();
  expect(screen.getByRole('button', { name: /download/i })).toBeTruthy();
  expect(screen.getByText('cd ~/nano && scripts/nano support-bundle')).toBeTruthy();
});

test('open core skips the license call and still works', async () => {
  mock.edition = 'open';
  renderHost();
  act(() => openSupportDialog('support'));
  await screen.findByRole('dialog');
  expect(mock.licenceCalls).toBe(0);
  expect(screen.getByRole('button', { name: /^email$/i })).toBeTruthy();
});

test('Get support opens the prefilled app.nano.rs form with severity, and posts nothing', async () => {
  const open = vi.spyOn(window, 'open').mockImplementation(() => null);
  const fetchSpy = vi.spyOn(window, 'fetch');
  renderHost();
  act(() => openSupportDialog('support'));
  await screen.findByRole('dialog');
  await screen.findByText('inst_0123456789abcdefghjkmnpqrs');
  fireEvent.click(screen.getByRole('radio', { name: /SEV1/ }));
  fireEvent.change(screen.getByPlaceholderText(/What you are trying to do/), { target: { value: 'Ingest stopped\nsince 14:00' } });
  fireEvent.click(screen.getByRole('button', { name: /open support request/i }));
  expect(open).toHaveBeenCalledTimes(1);
  const url = String(open.mock.calls[0][0]);
  expect(url.startsWith('https://app.nano.rs/feedback/new?type=support&deployment=deploy_01h455vb4pex5vsknk084sn02q#r=')).toBe(true);
  const payload = decodeFeedbackPayload(url.split('#r=')[1]);
  expect(payload).toMatchObject({ v: 1, type: 'support', severity: 'SEV1', summary: 'Ingest stopped', truncated: false });
  expect(payload.context.deployment_id).toBe('deploy_01h455vb4pex5vsknk084sn02q');
  expect(fetchSpy).not.toHaveBeenCalled();
  open.mockRestore();
  fetchSpy.mockRestore();
});
