// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5253: Help > Report a bug opens anywhere, sends nothing on its own, and
// offers copy/download only when air-gapped. NAN-5857: it is a right-side
// flyout with no scrim, and its context describes the page it was opened on.

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, beforeEach, expect, test, vi } from 'vitest';

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
import { HelpMenu } from './HelpMenu';
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

beforeAll(() => {
  // Radix menus measure and observe; jsdom has neither.
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  Element.prototype.scrollIntoView ??= () => {};
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
  // jsdom lacks matchMedia (DetailSheet's useIsMobile): desktop.
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
        addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
      }),
    });
  }
});

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

test('opens as a right-side flyout with no scrim, focused on What happened, and Escape closes it', async () => {
  renderHost();
  act(() => openSupportDialog('bug'));
  const flyout = await screen.findByTestId('support-flyout');
  expect(flyout.getAttribute('role')).toBe('dialog');
  expect(flyout.className).toContain('right-0');
  expect(flyout.className).toContain('w-[560px]');
  // The overlay is transparent: the page being reported on stays visible.
  const overlay = document.querySelector('[data-state="open"].fixed.inset-0');
  expect(overlay).toBeTruthy();
  expect(overlay!.className).toContain('bg-transparent');
  expect(overlay!.className).not.toMatch(/bg-black/);
  expect(document.activeElement).toBe(screen.getByPlaceholderText(/Steps, and the exact error/));
  expect(screen.getByRole('navigation', { name: 'Breadcrumb' }).textContent).toContain('Help');

  // A click on the (visible) page does not discard the report.
  fireEvent.change(screen.getByPlaceholderText(/Steps, and the exact error/), { target: { value: 'draft' } });
  fireEvent.pointerDown(overlay!);
  fireEvent.mouseDown(overlay!);
  fireEvent.click(overlay!);
  expect(screen.getByTestId('support-flyout')).toBeTruthy();

  fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByTestId('support-flyout')).toBeNull());
});

test('captures the page it was opened on, without query secrets, fresh on every open', async () => {
  window.history.pushState({}, '', '/search?token=supersecretvalue123&tab=results');
  renderHost();
  act(() => openSupportDialog('bug'));
  const flyout = await screen.findByTestId('support-flyout');
  expect(flyout.textContent).toContain('/search?token=[omitted]&tab=results');
  expect(flyout.textContent).not.toContain('supersecretvalue123');
  expect(flyout.textContent).toContain('v2.0.11');

  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  await waitFor(() => expect(screen.queryByTestId('support-flyout')).toBeNull());
  window.history.pushState({}, '', '/rules');
  act(() => openSupportDialog('support'));
  const reopened = await screen.findByTestId('support-flyout');
  expect(reopened.textContent).toContain('/rules');
  expect(reopened.textContent).not.toContain('/search');
  window.history.pushState({}, '', '/');
});

test.each([
  ['Report a bug', /Steps, and the exact error/],
  ['Get support', /What you are trying to do/],
])('opened from the Help menu (%s), focus starts in What happened, never on Close', async (item, placeholder) => {
  const user = userEvent.setup();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <HelpMenu />
      <SupportDialogHost />
    </QueryClientProvider>,
  );
  // Keyboard open: the path where Space or Enter on a focused Close would dismiss it.
  screen.getByRole('button', { name: 'Help' }).focus();
  await user.keyboard('{Enter}');
  const menuItem = await screen.findByRole('menuitem', { name: item });
  menuItem.focus();
  await user.keyboard('{Enter}');
  await screen.findByTestId('support-flyout');
  const field = screen.getByPlaceholderText(placeholder);
  await waitFor(() => expect(document.activeElement).toBe(field));
  // Focus stays there once the menu's own focus return has run.
  await new Promise((r) => setTimeout(r, 20));
  expect(document.activeElement).toBe(field);
  await user.keyboard(' x');
  expect(screen.getByTestId('support-flyout')).toBeTruthy();
});
