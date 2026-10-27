// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import userEvent from '@testing-library/user-event';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  getRecipients: vi.fn(),
  updateRecipients: vi.fn(),
  getMailTransport: vi.fn(),
  updateMailTransport: vi.fn(),
  sendTestEmail: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: { soar: mock } }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
import { SoarMailSettings } from './SoarMailSettings';
beforeEach(() => {
  vi.clearAllMocks();
  Element.prototype.scrollIntoView = vi.fn();
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.setPointerCapture = () => {};
  Element.prototype.releasePointerCapture = () => {};
  mock.getRecipients.mockResolvedValue({
    recipients: [{ name: 'oncall', address: 'soc@example.test' }],
    revision: 3,
    daily_send_cap: 100,
  });
  mock.getMailTransport.mockResolvedValue({
    transport: 'nano',
    smtp: null,
    revision: 0,
    has_password: false,
    nano_mailer_available: false,
  });
});
afterEach(cleanup);
function page(canEdit = true) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const node = (allowed: boolean) => (
    <QueryClientProvider client={client}>
      <SoarMailSettings canEdit={allowed} enabled />
    </QueryClientProvider>
  );
  const view = render(node(canEdit));
  return {
    updatePermissions: (allowed: boolean) => view.rerender(node(allowed)),
  };
}
async function selectTestRecipient() {
  const trigger = screen.getByRole('combobox', { name: 'Test email recipient' });
  // After cleanup, jsdom can retain Document as its previous focus target.
  // Focus before Radix opens so its click-time focus does not emit window blur
  // and dismiss the listbox that just opened on pointer-down.
  trigger.focus();
  await userEvent.click(trigger);
  expect(trigger.getAttribute('aria-expanded')).toBe('true');
  await userEvent.click(await screen.findByRole('option', { name: 'oncall' }));
  expect(trigger.textContent).toBe('oncall');
}
test('non-admin reads destinations without edit or test-send controls', async () => {
  page(false);
  expect(await screen.findByText('soc@example.test')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Add recipient' })).toBeNull();
  expect(
    screen.queryByRole('button', { name: 'Configure transport' }),
  ).toBeNull();
  expect(screen.queryByRole('button', { name: 'Send test email' })).toBeNull();
});
test('recipient creation submits a named destination, audit reason and revision', async () => {
  mock.updateRecipients.mockResolvedValue({
    recipients: [],
    revision: 4,
    daily_send_cap: 100,
  });
  page();
  await screen.findByText('soc@example.test');
  fireEvent.click(screen.getByRole('button', { name: 'Add recipient' }));
  fireEvent.change(screen.getByLabelText('Recipient name'), {
    target: { value: 'backup' },
  });
  fireEvent.change(screen.getByLabelText('Recipient email address'), {
    target: { value: 'backup@example.test' },
  });
  fireEvent.change(screen.getByLabelText('Recipient change reason'), {
    target: { value: 'Add backup on-call' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save recipient' }));
  await waitFor(() =>
    expect(mock.updateRecipients).toHaveBeenCalledWith({
      recipients: [
        { name: 'oncall', address: 'soc@example.test' },
        { name: 'backup', address: 'backup@example.test' },
      ],
      expected_revision: 3,
      reason: 'Add backup on-call',
    }),
  );
});
test('omits absent SMTP metadata and disables test-send without SMTP settings', async () => {
  mock.getMailTransport.mockResolvedValue({
    transport: 'smtp',
    smtp: null,
    revision: 9,
    has_password: false,
    nano_mailer_available: false,
  });
  page();
  expect(await screen.findByText('revision 9')).toBeTruthy();
  expect(screen.queryByText(/undefined/)).toBeNull();
  await selectTestRecipient();
  expect(
    (
      screen.getByRole('button', {
        name: 'Send test email',
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
  expect(mock.sendTestEmail).not.toHaveBeenCalled();
});
test('self-hosted transport offers mandatory TLS SMTP and submits a write-only password', async () => {
  mock.updateMailTransport.mockResolvedValue({
    transport: 'smtp',
    smtp: null,
    revision: 1,
    has_password: true,
    nano_mailer_available: false,
  });
  page();
  await screen.findByText(
    'No transport configured. Configure your SMTP server.',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Configure transport' }));
  expect(
    screen.getByRole('combobox', { name: 'Mail transport' }).textContent,
  ).toContain('Your SMTP server');
  await userEvent.click(
    screen.getByRole('combobox', { name: 'Mail transport' }),
  );
  expect(
    await screen.findByRole('option', { name: 'nano mailer (unavailable)' }),
  ).toHaveProperty('ariaDisabled', 'true');
  expect(screen.queryByRole('option', { name: /plaintext/i })).toBeNull();
  await userEvent.click(
    screen.getByRole('option', { name: 'Your SMTP server' }),
  );
  fireEvent.change(screen.getByLabelText('SMTP host'), {
    target: { value: 'smtp.example.test' },
  });
  fireEvent.change(screen.getByLabelText('SMTP From address'), {
    target: { value: 'nano@example.test' },
  });
  fireEvent.change(screen.getByLabelText('SMTP username'), {
    target: { value: 'soc' },
  });
  fireEvent.change(screen.getByLabelText('SMTP password'), {
    target: { value: 'fixture-password' },
  });
  fireEvent.change(screen.getByLabelText('Transport change reason'), {
    target: { value: 'Use our SMTP server' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(mock.updateMailTransport).toHaveBeenCalledWith({
      transport: 'smtp',
      smtp: {
        host: 'smtp.example.test',
        port: 587,
        tls: 'starttls',
        username: 'soc',
        from: 'nano@example.test',
      },
      password: 'fixture-password',
      expected_revision: 0,
      reason: 'Use our SMTP server',
    }),
  );
});
test('test-send addresses a selected allowlist name and cannot run without transport', async () => {
  mock.getMailTransport.mockResolvedValue({
    transport: 'nano',
    smtp: null,
    revision: 0,
    has_password: false,
    nano_mailer_available: true,
  });
  mock.sendTestEmail.mockResolvedValue({ status: 'sent' });
  page();
  await screen.findByText('soc@example.test');
  expect(
    (
      screen.getByRole('button', {
        name: 'Send test email',
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
  await selectTestRecipient();
  fireEvent.click(screen.getByRole('button', { name: 'Send test email' }));
  await waitFor(() =>
    expect(mock.sendTestEmail).toHaveBeenCalledWith('oncall'),
  );
  expect(await screen.findByText('Test email sent.')).toBeTruthy();
});

test('platform queue acceptance is shown separately from confirmed delivery', async () => {
  mock.getMailTransport.mockResolvedValue({
    transport: 'nano',
    smtp: null,
    revision: 0,
    has_password: false,
    nano_mailer_available: true,
  });
  mock.sendTestEmail.mockResolvedValue({ status: 'queued' });
  page();
  await screen.findByText('soc@example.test');
  await selectTestRecipient();
  fireEvent.click(screen.getByRole('button', { name: 'Send test email' }));
  expect(await screen.findByRole('status')).toHaveProperty(
    'textContent',
    'Test email queued for delivery.',
  );
});

test('a concurrent transport update reloads the editor and clears its unsaved password', async () => {
  mock.getMailTransport
    .mockResolvedValueOnce({
      transport: 'nano',
      smtp: null,
      revision: 0,
      has_password: false,
      nano_mailer_available: false,
    })
    .mockResolvedValue({
      transport: 'smtp',
      smtp: {
        host: 'new.example.test',
        port: 465,
        tls: 'implicit_tls',
        username: 'new-admin',
        from: 'soc@example.test',
      },
      revision: 1,
      has_password: true,
      nano_mailer_available: false,
    });
  mock.updateMailTransport.mockRejectedValue(
    Object.assign(new Error('Concurrent update'), { status: 409 }),
  );
  page();
  await screen.findByText(
    'No transport configured. Configure your SMTP server.',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Configure transport' }));
  fireEvent.change(screen.getByLabelText('SMTP host'), {
    target: { value: 'old.example.test' },
  });
  fireEvent.change(screen.getByLabelText('SMTP From address'), {
    target: { value: 'soc@example.test' },
  });
  fireEvent.change(screen.getByLabelText('SMTP password'), {
    target: { value: 'unsaved-password' },
  });
  fireEvent.change(screen.getByLabelText('Transport change reason'), {
    target: { value: 'Concurrent edit' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(screen.getByLabelText('SMTP host')).toHaveProperty(
      'value',
      'new.example.test',
    ),
  );
  expect(screen.getByLabelText('SMTP password')).toHaveProperty('value', '');
  expect(screen.getByLabelText('Transport change reason')).toHaveProperty(
    'value',
    '',
  );
});

test('empty destinations and unavailable mailer keep send disabled', async () => {
  mock.getRecipients.mockResolvedValue({
    recipients: [],
    revision: 0,
    daily_send_cap: 100,
  });
  page();
  await screen.findByText('No recipients configured');
  expect(
    screen.getByText('Add a recipient to send a test email.'),
  ).toBeTruthy();
  expect(
    screen.getByRole('button', { name: 'Send test email' }),
  ).toHaveProperty('disabled', true);
  expect(
    screen.getByRole('combobox', { name: 'Test email recipient' }),
  ).toHaveProperty('disabled', true);
  expect(screen.queryByText(/sent today/)).toBeNull();
  expect(screen.queryByText(/soar@mail/)).toBeNull();
});

test('the add row carries its real destination into audited confirmation', async () => {
  page();
  await screen.findByText('soc@example.test');
  fireEvent.change(screen.getByLabelText('New recipient name'), {
    target: { value: 'backup' },
  });
  fireEvent.change(screen.getByLabelText('New recipient email address'), {
    target: { value: 'backup@example.test' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Add recipient' }));
  expect(screen.getByLabelText('Recipient name')).toHaveProperty(
    'value',
    'backup',
  );
  expect(screen.getByLabelText('Recipient email address')).toHaveProperty(
    'value',
    'backup@example.test',
  );
  expect(screen.getByRole('button', { name: 'Save recipient' })).toHaveProperty(
    'disabled',
    true,
  );
  expect(mock.updateRecipients).not.toHaveBeenCalled();
});

test('losing edit permission closes an open recipient editor', async () => {
  const view = page();
  await screen.findByText('soc@example.test');
  fireEvent.click(screen.getByRole('button', { name: 'Add recipient' }));
  expect(screen.getByLabelText('Recipient change reason')).toBeTruthy();
  view.updatePermissions(false);
  await waitFor(() =>
    expect(screen.queryByLabelText('Recipient change reason')).toBeNull(),
  );
  expect(screen.queryByRole('button', { name: 'Add recipient' })).toBeNull();
  expect(mock.updateRecipients).not.toHaveBeenCalled();
});

test('an in-flight save prevents opening a competing recipient mutation', async () => {
  let finish!: (value: unknown) => void;
  mock.updateRecipients.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  page();
  await screen.findByText('soc@example.test');
  fireEvent.click(screen.getByRole('button', { name: 'Add recipient' }));
  fireEvent.change(screen.getByLabelText('Recipient name'), {
    target: { value: 'backup' },
  });
  fireEvent.change(screen.getByLabelText('Recipient email address'), {
    target: { value: 'backup@example.test' },
  });
  fireEvent.change(screen.getByLabelText('Recipient change reason'), {
    target: { value: 'Add backup' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Save recipient' }));
  await waitFor(() => expect(mock.updateRecipients).toHaveBeenCalledTimes(1));
  expect(
    screen.getByRole('button', { name: 'Edit oncall', hidden: true }),
  ).toHaveProperty('disabled', true);
  expect(
    screen.getByRole('button', { name: 'Remove oncall', hidden: true }),
  ).toHaveProperty('disabled', true);
  finish({ recipients: [], revision: 4, daily_send_cap: 100 });
  await waitFor(() =>
    expect(screen.queryByLabelText('Recipient change reason')).toBeNull(),
  );
});
