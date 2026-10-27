// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4546 — Run action sheet: typed validation, the "provide one of" target
// group, the effect summary and the dry-run preview that follows the run.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { catalog, connection, pack, run, runDetail } from './fixtures';

const mock = vi.hoisted(() => ({ soarApi: { queueAction: vi.fn(), getRun: vi.fn() } }));
vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi } }));

import { RunActionSheet } from '../RunActionSheet';
import type { RunActionPreset } from '../RunActionSheet';

const okta = pack({
  name: 'okta',
  display_name: 'Okta',
  vendor: 'Okta',
  actions: [
    {
      name: 'get_user', display_name: 'Get user', description: 'Return profile.', effect: 'read', approval_required: false,
      approval_forced: false, idempotent: true, inputs: [{ name: 'login', type: 'email', required: true, pattern: null }], require_one_of: [], rollback: null,
    },
  ],
});
const falcon = pack({
  actions: [
    {
      name: 'contain_host', display_name: 'Contain host', description: 'Network-isolate a host.', effect: 'destructive', approval_required: true,
      approval_forced: true, idempotent: true,
      inputs: [
        { name: 'hostname', type: 'string', required: false, pattern: null },
        { name: 'device_id', type: 'string', required: false, pattern: null },
      ],
      require_one_of: [['hostname', 'device_id']], rollback: 'lift_containment',
    },
    {
      name: 'lift_containment', display_name: 'Lift containment', description: '', effect: 'write', approval_required: true,
      approval_forced: false, idempotent: true, inputs: [{ name: 'device_id', type: 'string', required: true, pattern: null }], require_one_of: [], rollback: null,
    },
  ],
});
const oktaConn = connection({ id: 'c-okta', pack_name: 'okta', label: 'Okta · corp' });

function renderSheet(preset: RunActionPreset) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RunActionSheet open onOpenChange={() => {}} tenant="t1" catalog={catalog([falcon, okta])} connections={[connection(), oktaConn]} preset={preset} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return screen.findByTestId('run-action-dialog');
}

beforeEach(() => {
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
});
afterEach(cleanup);

test('typed inputs are validated before anything is sent', async () => {
  const sheet = await renderSheet({ pack: 'okta', action: 'get_user', inputs: { login: 'not-an-email' } });
  fireEvent.click(within(sheet).getByRole('button', { name: 'Preview' }));
  expect(await within(sheet).findByText('Enter an email address.')).toBeTruthy();
  expect(mock.soarApi.queueAction).not.toHaveBeenCalled();
  fireEvent.change(within(sheet).getByLabelText('login'), { target: { value: 'j.alvarez@acme.io' } });
  expect(within(sheet).queryByText('Enter an email address.')).toBeNull();
});

test('target group: one of hostname or device_id', async () => {
  const sheet = await renderSheet({ pack: 'crowdstrike', action: 'contain_host' });
  expect(within(sheet).getByText('Target · provide one of')).toBeTruthy();
  fireEvent.click(within(sheet).getByRole('button', { name: 'Request run' }));
  expect(await within(sheet).findByText('Provide hostname or device_id.')).toBeTruthy();
  expect(screen.queryByRole('alertdialog')).toBeNull();
});

test('summary shows verb, target, policy and inverse', async () => {
  const sheet = await renderSheet({ pack: 'crowdstrike', action: 'contain_host', inputs: { hostname: 'WS-FIN-022' } });
  const summary = within(sheet).getByTestId('run-action-summary');
  expect(within(summary).getByText('Contain')).toBeTruthy();
  expect(within(summary).getByText('WS-FIN-022')).toBeTruthy();
  expect(within(summary).getByText('Approval: Always required')).toBeTruthy();
  expect(within(summary).getByText('Inverse: Lift containment')).toBeTruthy();
});

test('case ID must be a UUID', async () => {
  const sheet = await renderSheet({ pack: 'okta', action: 'get_user', inputs: { login: 'a@b.io' }, caseId: 'CASE-1042' });
  fireEvent.click(within(sheet).getByRole('button', { name: 'Preview' }));
  expect(await within(sheet).findByText('Enter a case ID (UUID).')).toBeTruthy();
  expect(mock.soarApi.queueAction).not.toHaveBeenCalled();
});

test('preview follows the dry run until it finishes', async () => {
  mock.soarApi.queueAction.mockResolvedValue(run({ id: 'dry00001-0000-4000-8000-000000000001', dry_run: true, status: 'queued' }));
  mock.soarApi.getRun.mockResolvedValue(
    runDetail({ id: 'dry00001-0000-4000-8000-000000000001', dry_run: true, status: 'succeeded' }),
  );
  const sheet = await renderSheet({ pack: 'okta', action: 'get_user', inputs: { login: 'j.alvarez@acme.io' } });
  fireEvent.click(within(sheet).getByRole('button', { name: 'Preview' }));
  await waitFor(() => expect(mock.soarApi.queueAction).toHaveBeenCalledWith({ connection_id: 'c-okta', action: 'get_user', inputs: { login: 'j.alvarez@acme.io' }, dry_run: true }));
  expect(await within(sheet).findByText('No vendor requests sent. No changes made.')).toBeTruthy();
  expect(within(sheet).getByTestId('run-action-preview').textContent).toContain('dry00001');
});
