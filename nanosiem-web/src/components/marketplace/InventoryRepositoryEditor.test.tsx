// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, mock as nodeMock, test } from 'node:test';
import assert from 'node:assert/strict';
import { moduleMocks } from '../../test/marketplace-dom';
const mock = ({ list: nodeMock.fn<(...args: any[]) => any>(), create: nodeMock.fn<(...args: any[]) => any>(), update: nodeMock.fn<(...args: any[]) => any>(), sync: nodeMock.fn<(...args: any[]) => any>() });
moduleMocks['/lib/api/index.ts'] = { api: { marketplace: { listRepos: mock.list, createRepo: mock.create, updateRepo: mock.update, syncRepo: mock.sync } } };
moduleMocks['/contexts/AuthContext.tsx'] = { useAuth: () => ({ user: { id: 'member', active_tenant: { id: 'tenant' } } }) };
const { cleanup, fireEvent, render, waitFor } = await import('@testing-library/react');
const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query');
const { InventoryRepositoryEditor } = await import('./InventoryRepositoryEditor');
function mount() { return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { gcTime: 0 } } })}><InventoryRepositoryEditor /></QueryClientProvider>); }
beforeEach(() => {
  for (const fn of Object.values(mock)) fn.mock.resetCalls();  mock.list.mock.mockImplementation(async () => ([])); mock.create.mock.mockImplementation(async () => ({})); mock.update.mock.mockImplementation(async () => ({})); mock.sync.mock.mockImplementation(async () => ({})); });
afterEach(cleanup);
test('connect sends the native tenant repository contract', async () => {
  const view=mount();
  fireEvent.change(view.getByLabelText('Name'),{target:{value:'Tenant bundle'}});
  fireEvent.change(view.getByLabelText('Repository URL (no embedded credentials)'),{target:{value:'https://github.com/example/fixture'}});
  fireEvent.click(view.getByRole('button',{name:'Connect repository'}));
  await waitFor(() => assert.deepEqual(mock.create.mock.calls.at(-1)?.arguments, [{name:'Tenant bundle',url:'https://github.com/example/fixture',branch:'main',enrichments_path:'enrichments'}]));
});
test('existing connection edits preserve identity and call the native update API', async () => {
  mock.list.mock.mockImplementation(async () => ([{id:'repo-one',name:'Bundle',url:'https://github.com/example/fixture',branch:'main',enrichments_path:'feeds',last_sync_commit:'abc123'}]));
  const view=mount();
  await view.findByText(/abc123/);
  fireEvent.click(view.getByRole('button',{name:'Edit repository'}));
  fireEvent.change(view.getByLabelText('Branch'),{target:{value:'reviewed'}});
  fireEvent.click(view.getByRole('button',{name:'Save repository'}));
  await waitFor(() => assert.deepEqual(mock.update.mock.calls.at(-1)?.arguments, ['repo-one',{name:'Bundle',branch:'reviewed',enrichments_path:'feeds'}]));
  assert.equal(mock.create.mock.callCount(), 0);
});
test('raw sync errors and embedded credentials are never rendered as status', async () => {
  mock.list.mock.mockImplementation(async () => ([{id:'repo-one',name:'Bundle',url:'https://github.com/example/fixture',branch:'main',enrichments_path:'feeds',last_sync_status:'failed',last_sync_error:'token=must-not-leak'}]));
  mock.sync.mock.mockImplementation(async () => { throw new Error('token=must-not-leak'); });
  const view=mount();
  fireEvent.click(await view.findByRole('button',{name:'Sync bundle'}));
  await view.findByRole('alert');
  assert.ok(!view.container.textContent?.includes('must-not-leak'));
});
