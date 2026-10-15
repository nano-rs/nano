// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, mock as nodeMock, test } from 'node:test';
import assert from 'node:assert/strict';
import { moduleMocks } from '../../test/marketplace-dom';
const mocks = ({ permission: nodeMock.fn(() => true) });
moduleMocks['/lib/api/index.ts'] = { api: { marketplace: {} } };
moduleMocks['/contexts/AuthContext.tsx'] = { useAuth: () => ({ user: { id: 'operator' }, hasPermission: mocks.permission }) };
moduleMocks['/hooks/useDocumentTitle.ts'] = { useDocumentTitle() {} };
moduleMocks['/hooks/useBreadcrumbTitle.ts'] = { useBreadcrumbTitle() {} };
moduleMocks['/enterprise/pages/CustomEnrichmentWizard.tsx'] = { CustomEnrichmentWizard: () => <p>Native TI and asset wizard</p> };
moduleMocks['/pages/LookupTableCreate.tsx'] = { LookupTableCreate: ({ onSaved }: { onSaved: (id: string) => void }) => <button onClick={() => onSaved('assets')}>Native lookup save</button> };
moduleMocks['/InventoryRepositoryEditor.tsx'] = { InventoryRepositoryEditor: () => <p>Native repository connection</p> };
const { cleanup, fireEvent, render } = await import('@testing-library/react');
const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query');
const { MemoryRouter } = await import('react-router-dom');
const { InventoryEditor } = await import('./InventoryEditor');
function mount(element: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false, gcTime: 0 } } })}><MemoryRouter>{element}</MemoryRouter></QueryClientProvider>);
}
beforeEach(() => {
  for (const fn of Object.values(mocks)) fn.mock.resetCalls(); mocks.permission.mock.mockImplementation(() => true); });
afterEach(cleanup);
test('new item embeds lookup and repository editors without leaving Marketplace', async () => {
  const view=mount(<InventoryEditor definitionId="new" onClose={() => {}} onSaved={() => {}} />);
  await view.findByText('Native TI and asset wizard');
  fireEvent.click(view.getByRole('button',{name:'Lookup table'}));
  fireEvent.click(await view.findByRole('button',{name:'Native lookup save'}));
  await view.findByText('assets');
  fireEvent.click(view.getByRole('button',{name:'Git bundle'}));
  await view.findByText('Native repository connection');
});

test('lookup authoring is hidden when its native permissions are absent', async () => {
  mocks.permission.mock.mockImplementation(() => false);
  const view=mount(<InventoryEditor definitionId="new" onClose={() => {}} onSaved={() => {}} />);
  await view.findByText('Authoring permission required.');
  assert.equal(view.queryByRole('button',{name:'Lookup table'}), null);
});
