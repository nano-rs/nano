// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, mock as nodeMock, test } from 'node:test';
import assert from 'node:assert/strict';
import { moduleMocks } from '../../test/marketplace-dom';

const fixtures = ({
  api: {
    getCustomEnrichment: nodeMock.fn<(...args: any[]) => any>(), getCustomEnrichmentRuns: nodeMock.fn<(...args: any[]) => any>(),
    getCustomEnrichmentTemplates: nodeMock.fn<(...args: any[]) => any>(), updateCustomEnrichment: nodeMock.fn<(...args: any[]) => any>(),
    triggerCustomEnrichmentRun: nodeMock.fn<(...args: any[]) => any>(), validateCustomEnrichment: nodeMock.fn<(...args: any[]) => any>(),
  },
  toast: nodeMock.fn<(...args: any[]) => any>(),
});
moduleMocks['/lib/api/index.ts'] = { api: fixtures.api };
moduleMocks['/contexts/AuthContext.tsx'] = { useAuth: () => ({ hasPermission: () => true }) };
moduleMocks['/hooks/use-toast.ts'] = { useToast: () => ({ toast: fixtures.toast }) };
moduleMocks['/hooks/useDocumentTitle.ts'] = { useDocumentTitle: () => {} };
moduleMocks['/hooks/useBreadcrumbTitle.ts'] = { useBreadcrumbTitle: () => {} };
moduleMocks['/components/editor/index.ts'] = {
  TypeScriptEditor: ({ value }: { value: string }) => <textarea aria-label="Source" readOnly value={value} />,
  CodeInput: () => null,
};
const { cleanup, fireEvent, render, waitFor } = await import('@testing-library/react');
const { MemoryRouter, useLocation } = await import('react-router-dom');
const { CustomEnrichmentWizard } = await import('@/enterprise/pages/CustomEnrichmentWizard');
const definition = {
  id: 'tenant-definition', name: 'Tenant TI', enrichment_type: 'data',
  enabled: true, config: { key_type: 'ip' }, credential_id: 'credential-reference',
  allowed_domains: [], code: 'export default () => []', timeout_secs: 30,
};
function Location() { return <output>{useLocation().pathname}</output>; }
function mount(onSaved = nodeMock.fn<(...args: any[]) => any>(), onClose = nodeMock.fn<(...args: any[]) => any>()) {
  return { onSaved, onClose, ...render(<MemoryRouter initialEntries={['/marketplace']}>
    <CustomEnrichmentWizard definitionId="tenant-definition" onSaved={onSaved} onClose={onClose} /><Location />
  </MemoryRouter>) };
}
beforeEach(() => {
  for (const fn of Object.values(fixtures.api).concat(fixtures.toast)) fn.mock.resetCalls();

  fixtures.api.getCustomEnrichment.mock.mockImplementation(async () => (definition));
  fixtures.api.getCustomEnrichmentRuns.mock.mockImplementation(async () => ([]));
  fixtures.api.getCustomEnrichmentTemplates.mock.mockImplementation(async () => ({ data: '', agent: '' }));
  fixtures.api.updateCustomEnrichment.mock.mockImplementation(async () => (definition));
});
afterEach(cleanup);

test('embedded editor loads exact definition, source and run history through existing services', async () => {
  const view = mount();
  await view.findByText('Run History');
  assert.deepEqual(fixtures.api.getCustomEnrichment.mock.calls.at(-1)?.arguments, ['tenant-definition']);
  assert.deepEqual(fixtures.api.getCustomEnrichmentRuns.mock.calls.at(-1)?.arguments, ['tenant-definition', 10]);
  assert.equal(view.getByLabelText('Source').getAttribute('aria-label'), 'Source');
  assert.ok(view.getByText('/marketplace'));
  fireEvent.click(view.getByRole('button', { name: 'Back to Marketplace' }));
  assert.equal(view.onClose.mock.callCount(), 1);
});

test('saving retains credential reference and returns same item without route navigation', async () => {
  const view = mount();
  fireEvent.click(await view.findByRole('button', { name: 'Save Draft' }));
  await waitFor(() => assert.deepEqual(view.onSaved.mock.calls.at(-1)?.arguments, ['tenant-definition']));
  assert.equal(fixtures.api.updateCustomEnrichment.mock.calls.at(-1)?.arguments[0], 'tenant-definition');
  assert.equal(fixtures.api.updateCustomEnrichment.mock.calls.at(-1)?.arguments[1].credential_id, 'credential-reference');
  assert.ok(view.getByText('/marketplace'));
});

test('failed save cannot report success or validate stale deployed source', async () => {
  fixtures.api.updateCustomEnrichment.mock.mockImplementation(async () => { throw new Error('Denied'); });
  const view = mount();
  fireEvent.click(await view.findByRole('button', { name: 'Save Draft' }));
  await waitFor(() => assert.ok(fixtures.toast.mock.callCount() > 0));
  assert.equal(view.onSaved.mock.callCount(), 0);
  fireEvent.click(view.getByRole('button', { name: 'Next' }));
  fireEvent.click(view.getByRole('button', { name: 'Run Validation' }));
  await waitFor(() => assert.equal(fixtures.api.updateCustomEnrichment.mock.callCount(), 2));
  assert.equal(fixtures.api.validateCustomEnrichment.mock.callCount(), 0);
});

test('manual run uses the deployed data service and refreshes history', async () => {
  const view = mount();
  fireEvent.click(await view.findByRole('button', { name: 'Run deployed provider' }));
  await waitFor(() => assert.deepEqual(fixtures.api.triggerCustomEnrichmentRun.mock.calls.at(-1)?.arguments, ['tenant-definition']));
  await waitFor(() => assert.equal(fixtures.api.getCustomEnrichmentRuns.mock.callCount(), 2));
  assert.equal(fixtures.api.updateCustomEnrichment.mock.callCount(), 0);
});

test('agent editor exposes history but no data-only manual run', async () => {
  fixtures.api.getCustomEnrichment.mock.mockImplementation(async () => ({ ...definition, enrichment_type: 'agent' }));
  const view = mount();
  await view.findByText('Run History');
  assert.equal(view.queryByRole('button', { name: 'Run deployed provider' }), null);
});
