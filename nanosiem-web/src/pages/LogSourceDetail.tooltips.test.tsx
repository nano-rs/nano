// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { LogSourceDetail } from './LogSourceDetail';

const mocks = vi.hoisted(() => ({ shared: false, disabled: false, mutate: vi.fn() }));
const source = {
  id: 'source_vercel', name: 'Vercel', source_type: 'routed', match_values: ['vercel'],
  parser_vrl: '.message = "draft"', extension_vrl: '.extra = true',
  enabled: true, deployed: true, get validated() { return !mocks.disabled; }, namespace: 'default', timezone: 'UTC',
  created_at: '2026-10-29T00:00:00Z', updated_at: '2026-10-29T00:00:00Z', output_fields: [],
};
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({
  user: { deployment_mode: mocks.shared ? 'enterprise_shared' : 'dedicated' }, hasPermission: () => true,
}) }));
vi.mock('@/hooks/useBreadcrumbTitle', () => ({ useBreadcrumbTitle: () => {} }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/hooks/use-capabilities', () => ({
  useIngestGate: () => ({ tenzirOnly: false, blocked: false }), useCapabilities: () => ({ capabilities: {} }),
}));
vi.mock('@/hooks/use-api', () => {
  const data = (value: unknown) => ({ data: value, loading: false, refetch: vi.fn() });
  const mutation = () => ({ mutate: mocks.mutate, loading: mocks.disabled });
  return {
    useLogSource: () => data(source), useLogSourceHealth: () => data(null),
    useLogSourceDeployments: () => data([]), useIngestionHistory: () => data([]),
    useLogSourceDraftStatus: () => data({ has_draft_changes: true, active_version_number: 1 }),
    useLogSourceVersions: () => data([{ id: 1, version_number: 1, is_active: true, parser_vrl: '.', change_reason: 'publish', created_at: source.created_at }]),
    ...Object.fromEntries(['useUpdateLogSource', 'useToggleLogSource', 'useValidateLogSource',
      'useValidateLogSourceVrl', 'useDeployLogSource', 'useUndeployLogSource', 'usePublishLogSource',
      'useDiscardLogSourceDraft'].map(name => [name, mutation])),
  };
});
vi.mock('@/lib/api', () => ({ ApiClientError: class extends Error {}, api: {
  listSourceConfigs: async () => [], getSchemaFields: async () => ({ schema: 'ocsf', fields: [] }),
} }));
vi.mock('@/components/parser-rollout/use-log-source-rollouts', () => ({
  useLogSourceRollouts: () => ({ data: [] }), useLatestLiveRollout: () => ({ data: null }),
}));
vi.mock('@/components/parser-rollout/PlatformUpdateBanner', () => ({ PlatformUpdateBanner: () => null }));
vi.mock('@/components/parser-rollout/LogSourceRolloutPanel', () => ({ LogSourceRolloutPanel: () => null }));
vi.mock('@/components/parser/ParserTestLab', () => ({ ParserTestLab: () => null }));
vi.mock('@/components/editor', () => ({ VrlEditor: ({ value, onChange }: { value: string; onChange?: (value: string) => void }) => (
  <textarea aria-label="VRL buffer" value={value} onChange={event => onChange?.(event.target.value)} />
) }));
vi.mock('@/components/ui/resizable', () => ({
  ResizablePanelGroup: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  ResizablePanel: ({ children }: { children: ReactNode }) => <div>{children}</div>, ResizableHandle: () => null,
}));

beforeEach(() => { mocks.shared = false; mocks.disabled = false; mocks.mutate.mockReset(); });
afterEach(cleanup);
function renderPage(tab: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/ingestion/log-sources/source_vercel?tab=${tab}`]}>
    <Routes><Route path="/ingestion/log-sources/:id" element={<LogSourceDetail />} /></Routes>
  </MemoryRouter></QueryClientProvider>);
}

it.each([false, true])('Publish controls explain live activation for shared=%s and still open the dialog', async shared => {
  mocks.shared = shared;
  const expected = shared
    ? 'Make this draft live for incoming events. The current version keeps serving until the rollout completes.'
    : 'Make this draft live for incoming events. The previous version is kept in history.';
  renderPage('versions');
  for (const name of ['Publish', 'Publish current draft']) {
    const button = screen.getByRole('button', { name });
    fireEvent.focus(button);
    expect((await screen.findByRole('tooltip')).textContent).toBe(expected);
    fireEvent.blur(button);
  }
  fireEvent.click(screen.getByRole('button', { name: 'Publish' }));
  expect(await screen.findByRole('alertdialog', { name: 'Publish log source?' })).toBeTruthy();
  expect(mocks.mutate).not.toHaveBeenCalled();
});

it.each(['config', 'vrl', 'extension'])('the %s Save control explains that incoming events are unaffected', async tab => {
  renderPage(tab);
  if (tab !== 'extension') fireEvent.click(screen.getByRole('button', { name: tab === 'vrl' ? 'Edit VRL' : 'Edit' }));
  else fireEvent.change(screen.getByLabelText('VRL buffer'), { target: { value: '.extra = false' } });
  const button = screen.getByRole('button', { name: tab === 'config' ? 'Save changes' : tab === 'vrl' ? 'Save VRL' : 'Save' });
  fireEvent.focus(button);
  expect((await screen.findByRole('tooltip')).textContent).toBe("Save this draft. Incoming events aren't affected until you publish.");
  expect(mocks.mutate).not.toHaveBeenCalled();
});

// Disabled buttons suppress pointer events; the existing Tooltip must target a
// hoverable, keyboard-focusable wrapper while the action remains disabled.
it.each([
  ['versions', 'Publish'],
  ['versions', 'Publish current draft'],
  ['config', 'Save changes'],
  ['vrl', 'Save VRL'],
  ['extension', 'Save'],
])('the disabled %s / %s action still exposes its tooltip', async (tab, name) => {
  mocks.disabled = true;
  renderPage(tab);
  if (tab === 'config' || tab === 'vrl') {
    fireEvent.click(screen.getByRole('button', { name: tab === 'vrl' ? 'Edit VRL' : 'Edit' }));
  }
  const button = screen.getByRole('button', { name }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  const trigger = button.parentElement!;
  expect(trigger.tagName).toBe('SPAN');
  expect(trigger.tabIndex).toBe(0);
  fireEvent.pointerMove(trigger, { pointerType: 'mouse' });
  expect((await screen.findByRole('tooltip')).textContent).toBe(name.startsWith('Publish')
    ? 'Make this draft live for incoming events. The previous version is kept in history.'
    : "Save this draft. Incoming events aren't affected until you publish.");
  fireEvent.pointerLeave(trigger);
  fireEvent.focus(trigger);
  expect(await screen.findByRole('tooltip')).toBeTruthy();
  fireEvent.click(button);
  expect(mocks.mutate).not.toHaveBeenCalled();
});
