// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-4132: the Add Feed parser panel's pivt tab, "Ask pivt" chat and
// "Generate with pivt" exist only when AI does (open core has none).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { VrlPanel } from './AddFeed';

const mocks = vi.hoisted(() => ({ capabilities: {} as Record<string, boolean> }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: mocks.capabilities }) }));
vi.mock('@/enterprise/hooks/use-melod-job', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/enterprise/hooks/use-melod-job')>()),
  useMelodJob: () => ({ start: vi.fn(), loading: false }),
}));
vi.mock('@/components/editor/VrlEditor', () => ({ VrlEditor: () => null }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

const props: ComponentProps<typeof VrlPanel> = {
  vrl: '.a = 1', setVrl: () => {}, genState: 'idle', genProgress: 0, genStatus: '',
  onRegenerate: () => {}, onValidate: async () => true, isValidating: false,
  // A stale 'ai' selection (e.g. persisted) must not open the chat on open core.
  sidePane: 'ai', setSidePane: () => {},
  validation: { diagnostics: [], syntaxValid: true, errorMessages: [] }, tests: [], feedId: 'acme',
  pivtMessage: '', setPivtMessage: () => {}, onSendPivt: () => {}, pivtPending: false,
  pivtSuggestion: null, applyPivtSuggestion: () => {}, draftSaved: true,
};

beforeEach(() => {
  mocks.capabilities = {};
  localStorage.clear();
});
afterEach(cleanup);

it('open core (no melod): no pivt tab, chat or generate button', () => {
  render(<VrlPanel {...props} />);
  expect(screen.queryByRole('button', { name: 'pivt' })).toBeNull();
  expect(screen.queryByText('Ask pivt')).toBeNull();
  expect(screen.queryByText(/Generate with pivt|Regenerate/)).toBeNull();
  expect(screen.queryByText(/pivt-drafted/)).toBeNull();
  expect(screen.getByRole('button', { name: /Diagnostics/ })).toBeTruthy();
});

it('enterprise with AI: pivt tab, chat and regenerate are still offered', () => {
  mocks.capabilities = { melod: true };
  render(<VrlPanel {...props} />);
  expect(screen.getByRole('button', { name: 'pivt' })).toBeTruthy();
  expect(screen.getByText('Ask pivt')).toBeTruthy();
  expect(screen.getByText('Regenerate')).toBeTruthy();
});

it('NAN-4753: a failed draft shows one sanitized sentence and a Retry, never HTML', () => {
  mocks.capabilities = { melod: true };
  const onRegenerate = vi.fn();
  render(
    <VrlPanel
      {...props}
      vrl=""
      genState="error"
      genStatus="pivt could not draft the parser. Retry in a moment. Reference a51666239c020c02."
      onRegenerate={onRegenerate}
    />,
  );
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('Reference a51666239c020c02');
  expect(alert.querySelector('script, button#cf-footer-ip-reveal')).toBeNull();
  screen.getByRole('button', { name: /Retry/ }).click();
  expect(onRegenerate).toHaveBeenCalledTimes(1);
});
