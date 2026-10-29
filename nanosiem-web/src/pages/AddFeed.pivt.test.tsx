// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-4132: the Add Feed parser panel's pivt tab, "Ask pivt" chat and
// "Generate with pivt" exist only when AI does (open core has none).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { SamplesPaste, VrlPanel } from './AddFeed';

const mocks = vi.hoisted(() => ({ capabilities: {} as Record<string, boolean> }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: mocks.capabilities }) }));
vi.mock('@/enterprise/hooks/use-melod-job', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/enterprise/hooks/use-melod-job')>()),
  useMelodJob: () => ({ start: vi.fn(), loading: false }),
}));
vi.mock('@/components/editor/VrlEditor', () => ({ VrlEditor: () => null }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

const props: ComponentProps<typeof VrlPanel> = {
  vrl: '.a = 1', setVrl: () => {}, genState: 'idle', genStatus: '',
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

it('NAN-4792: a running draft shows its stage and elapsed time, never a percentage', () => {
  mocks.capabilities = { melod: true };
  render(
    <VrlPanel {...props} vrl="" genState="streaming" genStatus="AI model is reasoning (900 characters so far)... · 7m 14s" />,
  );
  expect(screen.getByTestId('draft-stage').textContent).toBe('reasoning');
  expect(screen.getByText(/7m 14s/)).toBeTruthy();
  expect(screen.queryByText(/\d+%/)).toBeNull();
});

it('NAN-4792: a terminal-wrapped paste shows the split and joins only on click', () => {
  const head = '<134>Oct 28 14:02:11 fw01 traffic: action=allow src=10.0.4.12 dst=8.8.8.8 dport=443 proto=tcp';
  const wrapped = [1, 2, 3, 4].map((i) => `${head} seq=${i}\n  bytes_out=1832 bytes_in=48211 user=alice`).join('\n');
  const setSampleText = vi.fn();
  render(<SamplesPaste sampleText={wrapped} setSampleText={setSampleText} sampleCount={8} />);
  expect(screen.getByTestId('sample-split').textContent).toBe('8 sample lines · one event per line');
  expect(screen.getByRole('status').textContent).toContain('4 of 8 lines look like wrapped continuations');
  expect(setSampleText).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Join wrapped lines' }));
  expect(setSampleText).toHaveBeenCalledTimes(1);
  expect(setSampleText.mock.calls[0][0].split('\n')).toHaveLength(4);
});

it('NAN-4792: a clean paste shows the count and no warning', () => {
  const clean = ['<134>Oct 28 14:02:11 fw01 a=1', '<134>Oct 28 14:02:12 fw01 a=2', '<134>Oct 28 14:02:13 fw01 a=3'].join('\n');
  render(<SamplesPaste sampleText={clean} setSampleText={() => {}} sampleCount={3} />);
  expect(screen.getByTestId('sample-split').textContent).toBe('3 sample lines · one event per line');
  expect(screen.queryByRole('status')).toBeNull();
});

it.each([
  ['compact multiline JSON', '{"a": 1,\n "b": 2}\n{"a": 3,\n "b": 4}'],
  ['CSV with quoted newlines', 'timestamp,message\n2026-10-28T14:02:11Z,"failed\n  retry"\n2026-10-28T14:02:12Z,ok'],
  ['an indented CSV row', 'user,action\n  alice,login\nbob,logout'],
  ['a short Java exception', '2026-10-28T14:02:11Z failed\njava.lang.IllegalStateException: failed\n2026-10-28T14:02:12Z ok'],
  ['Windows XML', '<Event>\n  <System><EventID>4624</EventID></System>\n</Event>'],
])('NAN-4792: %s offers no Join and preserves the paste on rerender', (_name, sampleText) => {
  const setSampleText = vi.fn();
  const samples = { sampleText, setSampleText, sampleCount: sampleText.split('\n').length };
  const { rerender } = render(<SamplesPaste {...samples} />);
  rerender(<SamplesPaste {...samples} />);
  expect(screen.queryByRole('status')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Join wrapped lines' })).toBeNull();
  expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe(sampleText);
  expect(setSampleText).not.toHaveBeenCalled();
});
