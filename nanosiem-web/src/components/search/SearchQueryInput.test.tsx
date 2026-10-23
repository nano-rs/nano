// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-4131: the "Try natural language" hint and the NATURAL LANGUAGE badge
// advertise pivt. Open core has no AI, so they render only when the page
// passes `onAiSearch` (capabilities.melod + connected provider).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { forwardRef } from 'react';
import { SearchQueryInput } from './SearchQueryInput';

vi.mock('@/lib/query-autocomplete', () => ({ setAutocompleteTimeRange: () => {} }));
vi.mock('@/components/editor', () => ({
  SearchQueryEditor: forwardRef(function MockEditor(
    { value, onChange, onFocus }: { value: string; onChange: (v: string) => void; onFocus?: () => void },
    _ref,
  ) {
    return <textarea aria-label="Query" value={value} onFocus={onFocus} onChange={e => onChange(e.target.value)} />;
  }),
}));

beforeEach(() => localStorage.clear());
afterEach(cleanup);

function renderInput(props: Partial<React.ComponentProps<typeof SearchQueryInput>>) {
  const onQueryChange = vi.fn();
  render(
    <SearchQueryInput query="show me logins" onQueryChange={onQueryChange} queryMode="piped" onSearch={() => {}} {...props} />,
  );
  const editor = screen.getByLabelText('Query');
  fireEvent.focus(editor);
  fireEvent.change(editor, { target: { value: 'show me logins' } });
  return { onQueryChange };
}

it('open core (no onAiSearch): no natural-language hint, badge or translate cue', () => {
  // aiMode=true simulates a stale/unknown AI signal; without onAiSearch it must stay closed.
  renderInput({ aiMode: true });
  expect(screen.queryByText('Try natural language like')).toBeNull();
  expect(screen.queryByText('Natural language')).toBeNull();
  expect(screen.queryByText(/translate/)).toBeNull();
});

it('enterprise with AI: the natural-language hint still shows', () => {
  renderInput({ onAiSearch: () => {} });
  expect(screen.getByText('Try natural language like')).toBeTruthy();
});

it('enterprise with AI in NL mode: shows the NATURAL LANGUAGE badge', () => {
  renderInput({ onAiSearch: () => {}, aiMode: true });
  expect(screen.getByText('Natural language')).toBeTruthy();
});
