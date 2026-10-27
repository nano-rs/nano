// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4597: a page's live Here card (Search's query + result count) must
// survive its own mount and every navigation back to it, and must never leak
// onto another page. The old `[pageKey]` reset effect in the provider ran
// after the page's own effect and wiped the override on mount.
import { act, cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, test } from 'vitest';
import { PageContextProvider, pageKeyFor, useHereCardOverride, usePageContext } from './PageContext';

/** Stands in for Search: registers a live card built from its state. */
function SearchPage() {
  useHereCardOverride({
    icon: 'Search',
    title: 'Search',
    tags: ['nPL'],
    lines: [
      { label: 'query', value: 'src_ip="10.0.0.5"' },
      { label: 'results', value: '42 events' },
    ],
  });
  return <div>search page</div>;
}

let go: (path: string) => void = () => {};
function Probe() {
  const { pageKey, hereCard } = usePageContext();
  go = useNavigate();
  return (
    <div data-testid="here">
      {pageKey}:{hereCard ? hereCard.lines?.map((l) => l.value).join('|') : 'static'}
    </div>
  );
}

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <PageContextProvider>
        <Probe />
        <Routes>
          <Route path="/search" element={<SearchPage />} />
          <Route path="/rules" element={<div>rules page</div>} />
        </Routes>
      </PageContextProvider>
    </MemoryRouter>,
  );
}

const here = () => screen.getByTestId('here').textContent;

afterEach(cleanup);

describe('PageContext Here card overrides', () => {
  test("Search's live card shows on mount, clears on another page, and returns with Search", () => {
    renderAt('/search');
    expect(here()).toBe('search:src_ip="10.0.0.5"|42 events');

    act(() => go('/rules'));
    expect(here()).toBe('rules:static');

    act(() => go('/search'));
    expect(here()).toBe('search:src_ip="10.0.0.5"|42 events');
  });

  test('a page without an override keeps the static card', () => {
    renderAt('/rules');
    expect(here()).toBe('rules:static');
  });

  test('pageKeyFor maps authoring and repository routes', () => {
    expect(pageKeyFor('/playbooks/new')).toBe('playbooks');
    expect(pageKeyFor('/playbooks/repositories')).toBe('playbook-repositories');
    expect(pageKeyFor('/rules/repositories')).toBe('rule-repositories');
    expect(pageKeyFor('/nowhere')).toBe('home');
  });
});
