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
    expect(pageKeyFor('/playbooks/new')).toBe('playbook-editor');
    expect(pageKeyFor('/playbooks/repositories')).toBe('playbook-repositories');
    expect(pageKeyFor('/rules/repositories')).toBe('rule-repositories');
    expect(pageKeyFor('/nowhere')).toBe('home');
  });

  // NAN-5571: segment-aware matching and the routes that used to fall
  // through to `home` or collapse into the wrong key.
  test.each([
    ['/', 'home'],
    ['/search', 'search'],
    ['/alerts', 'alerts'],
    ['/alerts/01890000-0000-7000-8000-000000000001', 'alert'],
    ['/rules', 'rules'],
    ['/rules/abc/matches', 'matches'],
    ['/rules/editor/new', 'rule-editor'],
    ['/rules/editor/abc', 'rule-editor'],
    ['/rules/tuning', 'ai-tuning'],
    ['/rules/tuning/p1', 'tuning-proposal'],
    ['/rules/coverage', 'mitre-coverage'],
    ['/rules/lookup-tables/geo', 'lookup-tables'],
    ['/hunts', 'hunts'],
    ['/hunts/h1', 'hunt'],
    ['/hunts/leads', 'hunt-leads'],
    ['/hunts/leads/l1', 'hunt-lead'],
    ['/hunts/campaigns/candidates', 'hunt-campaigns'],
    ['/hunts/campaigns/c1', 'hunt-campaign'],
    ['/inbox', 'inbox'],
    ['/cases/search', 'case-search'],
    ['/cases/c1', 'case'],
    ['/automation/runs', 'automation-runs'],
    ['/automation/runs/r1', 'automation-runs'],
    ['/automation/flows/f1', 'automation-flow'],
    ['/dashboards/d1', 'dashboard'],
    ['/notebooks', 'notebooks'],
    ['/notebooks/n1', 'notebook'],
    ['/ingestion/log-sources', 'log-sources'],
    ['/ingestion/log-sources/ls1', 'log-source'],
    ['/ingestion/log-sources/repositories', 'parser-repositories'],
    ['/ingestion/log-sources/credentials', 'ingest-credentials'],
    ['/ingestion/log-sources/cloud-pull', 'cloud-pull'],
    ['/ingestion/log-sources/inputs/sc1', 'source-config'],
    ['/ingestion/pipelines', 'pipelines'],
    ['/ingestion/pipelines/p1', 'pipeline'],
    ['/marketplace', 'marketplace'],
    ['/risk', 'risk'],
    ['/risk/watchlists', 'risk-watchlists'],
    ['/settings', 'settings'],
    ['/settings/cases/queues', 'settings'],
    ['/platform/health', 'health'],
    ['/search/', 'search'],
  ])('pageKeyFor(%s) = %s', (path, key) => {
    expect(pageKeyFor(path)).toBe(key);
  });

  test('prefixes need a segment boundary', () => {
    expect(pageKeyFor('/risky')).toBe('home');
    expect(pageKeyFor('/rulesx')).toBe('home');
    expect(pageKeyFor('/searchable')).toBe('home');
    expect(pageKeyFor('/matches')).toBe('home');
  });

  test('no literal route in App.tsx is read as a :param detail page', async () => {
    const app = (await import('../App.tsx?raw')).default as string;
    const literal = new Set<string>();
    for (const m of app.matchAll(/path(?:=|:\s*)["'](\/[^"'*:]*)["']/g)) literal.add(m[1]);
    // Keys that only a `:param` route produces.
    const detailKeys = new Set(['alert', 'matches', 'tuning-proposal', 'hunt', 'hunt-lead', 'hunt-campaign', 'case', 'automation-flow', 'dashboard', 'notebook', 'source-config', 'log-source', 'pipeline']);
    const misread = [...literal].filter((p) => detailKeys.has(pageKeyFor(p)));
    expect(misread).toEqual([]);
  });
});
