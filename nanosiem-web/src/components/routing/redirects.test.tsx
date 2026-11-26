// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5850: the old hunt settings routes land on their new homes in one hop,
// query string kept (design section 3).
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { QueryPreservingRedirect } from './QueryPreservingRedirect';
import { LEGACY_HUNT_REDIRECTS, fillParams, redirectTarget } from './redirects';
import app from '../../App.tsx?raw';

afterEach(cleanup);

describe('redirectTarget', () => {
  it('keeps the incoming query and hash', () => {
    expect(redirectTarget('/hunts/knowledge', '?tab=find&q=kn_1', '#row', 'keep')).toBe('/hunts/knowledge?tab=find&q=kn_1#row');
  });
  it("lets the target's own params win and keeps the rest", () => {
    expect(redirectTarget('/hunts/knowledge?tab=suppressions', '?tab=baseline&q=sup_1', '', 'keep')).toBe('/hunts/knowledge?tab=suppressions&q=sup_1');
  });
  it('drops the incoming query and hash when told to', () => {
    expect(redirectTarget('/settings/hunts', '?x=1', '#h', 'drop')).toBe('/settings/hunts');
  });
  it('adds no stray "?" when there is no query', () => {
    expect(redirectTarget('/rules/ideas', '', '', 'keep')).toBe('/rules/ideas');
  });
});

/** Every route a legacy redirect may land on renders its own path (no further redirect). */
const LANDINGS = ['/hunts/knowledge', '/hunts/leads/decisions', '/settings/hunts', '/rules/ideas', '/hunts/actors', '/hunts/actors/review', '/hunts/actors/:id'];

function Here() {
  const { pathname, search, hash } = useLocation();
  return <div data-testid="here">{`${pathname}${search}${hash}`}</div>;
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        {LEGACY_HUNT_REDIRECTS.map((r) => (
          <Route key={r.from} path={r.from} element={<QueryPreservingRedirect to={r.to} query={r.query} />} />
        ))}
        {LANDINGS.map((p) => <Route key={p} path={p} element={<Here />} />)}
      </Routes>
    </MemoryRouter>,
  );
}

describe('fillParams', () => {
  it('fills matched params, encoded, and leaves the rest', () => {
    expect(fillParams('/hunts/actors/:id', { id: 'hcmp_1' })).toBe('/hunts/actors/hcmp_1');
    expect(fillParams('/hunts/actors/:id', { id: 'a b/c' })).toBe('/hunts/actors/a%20b%2Fc');
    expect(fillParams('/hunts/actors/:id', {})).toBe('/hunts/actors/:id');
    expect(fillParams('/rules/ideas', { id: 'x' })).toBe('/rules/ideas');
  });
});

describe('legacy hunt redirects', () => {
  it.each([
    ['/hunts/memory', '/hunts/knowledge'],
    ['/hunts/memory?tab=suppressions&q=x', '/hunts/knowledge?tab=suppressions&q=x'],
    ['/hunts/memory?tab=find&q=kn_01', '/hunts/knowledge?tab=find&q=kn_01'],
    ['/hunts/suppressions', '/hunts/knowledge?tab=suppressions'],
    ['/hunts/suppressions?q=sup_7', '/hunts/knowledge?tab=suppressions&q=sup_7'],
    ['/hunts/rulings?hunt=pb_1&disposition=benign', '/hunts/leads/decisions?hunt=pb_1&disposition=benign'],
    ['/hunts/runners?anything=1', '/settings/hunts'],
    ['/hunts/rule-ideas?playbook_id=pb_9', '/rules/ideas?playbook_id=pb_9'],
    // NAN-5859: Campaigns became Actors.
    ['/hunts/campaigns', '/hunts/actors'],
    ['/hunts/campaigns?status=proposals', '/hunts/actors?status=proposals'],
    ['/hunts/campaigns/candidates', '/hunts/actors/review?kind=unassigned'],
    ['/hunts/campaigns/candidates?x=1', '/hunts/actors/review?kind=unassigned&x=1'],
    ['/hunts/campaigns/hcmp_01jd7m3k9p', '/hunts/actors/hcmp_01jd7m3k9p'],
    ['/hunts/campaigns/hcmp_01jd7m3k9p?tab=watch#r', '/hunts/actors/hcmp_01jd7m3k9p?tab=watch#r'],
  ])('%s lands on %s', (from, to) => {
    renderAt(from);
    expect(screen.getByTestId('here').textContent).toBe(to);
  });

  it('resolves every old path in one hop: no target is itself a redirect', () => {
    const sources = new Set(LEGACY_HUNT_REDIRECTS.map((r) => r.from));
    for (const r of LEGACY_HUNT_REDIRECTS) {
      const [path] = r.to.split('?');
      expect(sources.has(path)).toBe(false);
      expect(path.startsWith('/hunts/campaigns')).toBe(false);
      expect(LANDINGS).toContain(path);
    }
  });

  it('never redirects the new canonical Knowledge or Actors routes', () => {
    expect(LEGACY_HUNT_REDIRECTS.some((r) => r.from === '/hunts/knowledge')).toBe(false);
    expect(LEGACY_HUNT_REDIRECTS.some((r) => r.from.startsWith('/hunts/actors'))).toBe(false);
  });

  it('App.tsx registers every redirect in this table, with the same target and query handling', () => {
    for (const r of LEGACY_HUNT_REDIRECTS) {
      const drop = r.query === 'drop' ? ' query="drop"' : '';
      expect(app).toContain(`<Route path="${r.from}" element={<QueryPreservingRedirect to="${r.to}"${drop} />} />`);
    }
    expect(app.match(/<QueryPreservingRedirect /g)?.length).toBe(LEGACY_HUNT_REDIRECTS.length);
  });
});
