// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5844 / NAN-5850: which Hunts rail entry owns a path.
import { describe, expect, test } from 'vitest';
import { isHuntsNavItemActive } from './hunts-navigation';

const ENTRIES = ['/hunts', '/hunts/leads', '/hunts/escalations', '/hunts/campaigns', '/hunts/knowledge'];
const owner = (path: string) => ENTRIES.filter((href) => isHuntsNavItemActive(path, href));

describe('isHuntsNavItemActive', () => {
  test.each([
    ['/hunts', '/hunts'],
    ['/hunts/pb_01', '/hunts'],
    // Profile has no rail entry of its own until it folds into MITRE Coverage.
    ['/hunts/profile', '/hunts'],
    ['/hunts/leads', '/hunts/leads'],
    ['/hunts/leads/lead_01', '/hunts/leads'],
    ['/hunts/leads/decisions', '/hunts/leads'],
    ['/hunts/escalations', '/hunts/escalations'],
    ['/hunts/campaigns/candidates', '/hunts/campaigns'],
    ['/hunts/campaigns/cmp_01', '/hunts/campaigns'],
    ['/hunts/knowledge', '/hunts/knowledge'],
    // Redirect-only legacy routes light their new home for the one render.
    ['/hunts/memory', '/hunts/knowledge'],
    ['/hunts/suppressions', '/hunts/knowledge'],
    ['/hunts/rulings', '/hunts/leads'],
  ])('%s is owned by exactly %s', (path, href) => {
    expect(owner(path)).toEqual([href]);
  });

  test('pages that left the Hunts group light no Hunts entry', () => {
    expect(owner('/hunts/runners')).toEqual([]);
    expect(owner('/hunts/rule-ideas')).toEqual([]);
  });

  test('paths outside /hunts belong to no entry', () => {
    expect(owner('/huntsman')).toEqual([]);
    expect(owner('/search')).toEqual([]);
    expect(owner('/settings/hunts')).toEqual([]);
    expect(owner('/rules/ideas')).toEqual([]);
  });
});
