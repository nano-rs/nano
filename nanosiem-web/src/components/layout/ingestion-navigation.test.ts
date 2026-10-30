// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-3620: Ingestion → Credentials is hidden on hosted-shared only. */
import { describe, expect, it } from 'vitest';
import { ingestionNavigation, visibleOnEdition } from './ingestion-navigation';

const visible = (shared: boolean) => ingestionNavigation.filter(item => visibleOnEdition(item, shared)).map(item => item.name);

describe('ingestion navigation by edition', () => {
  it('hides Credentials (and Source Configs) on hosted-shared', () => {
    const shared = visible(true);
    expect(shared).not.toContain('Credentials');
    expect(shared).not.toContain('Source Configs');
    expect(shared).toEqual(['Log Sources', 'Pipelines', 'Repositories']);
  });

  it('keeps Credentials on open core and dedicated', () => {
    const dedicated = visible(false);
    expect(dedicated).toContain('Credentials');
    expect(dedicated).toContain('Source Configs');
    expect(dedicated).not.toContain('Pipelines');
    const credentials = ingestionNavigation.find(item => item.name === 'Credentials');
    expect(credentials).toMatchObject({ href: '/ingestion/credentials', permissions: 'credentials:view', hideOnShared: true });
  });

  it('gates each item on its own flags', () => {
    expect(visibleOnEdition({}, true)).toBe(true);
    expect(visibleOnEdition({}, false)).toBe(true);
    expect(visibleOnEdition({ hideOnShared: true }, true)).toBe(false);
    expect(visibleOnEdition({ hideOnShared: true }, false)).toBe(true);
    expect(visibleOnEdition({ sharedOnly: true }, false)).toBe(false);
    expect(visibleOnEdition({ sharedOnly: true }, true)).toBe(true);
  });

  it('removes the old onboarding surface from navigation', () => {
    for (const shared of [true, false]) expect(visible(shared)).not.toContain('Source onboarding');
  });
});
