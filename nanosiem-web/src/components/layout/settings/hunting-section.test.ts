// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5850: Settings > Workspace > Hunting (Runners, Charter & defaults).
import { describe, expect, test } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { SETTINGS_LANDING_PERMISSIONS, SETTINGS_SECTIONS, isSectionVisible, resolveActiveSection, settingsHomeHref } from './sections';
import app from '../../../App.tsx?raw';

const hunting = SETTINGS_SECTIONS.find((s) => s.id === 'hunting')!;

function ctx(hunts: boolean, perms: string[]) {
  return {
    capabilities: { hunts } as unknown as Capabilities,
    edition: 'enterprise' as const,
    isDemoUser: false,
    isAirGap: false,
    hasPermission: (p: string) => perms.includes(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => perms.includes(p)),
  };
}

describe('Hunting settings section', () => {
  test('sits in Workspace with Runners then Charter & defaults', () => {
    expect(hunting.group).toBe('workspace');
    expect(hunting.href).toBe('/settings/hunts');
    expect(hunting.children?.map((c) => [c.label, c.href])).toEqual([
      ['Runners', '/settings/hunts'],
      ['Charter & defaults', '/settings/hunts/charter'],
      ['Actors', '/settings/hunts/actors'],
    ]);
  });

  test('needs the hunts capability and hunts:view', () => {
    expect(isSectionVisible(hunting, ctx(true, ['hunts:view']))).toBe(true);
    expect(isSectionVisible(hunting, ctx(false, ['hunts:view']))).toBe(false);
    expect(isSectionVisible(hunting, ctx(true, ['settings:system']))).toBe(false);
  });

  test.each([
    ['/settings/hunts', 'hunting-runners'],
    ['/settings/hunts/charter', 'hunting-charter'],
    ['/settings/hunts/actors', 'hunting-actors'],
  ])('%s lights %s under Hunting', (path, id) => {
    expect(resolveActiveSection(path)).toEqual({ sectionId: id, parentId: 'hunting' });
  });

  test('a hunts:view-only role sees Hunting and no other Settings section', () => {
    const visible = SETTINGS_SECTIONS.filter((s) => isSectionVisible(s, ctx(true, ['hunts:view']))).map((s) => s.id);
    expect(visible).toEqual(['hunting']);
  });

  test('the /settings landing gate in App.tsx is exactly SETTINGS_LANDING_PERMISSIONS, with no hunts permission', () => {
    const m = app.match(/<Route path="\/settings" element=\{\s*<PermissionRoute anyPermission=\{\[([^\]]*)\]\}/);
    expect(m).not.toBeNull();
    const perms = [...m![1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
    expect(perms).toEqual([...SETTINGS_LANDING_PERMISSIONS]);
    expect(perms.some((p) => p.startsWith('hunts:'))).toBe(false);
  });

  test('Settings links point at the landing, or at the first visible section for a role that cannot open it', () => {
    expect(settingsHomeHref(true, '/settings/hunts')).toBe('/settings');
    expect(settingsHomeHref(false, '/settings/hunts')).toBe('/settings/hunts');
    expect(settingsHomeHref(false, undefined)).toBe('/settings');
  });
});
