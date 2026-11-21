// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5683 — rule-editor control access mirrors the server check of each
// endpoint, and an archived rule is read-only.
import { describe, expect, test } from 'vitest';
import {
  ruleEditorActionAccess,
  type RuleEditorActionAccess,
  type RuleEditorActionInput,
} from './rule-action-access';

const ALL = {
  canView: true,
  canCreate: true,
  canEdit: true,
  canDelete: true,
  canPromote: true,
  canSearch: true,
  canViewAlerts: true,
  canMelodDetection: true,
};
const NONE = Object.fromEntries(Object.keys(ALL).map((k) => [k, false])) as typeof ALL;
const saved = { isNewMode: false, hasRule: true, archived: false, unsavedEdits: false };
const draft = { isNewMode: true, hasRule: false, archived: false, unsavedEdits: false };

function access(input: Partial<RuleEditorActionInput>): RuleEditorActionAccess {
  return ruleEditorActionAccess({ ...saved, ...ALL, ...input });
}
function granted(a: RuleEditorActionAccess): string[] {
  return Object.entries(a)
    .filter(([, v]) => v)
    .map(([k]) => k)
    .sort();
}

describe('archived rule', () => {
  test('offers only Unarchive (and its match history), even to an admin', () => {
    expect(granted(access({ archived: true }))).toEqual(['unarchive', 'viewMatches']);
  });

  test('unarchive needs detections:edit AND detections:promote', () => {
    expect(access({ archived: true, canPromote: false }).unarchive).toBe(false);
    expect(access({ archived: true, canEdit: false }).unarchive).toBe(false);
  });
});

describe('live saved rule', () => {
  test('an admin keeps every control', () => {
    expect(granted(access({}))).toEqual([
      'archive', 'delete', 'discard', 'duplicate', 'format', 'lifecycle', 'save', 'test', 'tune', 'tuneSettings',
      'viewMatches', 'write',
    ]);
  });

  test('archive needs edit + delete; delete needs delete (PUT {archived} / DELETE)', () => {
    expect(access({ canDelete: false })).toMatchObject({ archive: false, delete: false });
    expect(access({ canEdit: false })).toMatchObject({ archive: false, delete: true });
  });

  test('a view-only user gets no write, save, format or tune', () => {
    const a = access({ ...NONE, canView: true, canSearch: true });
    expect(granted(a)).toEqual(['test', 'viewMatches']);
  });

  test('test of the saved rule needs view + search:execute; of unsaved edits, create + search:execute', () => {
    expect(access({ canSearch: false }).test).toBe(false);
    expect(access({ canView: false }).test).toBe(false);
    expect(access({ unsavedEdits: true, canCreate: false }).test).toBe(false);
    expect(access({ unsavedEdits: true, canView: false }).test).toBe(true);
  });

  test('tune needs melod:detection + detections:view + alerts:view + search:execute, and edit to apply', () => {
    for (const missing of ['canMelodDetection', 'canView', 'canViewAlerts', 'canSearch', 'canEdit'] as const) {
      expect(access({ [missing]: false }).tune, missing).toBe(false);
    }
  });
});

describe('new rule draft', () => {
  test('a creator without detections:edit can author, format and test it', () => {
    const a = access({ ...draft, ...NONE, canView: true, canCreate: true, canSearch: true });
    expect(granted(a)).toEqual(['format', 'save', 'test', 'write']);
  });

  test('edit without create cannot author a new rule (POST /api/rules is detections:create)', () => {
    const a = access({ ...draft, canCreate: false });
    expect(a).toMatchObject({ write: false, save: false, format: false, test: false });
  });
});
