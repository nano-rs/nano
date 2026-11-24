// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5773: the rule rail footer counts what the selected tab lists; deleted
// (archived) rules never inflate the Active tab's total.
import { describe, expect, it } from 'vitest';
import { activeFolderNames, inRailTab, railTabTotal } from './helpers';

const live = { archived: false };
const legacy = { archived: undefined };
const deleted = { archived: true };

describe('inRailTab', () => {
  it('puts archived rules only in the Archived tab', () => {
    expect(inRailTab(deleted, 'archived')).toBe(true);
    expect(inRailTab(deleted, 'active')).toBe(false);
  });
  it('treats a rule without the flag as active', () => {
    expect(inRailTab(legacy, 'active')).toBe(true);
    expect(inRailTab(legacy, 'archived')).toBe(false);
  });
});

describe('railTabTotal', () => {
  const rules = [live, ...Array.from({ length: 16 }, () => deleted)];

  it('counts 1 rule on Active when 16 more are archived', () => {
    expect(railTabTotal(rules, 'active')).toBe(1);
  });
  it('counts the archived rules on Archived', () => {
    expect(railTabTotal(rules, 'archived')).toBe(16);
  });
  it('is zero for an empty tab', () => {
    expect(railTabTotal([deleted], 'active')).toBe(0);
    expect(railTabTotal([], 'archived')).toBe(0);
  });
});

describe('activeFolderNames', () => {
  it('leaves out folders only deleted rules use', () => {
    const rules = [
      { archived: false, folder: 'network' },
      { archived: true, folder: 'gone_folder' },
      { archived: true, folder: 'network' },
      { archived: undefined, folder: '' },
    ];
    expect(activeFolderNames(rules)).toEqual(['network', 'Uncategorized']);
  });
});
