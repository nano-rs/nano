// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5716: a load/save round trip in the rule editor must not rewrite what is
// stored. Before: a description with `"` or `\` gained a layer of escaping on
// every save, and `informational` failed validation (the editor coerced it to
// `low`). Either rewrote a repository-linked rule, which then read DRIFT.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseDetectionMetadata, serializeDetectionMetadata, validateMetadata } from './detection-metadata';

function roundTrip(description: string) {
  const yaml = serializeDetectionMetadata({ title: 'rule_a', description, severity: 'low' }, 'class_uid=3002');
  return parseDetectionMetadata(yaml).metadata.description;
}

describe('detection metadata round trip (NAN-5716)', () => {
  it('keeps quotes and backslashes in a description unchanged', () => {
    for (const d of ['say "hi"', 'C:\\Windows\\System32', 'trailing \\', 'both \\"x\\"', 'plain']) {
      expect(roundTrip(d)).toBe(d);
      // Stable across repeated saves, not one escape layer per save.
      expect(roundTrip(roundTrip(d) ?? '')).toBe(d);
    }
  });

  it('accepts and keeps the informational severity', () => {
    const yaml = serializeDetectionMetadata({ title: 'rule_a', description: '', severity: 'informational' }, 'x');
    const { metadata } = parseDetectionMetadata(yaml);
    expect(metadata.severity).toBe('informational');
    expect(validateMetadata(metadata)).toEqual([]);
  });

  it('single-quoted scalars are left as written', () => {
    const { metadata } = parseDetectionMetadata("---\ntitle: rule_a\ndescription: 'a \\\" b'\n---\nx");
    expect(metadata.description).toBe('a \\" b');
  });

  it('the editor loads severity and lookback exactly as stored', () => {
    const editor = readFileSync(resolve(__dirname, '../pages/RuleEditorRedesign.tsx'), 'utf8');
    expect(editor).not.toContain("apiRule.severity === 'informational' ? 'low'");
    expect(editor).toContain(
      "const lookback = apiRule.lookback_minutes ? formatMinutesToDuration(apiRule.lookback_minutes) : '';",
    );
  });
});
