// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5716: Dismiss acknowledges an upstream change, so it is not offered on a
// DRIFT row (where it was a no-op behind a success toast); Resolve on a DRIFT
// row opens the upstream merge modal.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { linkedRuleEditorPath, upstreamDismissOffered } from './helpers';

describe('DRIFT row actions (NAN-5716)', () => {
  it('offers Dismiss only for an upstream update', () => {
    expect(upstreamDismissOffered('UPDATED')).toBe(true);
    for (const s of ['DRIFT', 'IMPORTED', 'DELETED', 'AVAILABLE', 'NEW'] as const) {
      expect(upstreamDismissOffered(s)).toBe(false);
    }
  });

  it('Resolve on DRIFT opens the merge modal; other rows open the editor', () => {
    expect(linkedRuleEditorPath('DRIFT', 'rule_1')).toBe('/rules/editor/rule_1?merge=upstream');
    expect(linkedRuleEditorPath('IMPORTED', 'rule_1')).toBe('/rules/editor/rule_1');
    expect(linkedRuleEditorPath('DELETED', 'rule_1')).toBe('/rules/editor/rule_1');
  });

  it('Preview-pane and Bulk import create linked imports, like the row Import', () => {
    const preview = readFileSync(resolve(__dirname, 'RepoPreview.tsx'), 'utf8');
    expect(preview).toContain("import_type: 'linked',");
    expect(preview).not.toContain("import_type: 'forked'");
    const batch = readFileSync(
      resolve(__dirname, '../../../../nanosiem-api/src/handlers/rule_repositories/batch.rs'),
      'utf8',
    );
    expect(batch).toContain('import_type: nanosiem_core::ImportType::Linked,');
    expect(batch).not.toContain('ImportType::Forked');
  });
});
