// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5716: a linked rule edited locally reads DRIFT (the server derives
// `local_drift` from a content hash); an upstream change still outranks it.
import { describe, expect, it } from 'vitest';
import type { RepositoryRule, RuleRepository, UpdatedRule } from '@/lib/api/rule-repositories';
import { buildRepoView, buildRuleView, categoryCounts } from './helpers';

function rule(overrides: Partial<RepositoryRule> = {}): RepositoryRule {
  return {
    id: 'rrule_1',
    repository_id: 'rrepo_1',
    file_path: 'windows/a.npl',
    file_sha: 'abcdef0123',
    raw_content: '',
    is_imported: false,
    linked_detection_rule_id: null,
    title: 'A rule',
    description: null,
    severity: 'high',
    mitre_tactics: null,
    mitre_techniques: null,
    ...overrides,
  } as RepositoryRule;
}

const upd = (file_path: string, change_type: UpdatedRule['change_type'] = 'modified'): UpdatedRule => ({
  repository_rule_id: 'rrule_x',
  detection_rule_id: 'rule_x',
  file_path,
  title: null,
  change_type,
  old_sha: null,
  new_sha: null,
});

describe('buildRuleView status (NAN-5716)', () => {
  it('an imported rule with local edits reads DRIFT', () => {
    const v = buildRuleView(rule({ is_imported: true, local_drift: true }), new Map(), '');
    expect(v.status).toBe('DRIFT');
  });

  it('an imported rule without local edits reads IMPORTED', () => {
    expect(buildRuleView(rule({ is_imported: true, local_drift: false }), new Map(), '').status).toBe('IMPORTED');
    // Older API without the field.
    expect(buildRuleView(rule({ is_imported: true }), new Map(), '').status).toBe('IMPORTED');
  });

  it('an upstream update outranks drift', () => {
    const r = rule({ is_imported: true, local_drift: true });
    expect(buildRuleView(r, new Map([[r.file_path, upd(r.file_path)]]), '').status).toBe('UPDATED');
    expect(buildRuleView(r, new Map([[r.file_path, upd(r.file_path, 'deleted')]]), '').status).toBe('DELETED');
  });

  it('local_drift on a rule that is not imported is ignored', () => {
    expect(buildRuleView(rule({ is_imported: false, local_drift: true }), new Map(), '').status).toBe('AVAILABLE');
  });

  it('counts drift in the repo view and the Drift category', () => {
    const rules = [
      rule({ id: 'a', file_path: 'a.npl', is_imported: true, local_drift: true }),
      rule({ id: 'b', file_path: 'b.npl', is_imported: true, local_drift: true }),
      rule({ id: 'c', file_path: 'c.npl', is_imported: true }),
      rule({ id: 'd', file_path: 'd.npl' }),
    ];
    const upstream = [upd('b.npl')];
    const repo = {
      id: 'rrepo_1',
      name: 'rules',
      slug: 'nano-rs/rules',
      url: 'https://github.com/nano-rs/rules',
      branch: 'main',
      rule_count: rules.length,
      last_sync_status: 'success',
      last_synced_at: null,
      last_sync_commit: null,
      auto_sync_enabled: false,
      sync_interval_hours: 0,
    } as unknown as RuleRepository;
    expect(buildRepoView(repo, rules, upstream).counts.drift).toBe(1);

    const byPath = new Map(upstream.map((u) => [u.file_path, u]));
    const views = rules.map((r) => buildRuleView(r, byPath, ''));
    expect(categoryCounts(views).find((c) => c.id === 'drift')?.count).toBe(1);
  });
});
