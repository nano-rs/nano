// NAN-5592: rule lifecycle actions target one rule the page shows, bind its
// mode once (sent as expected_mode), make exactly one server transition, and
// run through pivtApi (the analyst's session, marked pivt). Query edits only
// ever land in the editor buffer.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DetectionRule } from '@/lib/api/types';
import { capPageContext, PivtRefusal } from '@/contexts/pivt-page';

const mock = vi.hoisted(() => ({ promote: vi.fn(), demote: vi.fn(), pause: vi.fn(), resume: vi.fn() }));
vi.mock('@/lib/api/pivt-api', () => ({
  pivtApi: {
    promoteDetection: mock.promote,
    demoteDetection: mock.demote,
    pauseDetection: mock.pause,
    resumeDetection: mock.resume,
  },
}));

import { editQueryAction, MAX_CONTEXT_RULES, resolveRule, ruleLifecycleActions, ruleRow, ruleSummary } from './rulesPivt';

const rule = (id: string, mode: DetectionRule['mode'], over: Partial<DetectionRule> = {}): DetectionRule =>
  ({
    id,
    name: `rule ${id}`,
    query: 'event_type=logon',
    severity: 'high',
    mode,
    mitre_tactics: ['TA0006'],
    mitre_techniques: ['T1110'],
    tags: [],
    match_count: 3,
    created_at: '2026-11-17T00:00:00Z',
    updated_at: '2026-11-17T00:00:00Z',
    ...over,
  }) as DetectionRule;

const visible = [rule('rule_s', 'staging'), rule('rule_l', 'live'), rule('rule_a', 'alerting'), rule('rule_p', 'paused')];

beforeEach(() => {
  vi.clearAllMocks();
  for (const f of Object.values(mock)) f.mockImplementation(async (id: string) => rule(id, 'live'));
});

function spec(name: string, targets: Parameters<typeof ruleLifecycleActions>[0], mode?: DetectionRule['mode']) {
  const s = ruleLifecycleActions(targets, { mode }).find((a) => a.name === name);
  if (!s) throw new Error(`${name} not offered`);
  return s;
}

describe('rule lifecycle actions', () => {
  it('need detections:promote (what the REST routes enforce) and change state', () => {
    const all = ruleLifecycleActions({ visible: () => visible });
    expect(all.map((a) => a.name)).toEqual(['rules.promote', 'rules.demote', 'rules.pause', 'rules.resume']);
    for (const a of all) expect([a.permission, a.mutates]).toEqual(['detections:promote', true]);
  });

  it('bind the named rule and its current mode, only for rules on the page', () => {
    const s = spec('rules.promote', { visible: () => visible });
    expect(s.bind!({ rule_id: 'rule_l' })).toEqual({ rule_id: 'rule_l', from: 'live', rule_name: 'rule rule_l' });
    expect(() => s.bind!({ rule_id: 'rule_forged' })).toThrow(PivtRefusal);
    expect(() => s.bind!({ rule_id: 'rule_forged' })).toThrow('Rule rule_forged is not on this page.');
  });

  it('fall back to the focused rule; refuse with no target', () => {
    const s = spec('rules.pause', { visible: () => visible, focused: () => 'rule_a' });
    expect(s.bind!({})).toMatchObject({ rule_id: 'rule_a', from: 'alerting' });
    expect(() => spec('rules.pause', { visible: () => visible }).bind!({})).toThrow('Open or select the rule first');
  });

  it('refuse a transition the rule is not in a mode for', () => {
    const t = { visible: () => visible };
    expect(() => spec('rules.promote', t).bind!({ rule_id: 'rule_a' })).toThrow('already alerting');
    expect(() => spec('rules.promote', t).bind!({ rule_id: 'rule_p' })).toThrow('resume it first');
    expect(() => spec('rules.demote', t).bind!({ rule_id: 'rule_s' })).toThrow('already in staging');
    expect(() => spec('rules.pause', t).bind!({ rule_id: 'rule_p' })).toThrow('already paused');
    // The server pauses only running rules.
    expect(() => spec('rules.pause', t).bind!({ rule_id: 'rule_s' })).toThrow('in staging and not running');
    expect(() => spec('rules.resume', t).bind!({ rule_id: 'rule_l' })).toThrow('not paused');
  });

  it('preview the single transition, and warn before a rule starts alerting', async () => {
    const s = spec('rules.promote', { visible: () => visible });
    const p = await s.preview!(s.bind!({ rule_id: 'rule_l' }));
    expect(p.rows).toEqual([
      ['rule', 'rule_l'],
      ['mode', 'live → alerting'],
      ['note', 'Alerting rules generate alerts.'],
    ]);
    const r = spec('rules.resume', { visible: () => visible });
    expect((await r.preview!(r.bind!({ rule_id: 'rule_p' }))).rows?.[1]).toEqual(['mode', 'paused → its mode before the pause']);
  });

  it('run one transition with the BOUND mode as expected_mode, then refresh', async () => {
    const onChanged = vi.fn();
    const s = spec('rules.promote', { visible: () => visible, onChanged });
    const bound = s.bind!({ rule_id: 'rule_s' });
    const res = await s.run(bound);
    expect(mock.promote).toHaveBeenCalledExactlyOnceWith('rule_s', 'staging');
    expect(onChanged).toHaveBeenCalled();
    expect(res.summary).toBe('rule rule_s: staging → live');
  });

  it('on the editor: only the transitions that fit the rule, no rule_id param, no retargeting', () => {
    const open = rule('rule_x', 'live');
    const t = { visible: () => [open], fixed: () => open };
    const names = ruleLifecycleActions(t, { mode: 'live' }).map((a) => a.name);
    expect(names).toEqual(['rules.promote', 'rules.demote', 'rules.pause']);
    expect(ruleLifecycleActions(t, { mode: 'paused' }).map((a) => a.name)).toEqual(['rules.resume']);
    expect(ruleLifecycleActions(t, { mode: 'staging' }).map((a) => a.name)).toEqual(['rules.promote']);
    expect(ruleLifecycleActions(t, { mode: 'alerting' }).map((a) => a.name)).toEqual(['rules.demote', 'rules.pause']);
    const s = spec('rules.demote', t, 'live');
    expect(s.params).toEqual({});
    expect(s.bind!({})).toMatchObject({ rule_id: 'rule_x', from: 'live' });
    expect(() => s.bind!({ rule_id: 'rule_other' })).toThrow('different rule');
  });

  it('re-check at Apply: a rule no longer on the page (or another rule open) is not changed', async () => {
    let shown = visible;
    const s = spec('rules.promote', { visible: () => shown });
    const bound = s.bind!({ rule_id: 'rule_l' });
    shown = [rule('rule_s', 'staging')];
    await expect(s.run(bound)).rejects.toThrow('not on this page');
    let open = rule('rule_x', 'live');
    const e = spec('rules.demote', { visible: () => [open], fixed: () => open }, 'live');
    const eb = e.bind!({});
    open = rule('rule_y', 'live');
    await expect(e.run(eb)).rejects.toThrow('different rule');
    expect(mock.promote).not.toHaveBeenCalled();
    expect(mock.demote).not.toHaveBeenCalled();
  });

  it('resolveRule prefers the fixed rule', () => {
    const open = rule('rule_x', 'staging');
    expect(resolveRule({ visible: () => visible, fixed: () => open })).toBe(open);
  });
});

describe('rules.edit_query', () => {
  it('needs detections:edit, shows the buffer → proposal diff, and only writes the buffer', async () => {
    const apply = vi.fn();
    const buffer = 'event_type=logon';
    const s = editQueryAction({ ruleId: () => 'rule_x', currentQuery: () => buffer, apply });
    expect([s.permission, s.mutates]).toEqual(['detections:edit', true]);
    const bound = s.bind!({ query: '  event_type=logon | where auth_result="failure"  ' });
    const p = await s.preview!(bound);
    expect(p.diff).toEqual({ before: 'event_type=logon', after: 'event_type=logon | where auth_result="failure"', lang: 'npl' });
    const res = await s.run(bound);
    expect(apply).toHaveBeenCalledExactlyOnceWith('event_type=logon | where auth_result="failure"');
    expect(res.summary).toMatch(/unsaved/);
    for (const f of Object.values(mock)) expect(f).not.toHaveBeenCalled();
  });

  it('refuses an empty query, and a card bound to another rule', async () => {
    let open: string | null = 'rule_x';
    const apply = vi.fn();
    const s = editQueryAction({ ruleId: () => open, currentQuery: () => '', apply });
    expect(() => s.bind!({ query: '   ' })).toThrow(PivtRefusal);
    const bound = s.bind!({ query: 'x=1' });
    open = 'rule_y';
    await expect(s.run(bound)).rejects.toThrow('different rule');
    expect(apply).not.toHaveBeenCalled();
  });

  it('refuses when the analyst edited the buffer after the card showed (the confirmed diff is stale)', async () => {
    let buffer = 'a=1';
    const apply = vi.fn();
    const s = editQueryAction({ ruleId: () => 'rule_x', currentQuery: () => buffer, apply });
    const bound = s.bind!({ query: 'a=2' });
    buffer = 'a=1 | head 5';
    await expect(s.run(bound)).rejects.toThrow('changed since this card was shown');
    expect(apply).not.toHaveBeenCalled();
  });
});

describe('Rules list page context', () => {
  it('stays under the 8 KB cap with a full list, an open rule and a selection', () => {
    const long = 'x'.repeat(48);
    const rules = Array.from({ length: 40 }, (_, i) =>
      rule(`rule_01kfz${String(i).padStart(21, '0')}`, 'alerting', {
        name: `${long}_${i}`,
        query: 'q'.repeat(3000),
        mitre_tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0004'],
        mitre_techniques: ['T1001', 'T1002', 'T1003', 'T1004', 'T1005', 'T1006'],
        last_match_at: '2026-11-17T12:00:00Z',
        last_run_at: '2026-11-17T12:00:00Z',
      }),
    );
    const open = rules[0];
    const { truncated, context } = capPageContext({
      pageKey: 'rules',
      title: 'Detection rules',
      facts: [
        { label: 'showing', value: '40 of 40' },
        { label: 'filters', value: 'all · all · all · All tactics' },
        { label: 'firing', value: '40' },
        { label: 'open', value: open.name },
      ],
      entity: { kind: 'rule', id: open.id, name: open.name },
      selection: { kind: 'rule', ids: rules.slice(0, 20).map((r) => r.id) },
      data: {
        counts: { total: 40, showing: 40, firing: 40, silent: 0 },
        filters: { severity: 'all', status: 'all', schedule: 'all', tactic: 'All tactics', name: '' },
        open_rule: { ...ruleSummary(open), query: open.query.slice(0, 500) },
        rules: rules.slice(0, MAX_CONTEXT_RULES).map((r) => ruleRow(r, 12345)),
      },
    });
    expect(truncated).toBe(false);
    expect((context.data?.rules as unknown[]).length).toBe(MAX_CONTEXT_RULES);
  });
});

describe('ruleSummary', () => {
  it('is compact and carries no query text', () => {
    const s = ruleSummary(rule('rule_s', 'staging'));
    expect(s).toMatchObject({ id: 'rule_s', mode: 'staging', severity: 'high', tactics: ['TA0006'], matches: 3 });
    expect(JSON.stringify(s)).not.toContain('event_type');
  });
});
