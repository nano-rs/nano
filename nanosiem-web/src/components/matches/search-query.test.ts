import { describe, expect, it } from 'vitest';
import { matchSearchUrl } from './search-window';
import { buildMatchView } from './helpers';
import { ruleMatchSearchQuery as pivot } from './search-query';
const entity = { raw: 'iad2-jobs', type: 'user' };
const prefix = 'metadata.log_source=ops_shared_apps | eval failed=if(status="error",1,0) | where failed=1';
const query = `${prefix} | stats count, sum(failed) as failures by metadata.product.name, metadata.tenant_uid | where failures>2 | risk score=50 | table metadata.product.name`;
describe('rule-aware pivot', () => {
  it('retains the ops filter pipeline and all group values instead of the guessed user', () => {
    expect(pivot(query, [{ 'metadata.product.name': 'iad2-jobs', 'metadata.tenant_uid': 'ops' }], entity))
      .toBe(`${prefix} | where (metadata.product.name="iad2-jobs" AND metadata.tenant_uid="ops")`);
  });
  it('carries the exact group query and contributing event window into the Matches URL', () => {
    const view = buildMatchView({ id: 'm', detected_at: '2026-10-17T12:30:00Z', severity: 'high', status: 'open', event_count: 1,
      events: [{ 'metadata.product.name': 'iad2-jobs', 'metadata.tenant_uid': 'ops', first_seen: '2026-10-17T12:00:00Z', last_seen: '2026-10-17T12:20:00Z' }] });
    const url = new URL(matchSearchUrl(pivot(query, view.events, view.entity), view, 15), 'https://nano.example');
    expect(new URLSearchParams(url.hash.slice(1)).get('q')).toBe(`${prefix} | where (metadata.product.name="iad2-jobs" AND metadata.tenant_uid="ops")`);
    expect(new URLSearchParams(url.hash.slice(1)).get('start')).toBe('2026-10-17T11:45:00.000Z');
    expect(new URLSearchParams(url.hash.slice(1)).get('end')).toBe('2026-10-17T12:21:00.000Z');
  });
  it('retains non-aggregate transforms and OCSF entity filtering', () => {
    expect(pivot('* | eval x=1 | where x=1', [], { raw: 'alice', type: 'user' }))
      .toBe('* | eval x=1 | where x=1 | where (actor.user.name="alice" OR actor.user.uid="alice" OR user.name="alice" OR user.uid="alice")');
  });
  it('uses nested OCSF grouping fields', () => {
    expect(pivot('* | stats count by actor.user.uid', [{ actor: { user: { uid: 'alice' } } }], entity))
      .toBe('(*) ((actor.user.uid="alice"))');
  });
  it('keeps multi-row tuples paired and retains numeric/boolean values', () => {
    expect(pivot('* | stats count by product, code, allowed', [{ product: 'a', code: 0, allowed: false }, { product: 'b', code: 1, allowed: true }], entity))
      .toBe('(*) ((product="a" AND code=0 AND allowed=false) OR (product="b" AND code=1 AND allowed=true))');
  });
  it('does not guess an entity if grouped columns were not captured', () => {
    expect(pivot(query, [{ 'metadata.product.name': 'iad2-jobs' }], entity)).toBe(prefix);
  });
  it.each(['stats', 'eventstats', 'streamstats', 'timechart', 'chart', 'top', 'rare'])('stops before %s', command => {
    expect(pivot(`* | eval x=1 | ${command} count by x | where count>10`, [{ x: 1 }], entity))
      .toBe('* | eval x=1 | where (x=1)');
  });
  it('preserves literal/regex pipes and ignores by inside aggregate functions', () => {
    expect(pivot('name=/a|b/ | eval s="x|y" | stats count(eval(s=" by ")) by product', [{ product: 'x|y' }], entity))
      .toBe('name=/a|b/ | eval s="x|y" | where (product="x|y")');
  });
  it('preserves source OR precedence and safely quotes group values', () => {
    expect(pivot('source=a OR source=b | stats count by product', [{ product: 'a" | stats count' }], entity))
      .toBe('(source=a OR source=b) ((product="a | stats count"))');
  });
  it('keeps the legacy schema heuristic for ungrouped rules', () => {
    expect(pivot('source=a', [], { raw: 'alice', type: 'user' }, false)).toBe('(source=a) (user="alice")');
  });
});
