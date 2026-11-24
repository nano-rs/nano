// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5850: the unified coverage cell model against PR B's fixture. Every
 * technique in the fixture header table lands on its expected class, the
 * open-core null layer degrades as designed, and the URL state round-trips.
 */
import { describe, expect, it } from 'vitest';
import { fixtureHuntLayerMap, unifiedCoverageFixture } from './__fixtures__/unified-coverage';
import {
  type CoverageClass,
  combinedClass,
  compareGapRows,
  detectionState,
  effectiveView,
  gapKinds,
  huntState,
  inGapQueue,
  isDimmed,
  matchesUnifiedFilters,
  parseCoverageParams,
  ruleWithoutTelemetry,
  techniqueLayers,
  telemetryState,
  viewFellBack,
  writeCoverageParams,
} from './layers';

const NOW = Date.parse('2026-11-22T21:40:00Z');
const { coverage, hunts, hunts7d } = unifiedCoverageFixture;
const layers30 = fixtureHuntLayerMap(hunts);
const layers7 = fixtureHuntLayerMap(hunts7d);
const byId = new Map(coverage.techniques.map((t) => [t.technique_id, t]));
const tech = (id: string) => {
  const t = byId.get(id);
  if (!t) throw new Error(`fixture has no ${id}`);
  return t;
};

const EXPECTED_30D: Record<string, CoverageClass> = {
  T1059: 'detected',
  'T1059.001': 'both',
  'T1059.003': 'huntable',
  T1053: 'huntable',
  'T1053.005': 'detected',
  T1136: 'unmapped',
  'T1136.001': 'huntable',
  T1027: 'blind',
  T1003: 'blind',
  'T1003.001': 'blind',
  T1021: 'hunted',
  'T1021.002': 'hunted',
  T1685: 'both',
  T1071: 'detected',
  'T1071.001': 'unmapped',
  T1105: 'hunted',
};

describe('combinedClass (Both view, fixture header table)', () => {
  it.each(Object.entries(EXPECTED_30D))('%s is %s at 30d', (id, cls) => {
    expect(combinedClass(tech(id), layers30.get(id) ?? null, 30, NOW)).toBe(cls);
  });

  it('T1105 is hunted at 30d and blind at 7d (last sweep 9 days ago)', () => {
    expect(combinedClass(tech('T1105'), layers7.get('T1105') ?? null, 7, NOW)).toBe('blind');
    expect(huntState(layers7.get('T1105'), 7, NOW)).not.toBe('hunted');
  });

  it('covers every fixture technique', () => {
    expect(new Set(coverage.techniques.map((t) => t.technique_id))).toEqual(new Set(Object.keys(EXPECTED_30D)));
  });
});

describe('layer states', () => {
  it('reads D from live rules only; staging is review, paused is off', () => {
    expect(detectionState(tech('T1059.001'))).toBe('full');
    expect(detectionState(tech('T1059'))).toBe('partial');
    expect(detectionState(tech('T1059.003'))).toBe('review');
    expect(detectionState(tech('T1003'))).toBe('off');
    expect(detectionState(tech('T1027'))).toBe('none');
  });

  it('reads T from live readiness', () => {
    expect(telemetryState(tech('T1059.001'))).toBe('active');
    expect(telemetryState(tech('T1027'))).toBe('stale');
    expect(telemetryState(tech('T1003'))).toBe('missing');
    expect(telemetryState(tech('T1136'))).toBe('unmapped');
  });

  it('reads H: hunted, scheduled, drafted, none', () => {
    expect(huntState(layers30.get('T1059.001'), 30, NOW)).toBe('hunted');
    expect(huntState(layers30.get('T1053.005'), 30, NOW)).toBe('scheduled');
    expect(huntState(layers30.get('T1053'), 30, NOW)).toBe('drafted');
    expect(huntState(null, 30, NOW)).toBe('none');
  });

  it('flags rule, no telemetry only for a live rule on stale or missing telemetry', () => {
    expect(ruleWithoutTelemetry(tech('T1053.005'))).toBe(true);
    // Unmapped telemetry is not a silent failure we can prove.
    expect(ruleWithoutTelemetry(tech('T1071'))).toBe(false);
    expect(ruleWithoutTelemetry(tech('T1059.001'))).toBe(false);
  });

  it('a parent never inherits a hunted child', () => {
    expect(huntState(layers30.get('T1059') ?? null, 30, NOW)).toBe('none');
    expect(combinedClass(tech('T1059'), layers30.get('T1059') ?? null, 30, NOW)).toBe('detected');
  });
});

describe('open core (null hunt layer)', () => {
  it('degrades to detected / huntable / blind / unmapped and never hunted or both', () => {
    const classes = coverage.techniques.map((t) => combinedClass(t, null, 30, NOW));
    expect(classes).not.toContain('both');
    expect(classes).not.toContain('hunted');
    expect(combinedClass(tech('T1059.001'), null, 30, NOW)).toBe('detected');
    expect(combinedClass(tech('T1021.002'), null, 30, NOW)).toBe('huntable');
    expect(combinedClass(tech('T1105'), null, 30, NOW)).toBe('blind');
  });

  it('falls back from hunts / both to detections', () => {
    expect(effectiveView('hunts', false)).toBe('detections');
    expect(effectiveView('both', false)).toBe('detections');
    expect(effectiveView(null, false)).toBe('detections');
    expect(effectiveView(null, true)).toBe('both');
    expect(effectiveView('gaps', false)).toBe('gaps');
    expect(viewFellBack('hunts', false)).toBe(true);
    expect(viewFellBack('hunts', true)).toBe(false);
  });
});

describe('gaps', () => {
  it('classifies gap kinds', () => {
    expect(gapKinds(tech('T1021.002'), layers30.get('T1021.002'), 30, NOW)).toEqual(['huntable_no_rule']);
    expect(gapKinds(tech('T1053.005'), layers30.get('T1053.005'), 30, NOW)).toEqual(['rule_no_telemetry']);
    expect(gapKinds(tech('T1027'), null, 30, NOW)).toEqual(['no_coverage']);
    expect(gapKinds(tech('T1059.001'), layers30.get('T1059.001'), 30, NOW)).toEqual([]);
  });

  it('dims non-gaps in the Gaps view and narrows by chip', () => {
    const covered = techniqueLayers(tech('T1059.001'), layers30.get('T1059.001'), 30, NOW);
    const huntable = techniqueLayers(tech('T1053'), layers30.get('T1053'), 30, NOW);
    expect(isDimmed('gaps', new Set(), covered)).toBe(true);
    expect(isDimmed('gaps', new Set(), huntable)).toBe(false);
    expect(isDimmed('gaps', new Set(['rule_no_telemetry']), huntable)).toBe(true);
    expect(isDimmed('both', new Set(), covered)).toBe(false);
    expect(inGapQueue(new Set(['huntable_no_rule']), huntable)).toBe(true);
  });

  it('sorts huntable techniques with findings first', () => {
    const rows = coverage.techniques
      .map((technique) => ({ technique, facts: techniqueLayers(technique, layers30.get(technique.technique_id), 30, NOW) }))
      .filter((r) => r.facts.gaps.length > 0)
      .sort(compareGapRows);
    const first = rows[0];
    expect(first.facts.gaps).toContain('huntable_no_rule');
    expect(first.facts.findings).toBeGreaterThan(0);
  });
});

describe('filters', () => {
  const base = parseCoverageParams(new URLSearchParams());
  const ctx = (id: string) => {
    const facts = techniqueLayers(tech(id), layers30.get(id), 30, NOW);
    return { layer: facts.layer, facts };
  };

  it('mode keeps techniques with a rule in a selected mode', () => {
    const s = { ...base, modes: new Set(['staging']) };
    expect(matchesUnifiedFilters(tech('T1059.003'), s, ctx('T1059.003'))).toBe(true);
    expect(matchesUnifiedFilters(tech('T1059.001'), s, ctx('T1059.001'))).toBe(false);
  });

  it('source matches a rule source OR a mapped telemetry source type', () => {
    const s = { ...base, sources: new Set(['okta']) };
    // No rule queries okta, but its telemetry maps there.
    const matched = coverage.techniques.filter((t) => matchesUnifiedFilters(t, s, ctx(t.technique_id)));
    expect(matched.length).toBeGreaterThan(0);
    expect(matched.every((t) => !(t.rules || []).some((r) => r.source === 'okta'))).toBe(true);
  });

  it('tactic, class and q narrow; q searches hunt titles', () => {
    expect(matchesUnifiedFilters(tech('T1021'), { ...base, tactic: 'TA0008' }, ctx('T1021'))).toBe(true);
    expect(matchesUnifiedFilters(tech('T1059'), { ...base, tactic: 'TA0008' }, ctx('T1059'))).toBe(false);
    expect(matchesUnifiedFilters(tech('T1027'), { ...base, classes: new Set(['blind']) }, ctx('T1027'))).toBe(true);
    const huntTitle = layers30.get('T1059.001')!.hunts[0].title;
    expect(matchesUnifiedFilters(tech('T1059.001'), { ...base, q: huntTitle.toUpperCase() }, ctx('T1059.001'))).toBe(true);
  });
});

describe('URL state', () => {
  it('round-trips every param and omits defaults', () => {
    const raw = 'view=gaps&mode=staging,live&source=okta&tactic=ta0008&hunted=7&gap=huntable_no_rule&class=blind&q=powershell&tech=t1059.001&tab=gaps';
    const state = parseCoverageParams(new URLSearchParams(raw));
    expect(state.view).toBe('gaps');
    expect([...state.modes].sort()).toEqual(['live', 'staging']);
    expect(state.tactic).toBe('TA0008');
    expect(state.tech).toBe('T1059.001');
    expect(state.hunted).toBe(7);
    const again = parseCoverageParams(writeCoverageParams(state));
    expect(again).toEqual(state);
    expect(writeCoverageParams(parseCoverageParams(new URLSearchParams())).toString()).toBe('');
  });

  it('drops invalid values and keeps foreign params', () => {
    const state = parseCoverageParams(new URLSearchParams('view=nope&hunted=45&gap=bogus&mode=archived&tab=x'));
    expect(state.view).toBeNull();
    expect(state.hunted).toBe(30);
    expect(state.gaps.size).toBe(0);
    expect(state.modes.size).toBe(0);
    expect(state.tab).toBe('matrix');
    expect(writeCoverageParams(state, new URLSearchParams('other=1')).get('other')).toBe('1');
  });
});
