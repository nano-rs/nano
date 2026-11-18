// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5592: what pivt knows and may do on the Rules surfaces (the shared
// `usePivtPage` contract, NAN-5571). Context comes from data the pages already
// hold; lifecycle actions call the REST client as the analyst (`pivtApi`,
// audited with `request_origin: pivt`).
//
// Each lifecycle action is ONE server transition (staging → live → alerting,
// or back; pause; resume) sent with `expected_mode`, so the card the analyst
// confirms is exactly the transition the server makes: if the rule moved in
// the meantime the server refuses (409) instead of skipping a step.
//
// Targets are frozen when the card first shows (`bind`), and only rules the
// page is showing can be targeted: pivt never acts on a rule id it read from
// log text or made up.
import { definePivtAction, PivtRefusal, type PivtActionSpec } from '@/contexts/pivt-page';
import { pivtApi } from '@/lib/api/pivt-api';
import type { DetectionRule } from '@/lib/api/types';

type Mode = DetectionRule['mode'];

/** Compact, serialisable view of a rule for the page context. */
export function ruleSummary(r: DetectionRule) {
  return {
    id: r.id,
    name: r.name,
    mode: r.mode,
    severity: r.severity,
    schedule: r.detection_mode ?? null,
    dataset: r.dataset ?? 'logs',
    tactics: r.mitre_tactics?.slice(0, 4) ?? [],
    techniques: r.mitre_techniques?.slice(0, 6) ?? [],
    matches: r.match_count ?? 0,
    last_match_at: r.last_match_at ?? null,
    last_run_at: r.last_run_at ?? null,
  };
}

/** One row of the rule list in the page context: just enough to name and
    target a rule (the page context is capped at 8 KB as a whole). */
export function ruleRow(r: DetectionRule, today: number) {
  return { id: r.id, name: r.name, mode: r.mode, severity: r.severity, matches: r.match_count ?? 0, today };
}

/** Rows of the list sent to pivt. */
export const MAX_CONTEXT_RULES = 20;

export interface RuleTargets {
  /** Rules the page shows now (the only ones an action may target). */
  visible: () => DetectionRule[];
  /** The rule the analyst is focused on (expanded row / single selection). */
  focused?: () => string | null;
  /** Fixed target (the rule editor). */
  fixed?: () => DetectionRule | null;
  /** Refresh the page after a change. */
  onChanged?: () => void;
}

interface Bound {
  rule_id?: string;
  /** The mode the card was bound against (sent as `expected_mode`). */
  from?: Mode;
  rule_name?: string;
}

/** Resolve the one rule an action applies to, now; throws a reason if none. */
export function resolveRule(t: RuleTargets, ruleId?: string): DetectionRule {
  const fixed = t.fixed?.();
  if (fixed) {
    if (ruleId && ruleId !== fixed.id) throw new PivtRefusal('This card targets a different rule than the one open.');
    return fixed;
  }
  const visible = t.visible();
  const id = ruleId || t.focused?.() || null;
  if (!id) throw new PivtRefusal('Open or select the rule first, or name one rule.');
  const rule = visible.find((r) => r.id === id);
  if (!rule) throw new PivtRefusal(`Rule ${id} is not on this page.`);
  return rule;
}

interface Transition {
  name: string;
  verb: string;
  /** Modes it applies from → the mode it lands in (null: the pre-pause mode). */
  from: Partial<Record<Mode, Mode | null>>;
  description: string;
  call: (id: string, expected: Mode) => Promise<DetectionRule>;
  refuse: (rule: DetectionRule) => string;
}

const TRANSITIONS: Transition[] = [
  {
    name: 'rules.promote',
    verb: 'Promote',
    from: { staging: 'live', live: 'alerting' },
    description: 'Promote the rule one step: staging → live (matches counted, no alerts) or live → alerting (generates alerts).',
    call: (id, m) => pivtApi.promoteDetection(id, m),
    refuse: (r) =>
      r.mode === 'paused' ? `Rule ${r.id} is paused; resume it first.` : `Rule ${r.id} is already alerting.`,
  },
  {
    name: 'rules.demote',
    verb: 'Demote',
    from: { alerting: 'live', live: 'staging' },
    description: 'Demote the rule one step: alerting → live (stops alerting) or live → staging (stops running).',
    call: (id, m) => pivtApi.demoteDetection(id, m),
    refuse: (r) =>
      r.mode === 'paused' ? `Rule ${r.id} is paused; resume it first.` : `Rule ${r.id} is already in staging.`,
  },
  {
    name: 'rules.pause',
    verb: 'Pause',
    // The server pauses only running rules (live / alerting).
    from: { live: 'paused', alerting: 'paused' },
    description: 'Pause a live or alerting rule (it stops running until resumed).',
    call: (id, m) => pivtApi.pauseDetection(id, m),
    refuse: (r) =>
      r.mode === 'staging' ? `Rule ${r.id} is in staging and not running.` : `Rule ${r.id} is already paused.`,
  },
  {
    name: 'rules.resume',
    verb: 'Resume',
    from: { paused: null },
    description: 'Resume a paused rule to the mode it had before the pause.',
    call: (id, m) => pivtApi.resumeDetection(id, m),
    refuse: (r) => `Rule ${r.id} is not paused.`,
  },
];

function landing(tr: Transition, from: Mode): string {
  const to = tr.from[from];
  return to === null ? 'its mode before the pause' : (to ?? from);
}

/**
 * Lifecycle actions (promote / demote / pause / resume) for a rules surface.
 *
 * `mode` (the editor, one known rule) limits the actions to those that fit;
 * on the list every action is offered and `bind` refuses one that does not
 * fit the targeted rule.
 */
export function ruleLifecycleActions(t: RuleTargets, opts: { mode?: Mode } = {}): PivtActionSpec[] {
  return TRANSITIONS.filter((tr) => !opts.mode || opts.mode in tr.from).map((tr) =>
    definePivtAction<{ rule_id?: string } & Bound>({
      name: tr.name,
      description: tr.description,
      params: t.fixed
        ? {}
        : {
            rule_id: {
              type: 'string',
              description: 'One rule id shown on this page; omit to use the open or selected rule',
              maxLength: 64,
            },
          },
      permission: 'detections:promote',
      mutates: true,
      bind: (p) => {
        const rule = resolveRule(t, p.rule_id);
        if (!(rule.mode in tr.from)) throw new PivtRefusal(tr.refuse(rule));
        return { rule_id: rule.id, from: rule.mode, rule_name: rule.name };
      },
      preview: (p) => ({
        summary: `${tr.verb} ${p.rule_name ?? 'this rule'}`,
        rows: [
          ['rule', p.rule_id ?? ''],
          ['mode', `${p.from} → ${p.from ? landing(tr, p.from) : '?'}`],
          ...(tr.name === 'rules.promote' && p.from === 'live'
            ? ([['note', 'Alerting rules generate alerts.']] as Array<[string, string]>)
            : []),
        ],
      }),
      run: async (p) => {
        if (!p.rule_id || !p.from) throw new Error('No rule is bound to this card.');
        // Still on the page (the editor for it is open / it is still listed):
        // the confirmed rule, never a later focus.
        if (resolveRule(t, p.rule_id).id !== p.rule_id) throw new Error('That rule is not open here any more.');
        const updated = await tr.call(p.rule_id, p.from);
        t.onChanged?.();
        return { summary: `${p.rule_name ?? p.rule_id}: ${p.from} → ${updated.mode}`, href: `/rules/editor/${p.rule_id}` };
      },
    }),
  );
}

/**
 * Editor only: propose a new detection query. Apply writes it into the editor
 * buffer, UNSAVED; the analyst reviews and saves (rule version + audit), the
 * same as a hand edit or an `@tune` suggestion.
 */
export function editQueryAction(opts: {
  ruleId: () => string | null;
  currentQuery: () => string;
  apply: (query: string) => void;
}): PivtActionSpec {
  return definePivtAction<{ query: string; rule_id?: string | null; before?: string }>({
    name: 'rules.edit_query',
    description:
      "Rewrite this rule's nPL detection query. It goes into the editor unsaved; the analyst reviews it and saves.",
    params: { query: { type: 'string', description: 'The full new nPL query', required: true, maxLength: 8000 } },
    permission: 'detections:edit',
    mutates: true,
    bind: (p) => {
      const query = p.query.trim();
      if (!query) throw new PivtRefusal('The proposed query is empty.');
      return { query, rule_id: opts.ruleId(), before: opts.currentQuery() };
    },
    preview: (p) => ({
      summary: 'Put this query in the editor (unsaved)',
      diff: { before: p.before ?? '', after: p.query, lang: 'npl' },
    }),
    run: async (p) => {
      if (opts.ruleId() !== (p.rule_id ?? null)) throw new Error('A different rule is open now.');
      // The analyst confirmed `before → after`; if they have typed since, that
      // diff no longer describes what Apply would do.
      if (opts.currentQuery() !== (p.before ?? '')) {
        throw new Error('The query changed since this card was shown; ask pivt again.');
      }
      opts.apply(p.query);
      return { summary: 'In the editor, unsaved. Review it and Save.' };
    },
  });
}
