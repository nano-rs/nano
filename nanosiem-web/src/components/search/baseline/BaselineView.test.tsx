// SPDX-License-Identifier: AGPL-3.0-or-later

import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { BaselineView } from './BaselineView';
import { baselineVerdict } from './baseline-verdict';

const row = (fields: Record<string, unknown>, i = 0) => ({
  id: String(i),
  timestamp: new Date('2026-10-07T20:00:00Z'),
  source: 'baseline',
  fields: { entity: 'ws-it-083.corp.local', entity_type: 'host', ...fields },
});

const valueRow = (value: string, extra: Record<string, unknown> = {}, i = 0) =>
  row(
    {
      dimension: 'destination IPs',
      value,
      count: 1,
      first_seen: '2026-10-07T19:30:00Z',
      coverage: 'sufficient',
      baseline_unknown: false,
      incomplete: false,
      ...extra,
    },
    i,
  );

/** Every trust label the panel can render. */
const LABELS = [
  'sufficient history',
  'thin history',
  'no prior history',
  'baseline unknown',
  'baseline incomplete',
];

function labelsIn(markup: string): string[] {
  return LABELS.filter((label) => markup.includes(label));
}

describe('baselineVerdict', () => {
  it('lets a caveat replace the coverage claim, never sit beside it', () => {
    for (const coverage of ['sufficient', 'thin', 'no_history', 'unknown', '']) {
      for (const unknown of [false, true]) {
        for (const incomplete of [false, true]) {
          const verdict = baselineVerdict(coverage, unknown, incomplete);
          // NAN-3277: unread history is never shown as "no history".
          if (coverage === 'unknown') expect(verdict).toBe('incomplete');
          else if (coverage !== 'sufficient' && coverage !== 'thin') expect(verdict).toBe('no_history');
          else if (unknown) expect(verdict).toBe('unknown');
          else if (incomplete) expect(verdict).toBe('incomplete');
          else expect(verdict).toBe(coverage);
        }
      }
    }
  });
});

describe('BaselineView labels', () => {
  const cases: Array<[string, ReturnType<typeof row>[], string]> = [
    ['sufficient, exhaustive', [valueRow('203.0.0.1')], 'sufficient history'],
    ['sufficient + legacy baseline_unknown', [valueRow('203.0.0.1', { baseline_unknown: true })], 'baseline unknown'],
    ['sufficient + window bound hit', [valueRow('203.0.0.1', { incomplete: true })], 'baseline incomplete'],
    [
      'sufficient + incomplete marker row',
      [
        valueRow('203.0.0.1'),
        row({ dimension: null, value: null, count: 0, coverage: 'sufficient', incomplete: true, note: 'x' }, 1),
      ],
      'baseline incomplete',
    ],
    ['thin', [valueRow('203.0.0.1', { coverage: 'thin' })], 'thin history'],
  ];
  for (const [name, results, expected] of cases) {
    it(`shows exactly one verdict: ${name}`, () => {
      const markup = renderToStaticMarkup(<BaselineView results={results} />);
      expect(labelsIn(markup)).toEqual([expected]);
      // The old "comparison cap filled" caveat never renders beside a coverage verdict.
      expect(markup).not.toContain('comparison cap filled');
    });
  }

  it('never pairs the "sufficient" pill with "baseline unknown"', () => {
    const markup = renderToStaticMarkup(
      <BaselineView results={[valueRow('203.0.0.1', { baseline_unknown: true })]} />,
    );
    expect(markup).not.toMatch(/>sufficient</);
    expect(markup).toContain('>baseline unknown<');
  });

  it('never renders unread history as "no history" (NAN-3277)', () => {
    const markup = renderToStaticMarkup(
      <BaselineView
        results={[
          row(
            {
              dimension: null,
              value: null,
              count: 0,
              coverage: 'unknown',
              incomplete: true,
              partial: true,
              note: 'the host activity history could not be read',
            },
            0,
          ),
        ]}
      />,
    );
    // The pill shows the incomplete verdict; no history claim anywhere.
    expect(markup).toContain('>incomplete<');
    expect(markup).not.toContain('no history');
    expect(markup).not.toContain('No history to baseline against');
    expect(markup).toContain('Baseline could not be completed');
  });

  it('keeps the server order of first sightings (newest first)', () => {
    const markup = renderToStaticMarkup(
      <BaselineView
        results={[
          valueRow('9.9.9.9', { first_seen: '2026-10-07T19:50:00Z' }, 0),
          valueRow('10.0.0.1', { first_seen: '2026-10-07T19:10:00Z' }, 1),
        ]}
      />,
    );
    expect(markup.indexOf('9.9.9.9')).toBeLessThan(markup.indexOf('10.0.0.1'));
  });
});
