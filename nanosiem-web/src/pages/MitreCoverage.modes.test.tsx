// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5717: the coverage page asks for EVERY rule mode, so staging ("In
 * review") and paused ("Disabled") rules reach it, and it shows how many are
 * in review. Coverage tiers still count live rules only.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { CoverageFilters, MitreCoverageResponse, TechniqueCoverage } from '@/components/mitre/types';

const coverageCalls: CoverageFilters[] = [];

function technique(id: string, rules: TechniqueCoverage['rules']): TechniqueCoverage {
  return {
    technique_id: id,
    technique_name: `Technique ${id}`,
    is_subtechnique: false,
    tactic_ids: ['TA0006'],
    rule_count: rules.length,
    coverage_level: rules.length ? 'low' : 'none',
    rules,
    data_sources: [],
  };
}

const response = {
  tactics: [{ tactic_id: 'TA0006', tactic_name: 'Credential Access', short_name: 'credential-access', total_techniques: 2, covered_techniques: 1 }],
  techniques: [
    technique('T1201', [
      { id: 'rule_review', name: 'staging_rule', severity: 'low', mode: 'staging' },
      { id: 'rule_off', name: 'paused_rule', severity: 'low', mode: 'paused' },
    ]),
    technique('T1110', [{ id: 'rule_live', name: 'live_rule', severity: 'high', mode: 'alerting' }]),
  ],
  summary: { coverage_unit: 'technique', total_techniques: 2, covered_techniques: 1 },
} as unknown as MitreCoverageResponse;

vi.mock('@/hooks/useMitreData', () => ({
  useMitreCoverage: (filters: CoverageFilters) => {
    coverageCalls.push(filters);
    return { data: response, loading: false, error: null };
  },
  useMitreData: () => ({ data: null, loading: false, error: null }),
  useMitreQuarantine: () => ({ mappings: [], unrepairedCount: 0, loading: false, error: null }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => undefined }));

import { MitreCoverage } from './MitreCoverage';
import { countRulesByStatus } from '@/components/mitre/types';

afterEach(cleanup);

describe('MITRE coverage modes (NAN-5717)', () => {
  it('requests staging and paused rules, not only the API default (alerting, live)', () => {
    render(
      <MemoryRouter>
        <MitreCoverage />
      </MemoryRouter>,
    );
    expect(coverageCalls.length).toBeGreaterThan(0);
    const modes = coverageCalls[coverageCalls.length - 1].mode;
    expect([...modes].sort()).toEqual(['alerting', 'live', 'paused', 'staging']);
  });

  it('shows the in-review and disabled rule counts, and covers on live rules only', () => {
    render(
      <MemoryRouter>
        <MitreCoverage />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('mitre-review-count').textContent).toBe('1 in review');
    expect(screen.getByTestId('mitre-disabled-count').textContent).toBe('1 disabled');
    // T1201 has only a review + a disabled rule: still a gap, not covered.
    expect(screen.getByText(/1 technique uncovered/)).toBeTruthy();
  });

  it('counts each rule once even when it maps to several techniques', () => {
    const shared = { id: 'rule_s', name: 's', severity: 'low', mode: 'staging' };
    expect(countRulesByStatus([technique('T1', [shared]), technique('T2', [shared])])).toEqual({
      live: 0,
      review: 1,
      disabled: 0,
    });
  });
});
