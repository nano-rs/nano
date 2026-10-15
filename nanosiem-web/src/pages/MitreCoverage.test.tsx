// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3250: the coverage page flows in the app scroller; the matrix keeps a bounded, non-collapsing box. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { MitreCoverageResponse } from '@/components/mitre/types';
import { MitreCoverage } from './MitreCoverage';

const coverage: MitreCoverageResponse = {
  tactics: [
    { tactic_id: 'TA0001', tactic_name: 'Initial Access', short_name: 'initial-access', total_techniques: 1, covered_techniques: 1 },
  ],
  techniques: [
    {
      technique_id: 'T1078', technique_name: 'Valid Accounts', is_subtechnique: false, tactic_ids: ['TA0001'],
      rule_count: 1, coverage_level: 'medium', rules: [{ id: 'r1', name: 'Impossible travel', severity: 'high', mode: 'alerting' }],
    },
  ],
  summary: {
    coverage_unit: 'technique', total_techniques: 1, covered_techniques: 1, coverage_percentage: 100, total_rules_with_mitre: 1,
  },
};

vi.mock('@/hooks/useMitreData', () => ({
  useMitreCoverage: () => ({ data: coverage, loading: false, error: null }),
  useMitreData: () => ({ data: null }),
  useMitreQuarantine: () => ({ mappings: [] }),
}));

afterEach(() => cleanup());

it('flows in the app scroller: no fill-height column; the matrix box is bounded but cannot collapse', () => {
  render(
    <MemoryRouter>
      <MitreCoverage />
    </MemoryRouter>,
  );
  const page = screen.getByTestId('mitre-coverage-page');
  expect(page.className).not.toMatch(/(^|\s)h-full(\s|$)/);
  expect(page.className).not.toMatch(/(^|\s)min-h-0(\s|$)/);

  const matrix = screen.getByTestId('coverage-matrix-scroll');
  // Not a leftover-height flex child...
  expect(matrix.className).not.toMatch(/(^|\s)(min-h-0|flex-1)(\s|$)/);
  // ...but a bounded box (sticky tactic headers) whose bound never drops below 60vh.
  expect(matrix.className).toContain('overflow-auto');
  expect(matrix.className).toContain('max-h-[max(60vh,');
  expect(within(matrix).getAllByText('Valid Accounts').length).toBeGreaterThan(0);
});
