// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-4946 (main NAN-3762): unmeasured coverage renders "not measured yet", never 0 %.
import { afterEach, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import type { ArtifactCoverage, MarketplaceCoverage } from '@/lib/api/marketplace';
import { CoverageHero } from './CoverageHero';

afterEach(cleanup);

const row = (id: string, pct: number, extra: Partial<ArtifactCoverage> = {}): ArtifactCoverage => ({
  id, label: id.toUpperCase(), pct, state: pct >= 75 ? 'good' : pct >= 30 ? 'partial' : 'gap', have: [], missing: [], ...extra,
});
const mount = (coverage: MarketplaceCoverage) => render(<CoverageHero coverage={coverage} onAddMissing={() => {}} />);

it('telemetry unavailable renders not measured yet instead of 0%', () => {
  const view = mount({
    computed_at: '2026-10-13T12:00:00Z', telemetry_available: false,
    artifacts: [row('ip', 0, { measured: false, have: ['IPinfo Lite'] }), row('asn', 0, { measured: false, have: ['IPinfo Lite'] })],
  });
  const text = view.container.textContent!;
  expect(text).toMatch(/Coverage not measured yet\./);
  expect(view.getAllByText('not measured yet')).toHaveLength(2);
  expect(text).not.toMatch(/\b0%/);
  expect(text).toMatch(/1 active providers/);
});

it('partially measured: headline averages measured rows only', () => {
  const view = mount({
    computed_at: '2026-10-13T12:00:00Z', telemetry_available: true,
    artifacts: [row('ip', 80, { measured: true }), row('asn', 60, { measured: true }), row('hash', 0, { measured: false })],
  });
  const text = view.container.textContent!;
  expect(text).toMatch(/70%/);
  expect(text).toMatch(/1 not measured yet/);
  expect(view.getAllByText('not measured yet')).toHaveLength(1);
});

it('rows without a measured flag render as measured', () => {
  const view = mount({ computed_at: '2026-10-13T12:00:00Z', artifacts: [row('ip', 0), row('asn', 50)] });
  expect(view.container.textContent).toMatch(/25%/);
  expect(view.queryAllByText('not measured yet')).toHaveLength(0);
});
