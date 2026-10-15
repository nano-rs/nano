// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-3762: unmeasured coverage renders "not measured yet", never 0 %.
import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import '../../test/marketplace-dom';
import type { ArtifactCoverage, MarketplaceCoverage } from '../../lib/api/marketplace';
const { cleanup, render } = await import('@testing-library/react');
const { CoverageHero } = await import('./CoverageHero');

afterEach(cleanup);

const row = (id: string, pct: number, extra: Partial<ArtifactCoverage> = {}): ArtifactCoverage => ({
  id, label: id.toUpperCase(), pct, state: pct >= 75 ? 'good' : pct >= 30 ? 'partial' : 'gap', have: [], missing: [], ...extra,
});

function mount(coverage: MarketplaceCoverage) {
  return render(<CoverageHero coverage={coverage} onAddMissing={() => {}} />);
}

test('telemetry unavailable renders not measured yet instead of 0%', () => {
  const view = mount({
    computed_at: '2026-10-13T12:00:00Z',
    telemetry_available: false,
    artifacts: [row('ip', 0, { measured: false, have: ['IPinfo Lite'] }), row('asn', 0, { measured: false, have: ['IPinfo Lite'] })],
  });
  const text = view.container.textContent!;
  assert.match(text, /Coverage not measured yet\./);
  assert.equal(view.getAllByText('not measured yet').length, 2);
  assert.doesNotMatch(text, /\b0%/);
  assert.doesNotMatch(text, /types are thin/);
  // One provider recommended for two types is one active provider.
  assert.match(text, /1 active providers/);
});

test('partially measured: headline averages measured rows only', () => {
  const view = mount({
    computed_at: '2026-10-13T12:00:00Z',
    telemetry_available: true,
    artifacts: [row('ip', 80, { measured: true }), row('asn', 60, { measured: true }), row('hash', 0, { measured: false })],
  });
  const text = view.container.textContent!;
  assert.match(text, /70%/);
  assert.match(text, /1 not measured yet/);
  assert.equal(view.getAllByText('not measured yet').length, 1);
  assert.match(text, /1 type is thin/);
});

test('open-core rows without a measured flag render as measured', () => {
  const view = mount({ computed_at: '2026-10-13T12:00:00Z', artifacts: [row('ip', 0), row('asn', 50)] });
  const text = view.container.textContent!;
  assert.match(text, /25%/);
  assert.equal(view.queryAllByText('not measured yet').length, 0);
});
