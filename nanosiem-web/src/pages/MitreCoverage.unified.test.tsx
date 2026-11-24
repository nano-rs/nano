// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5850: the unified MITRE coverage page. Views, filters and the panel all
 * live in the URL; the hunt layer is on only with the hunts capability AND
 * hunts:view; open core falls back to the Detections view.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fixtureHuntLayerMap, unifiedCoverageFixture } from '@/components/mitre/__fixtures__/unified-coverage';

const mocks = vi.hoisted(() => ({
  hunts: true,
  permissions: new Set<string>(),
  pivt: vi.fn(),
}));

vi.mock('@/hooks/useMitreData', () => ({
  useMitreCoverage: () => ({ data: unifiedCoverageFixture.coverage, loading: false, error: null }),
  useMitreData: () => ({ data: null, loading: false, error: null }),
  useMitreQuarantine: () => ({ mappings: [], unrepairedCount: 0, loading: false, error: null }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => undefined }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p: string) => mocks.permissions.has(p) }) }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: { hunts: mocks.hunts, melod: false } }) }));
vi.mock('@/enterprise/hooks/use-hunt-technique-coverage', () => ({
  useHuntTechniqueCoverage: (days: number, enabled: boolean) => {
    const body = days === 7 ? unifiedCoverageFixture.hunts7d : unifiedCoverageFixture.hunts;
    return {
      data: enabled ? fixtureHuntLayerMap(body) : null,
      recon: enabled ? body.recon : null,
      unattributed: null,
      windowDays: enabled ? days : null,
      isLoading: false,
      error: null,
    };
  },
}));
// The enterprise coverage pieces are covered by their own tests; render the
// open stubs here so the page test stays on the AGPL surface.
vi.mock('@/enterprise/components/coverage', async () => import('@/enterprise-stubs/components/coverage/index'));
vi.mock('@/enterprise/components/pivt/commands/router', () => ({ openPivtPanel: mocks.pivt }));

import { MitreCoverage } from './MitreCoverage';

let location = '';
function LocationSpy() {
  const loc = useLocation();
  location = `${loc.pathname}${loc.search}`;
  return null;
}

function renderAt(url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/rules/coverage" element={<MitreCoverage />} />
          <Route path="*" element={<div data-testid="elsewhere" />} />
        </Routes>
        <LocationSpy />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const params = () => new URLSearchParams(location.split('?')[1] ?? '');
const cell = (id: string) => screen.getAllByTestId(`coverage-cell-${id}`)[0];

beforeEach(() => {
  mocks.hunts = true;
  mocks.permissions = new Set(['detections:view', 'detections:create', 'hunts:view', 'log_sources:view', 'log_sources:create']);
  mocks.pivt.mockReset();
});
afterEach(cleanup);

describe('enterprise with hunts:view', () => {
  it('defaults to the Both view with combined classes and D/H/T data attributes', () => {
    renderAt('/rules/coverage');
    expect(screen.getByTestId('coverage-view-both').getAttribute('aria-checked')).toBe('true');
    expect(cell('T1059.001').getAttribute('data-class')).toBe('both');
    expect(cell('T1059.001').getAttribute('data-h')).toBe('hunted');
    expect(cell('T1053.005').getAttribute('data-warn')).toBe('rule_no_telemetry');
    expect(screen.getByTestId('coverage-legend-both')).toBeTruthy();
    expect(screen.getByTestId('coverage-filter-hunted')).toBeTruthy();
  });

  it('writes the view to the URL and shows gap chips in the Gaps view', () => {
    renderAt('/rules/coverage');
    fireEvent.click(screen.getByTestId('coverage-view-gaps'));
    expect(params().get('view')).toBe('gaps');
    fireEvent.click(screen.getByTestId('coverage-gap-chip-huntable_no_rule'));
    expect(params().get('gap')).toBe('huntable_no_rule');
    fireEvent.click(screen.getByTestId('coverage-view-hunts'));
    expect(params().get('view')).toBe('hunts');
    expect(screen.queryByTestId('coverage-gap-chip-huntable_no_rule')).toBeNull();
  });

  it('the hunted window changes the H layer (T1105 back-dated sweep)', () => {
    renderAt('/rules/coverage?hunted=90');
    expect(cell('T1105').getAttribute('data-h')).toBe('hunted');
    cleanup();
    renderAt('/rules/coverage?hunted=7');
    expect(cell('T1105').getAttribute('data-class')).toBe('blind');
    fireEvent.change(screen.getByTestId('coverage-filter-hunted'), { target: { value: '30' } });
    expect(params().get('hunted')).toBeNull();
    expect(cell('T1105').getAttribute('data-class')).toBe('hunted');
  });

  it('mode, tactic and legend filters narrow and land in the URL', () => {
    renderAt('/rules/coverage');
    fireEvent.click(screen.getByTestId('coverage-filter-mode-staging'));
    expect(params().get('mode')).toBe('staging');
    expect(screen.queryAllByTestId('coverage-cell-T1027')).toHaveLength(0);
    cleanup();
    renderAt('/rules/coverage?tactic=TA0008');
    expect(screen.getByTestId('coverage-column-TA0008')).toBeTruthy();
    expect(screen.queryByTestId('coverage-column-TA0002')).toBeNull();
    fireEvent.click(screen.getByTestId('coverage-legend-hunted'));
    expect(params().get('class')).toBe('hunted');
  });

  it('opens the panel from ?tech= with Review rule idea for a ready idea', () => {
    renderAt('/rules/coverage?tech=T1021.002');
    const panel = screen.getByTestId('coverage-panel');
    expect(panel.getAttribute('data-technique')).toBe('T1021.002');
    fireEvent.click(within(panel).getByTestId('coverage-panel-action-review_idea'));
    expect(location).toBe('/rules/ideas?technique=T1021.002');
  });

  it('Gaps tab lists hunted-no-rule techniques first, and Draft rule prefills the editor', () => {
    renderAt('/rules/coverage?tab=gaps&gap=huntable_no_rule');
    expect(screen.getByTestId('coverage-gap-row-T1021.002')).toBeTruthy();
    expect(screen.queryByTestId('coverage-gap-row-T1059.001')).toBeNull();
    fireEvent.click(screen.getByTestId('coverage-gap-row-T1053'));
    expect(params().get('tech')).toBe('T1053');
    fireEvent.click(within(screen.getByTestId('coverage-panel')).getByTestId('coverage-panel-action-draft_rule'));
    expect(location).toMatch(/^\/rules\/editor\/new\?mitre=T1053&mitre_tactics=/);
  });

  it('Telemetry tab ranks the onboarding backlog', () => {
    renderAt('/rules/coverage?tab=telemetry');
    expect(screen.getByTestId('coverage-telemetry-components')).toBeTruthy();
    expect(screen.getByTestId('coverage-telemetry-backlog')).toBeTruthy();
    expect(screen.queryByTestId('coverage-legend')).toBeNull();
  });
});

describe('action gates, recon and keyboard access (review fixes)', () => {
  it('hides Draft rule and Onboard without detections:create / log_sources:create', () => {
    mocks.permissions = new Set(['detections:view', 'hunts:view']);
    renderAt('/rules/coverage?tech=T1027');
    const panel = screen.getByTestId('coverage-panel');
    expect(within(panel).queryByTestId('coverage-panel-action-draft_rule')).toBeNull();
    expect(within(panel).queryByTestId('coverage-panel-action-onboard_source')).toBeNull();
    cleanup();
    mocks.permissions = new Set(['detections:view', 'hunts:view', 'log_sources:create']);
    renderAt('/rules/coverage?tech=T1027');
    expect(within(screen.getByTestId('coverage-panel')).getByTestId('coverage-panel-action-onboard_source')).toBeTruthy();
  });

  it('hides Open log sources without log_sources:view', () => {
    mocks.permissions = new Set(['detections:view', 'hunts:view']);
    renderAt('/rules/coverage?tech=T1053.005');
    expect(screen.queryByTestId('coverage-panel-action-open_log_sources')).toBeNull();
  });

  it('marks recon regressions on the cell and in the panel from the coverage response', () => {
    const regressed = unifiedCoverageFixture.hunts.recon?.regressed_to_blind ?? [];
    expect(regressed.length).toBeGreaterThan(0);
    renderAt(`/rules/coverage?tech=${regressed[0]}`);
    expect(cell(regressed[0]).getAttribute('data-regressed')).toBe('true');
    expect(screen.getByTestId('coverage-panel-regressed')).toBeTruthy();
  });

  it('opens a gap from the keyboard-reachable row button, and the chevron is a sibling button', () => {
    renderAt('/rules/coverage?tab=gaps');
    const open = screen.getByTestId('coverage-gap-open-T1027');
    expect(open.tagName).toBe('BUTTON');
    fireEvent.click(open);
    expect(params().get('tech')).toBe('T1027');
    cleanup();
    renderAt('/rules/coverage');
    const toggle = screen.getAllByRole('button', { name: /sub-techniques of T1059$/ })[0];
    expect(toggle.closest('[data-testid^="coverage-cell-"]')).toBeNull();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
  });

  it('debounces search into the URL', async () => {
    vi.useFakeTimers();
    try {
      renderAt('/rules/coverage');
      fireEvent.change(screen.getByTestId('coverage-filter-q'), { target: { value: 'lsass' } });
      expect(params().get('q')).toBeNull();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(250);
      });
      expect(params().get('q')).toBe('lsass');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('without the hunt layer', () => {
  it('a role with detections:view but no hunts:view sees no Hunts/Both and ?view=hunts falls back', () => {
    mocks.permissions = new Set(['detections:view']);
    renderAt('/rules/coverage?view=hunts');
    expect(screen.queryByTestId('coverage-view-hunts')).toBeNull();
    expect(screen.queryByTestId('coverage-view-both')).toBeNull();
    expect(screen.getByTestId('coverage-view-detections').getAttribute('aria-checked')).toBe('true');
    expect(screen.getByTestId('coverage-view-fallback').textContent).toContain('Hunt coverage needs Hunts access');
    expect(screen.queryByTestId('coverage-filter-hunted')).toBeNull();
  });

  it('open core degrades classes and labels hot gaps "telemetry, no rule"', () => {
    mocks.hunts = false;
    renderAt('/rules/coverage');
    expect(screen.getByTestId('coverage-view-detections').getAttribute('aria-checked')).toBe('true');
    expect(cell('T1059.001').getAttribute('data-class')).toBe('detected');
    expect(cell('T1021.002').getAttribute('data-class')).toBe('huntable');
    expect(cell('T1021.002').getAttribute('data-h')).toBe('none');
    expect(screen.queryByTestId('coverage-legend-both')).toBeNull();
    expect(screen.getByTestId('coverage-legend-huntable').textContent).toContain('Telemetry, no rule');
  });
});
