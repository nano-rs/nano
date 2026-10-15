// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

test('shared UI renders interactive responses through the common path and adopts escalated artifacts', () => {
  const source = readFileSync(new URL('../pages/Search.tsx', import.meta.url), 'utf8');
  const branch = source.split('// Shared Search tries interactive admission;')[1]?.split("} else if (currentMode === 'sql')")[0];
  assert(branch);
  assert.match(branch, /startInteractiveSearch\(api/);
  assert.match(branch, /request_id: requestId/);
  assert.match(branch, /currentRequestIdRef.current !== requestId/);
  assert.match(branch, /if \(admitted.pager\)/);
  assert.match(branch, /processAsyncJobResult/);
  assert.match(branch, /response = admitted.response/);
  assert.doesNotMatch(branch, /searchAsync|startStreamingSearch/);
  // Both direct paths fall through to the same rendering and field-stat code.
  assert.match(source, /setSearchResults\(results\)/);
  assert.match(source, /fetchFieldStats\(\{ \.\.\.fsRequest/);
});

test('Search page branches on the capability snapshot, never on the deployment mode (NAN-2361 wave 8)', () => {
  const source = readFileSync(new URL('../pages/Search.tsx', import.meta.url), 'utf8');
  // The hosted deployment-mode wire value, as the server reports it.
  assert.doesNotMatch(source, new RegExp(['deploymentMode', 'enterprise_shared', 'sharedTenantSearch', 'useSharedTenant'].join('|')));
  // Every profile-dependent affordance is named by the surface (see
  // SearchSurface docs); the page never decides from the deployment mode.
  for (const flag of ['rawSql', 'storedShortLinks', 'explanationCache', 'browserResultCache', 'durableExecution', 'datasets']) {
    assert.match(source, new RegExp(`searchSurface\\.${flag}`), `Search.tsx must consult searchSurface.${flag}`);
  }
  // Features with tenant-scoped routes are ungated: saved searches, history,
  // AI (capability-gated), dashboards, reports, rules, enrichment controls.
  assert.match(source, /useSavedSearches\(\)/);
  assert.match(source, /useSearchHistory\(\)/);
  assert.match(source, /useMelodStatus\(\{ skip: !capabilities\.melod \}\)/);
  assert.doesNotMatch(source, /allowEnrichmentControls/);
  // The Save/Share separator renders only when a chip follows it.
  assert.match(source, /\{\(canSave \|\| canShare\) && \(\s*<span aria-hidden/);
  // Query correction is gated on the capability alone (which folds in the
  // platform provider state on shared) and is never repeated for one failure.
  assert.match(source, /if \(!capabilities\.queryCorrection\) return;/);
  // Stored short links (NAN-2361 wave 8): the menu item renders only where the
  // surface serves POST /api/search/share, and the callback guards it too.
  assert.match(source, /\{searchSurface\.storedShortLinks && \(\s*<DropdownMenuItem/);
  assert.match(source, /if \(!searchSurface\.storedShortLinks\) return;/);
  assert.match(source, /correctionInFlightRef\.current === correctionKey\) return;/);
});
