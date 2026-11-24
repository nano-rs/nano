// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub (NAN-5850): hunts are enterprise-only, so MITRE Coverage
// never has a hunt layer. The page then renders the Detections / Gaps views
// and the combined classes degrade to detected / huntable / blind / unmapped.

import type { HuntTechniqueCoverageState } from '@/components/mitre/hunt-layer-types';

export function useHuntTechniqueCoverage(days: number, enabled: boolean): HuntTechniqueCoverageState {
  void days;
  void enabled;
  return { data: null, recon: null, unattributed: null, windowDays: null, isLoading: false, error: null };
}
