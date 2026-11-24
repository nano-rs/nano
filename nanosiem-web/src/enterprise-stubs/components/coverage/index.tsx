// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub (NAN-5850): MITRE Coverage has no hunt layer, recon,
// census or bindings in open core. Same names as the enterprise module; all
// render nothing.

import type { ReactNode } from 'react';
import type { TechniqueCoverage } from '@/components/mitre/types';
import type { HuntReconStatus, HuntTechniqueLayer } from '@/components/mitre/hunt-layer-types';

export function CoverageTelemetryEnterprise(): ReactNode {
  return null;
}

export function ReconMeta(props: { recon: HuntReconStatus | null }): ReactNode {
  void props;
  return null;
}

export function ReconStrip(): ReactNode {
  return null;
}

export function ReconResultProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

export function RunReconButton(props: { testId?: string }): ReactNode {
  void props;
  return null;
}

export function CoverageHuntsSection(props: {
  technique: TechniqueCoverage;
  layer: HuntTechniqueLayer | null;
  days: number;
  onNewHunt?: (() => void) | null;
}): ReactNode {
  void props;
  return null;
}

export function CoverageTechniqueBindings(props: { sourceTypes: string[] }): ReactNode {
  void props;
  return null;
}

export interface CoverageHuntActions {
  draftFromFindings: ((technique: TechniqueCoverage, layer: HuntTechniqueLayer | null, days: number) => void) | null;
  huntFirst: (() => void) | null;
  dialogs: ReactNode;
}

export function useCoverageHuntActions(): CoverageHuntActions {
  return { draftFromFindings: null, huntFirst: null, dialogs: null };
}
