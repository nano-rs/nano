// SPDX-License-Identifier: AGPL-3.0-or-later
// Open-edition stub: the Enrich flyout is enterprise-only (NAN-4931), so no
// value maps to a lookup type and opening is a no-op. Callers gate the
// affordance on `useEnrichEnabled()`, which is always false here.

import type { ThreatIntelArtifactType } from '@/enterprise/api/threat-intel';

export const ENRICH_ARTIFACT_EVENT = 'nano:enrich-artifact' as const;

export interface EnrichArtifactDetail {
  artifact: string;
  artifactType?: ThreatIntelArtifactType;
  origin?: 'analyst' | 'pivt';
}

export function openEnrich(_detail: EnrichArtifactDetail): void {
  void _detail;
}

export function detectArtifactType(_value: string): ThreatIntelArtifactType | null {
  void _value;
  return null;
}

export function enrichTypeFor(_kind: string | null | undefined, _value: string): ThreatIntelArtifactType | null {
  void _kind;
  void _value;
  return null;
}
