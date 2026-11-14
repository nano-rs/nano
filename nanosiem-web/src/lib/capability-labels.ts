// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Capabilities } from '@/hooks/use-capabilities';

/**
 * NAN-5310: user-facing names for license/build capabilities, so a refusal
 * says WHICH feature is unavailable instead of "this surface".
 */
export const CAPABILITY_LABELS: Record<keyof Capabilities, string> = {
  cases: 'Cases',
  notebooks: 'Notebooks',
  risk: 'Risk-based alerting',
  melod: 'AI assistant (pivt)',
  customEnrichment: 'Custom enrichment',
  agentEnrichment: 'Agent enrichment',
  aiTuning: 'AI rule tuning',
  playbooks: 'Playbooks',
  incidents: 'Incidents',
  siemHealth: 'SIEM health',
  sso: 'Single sign-on',
  observabilityConvergence: 'Security signals for services',
  iocLists: 'IOC lists',
  soar: 'SOAR automation',
  threatIntel: 'Threat intel',
  agentLane: 'Agent Lane',
};
