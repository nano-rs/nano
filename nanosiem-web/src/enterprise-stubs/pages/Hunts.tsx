// SPDX-License-Identifier: AGPL-3.0-or-later

import { EnterprisePagePlaceholder } from '../_placeholder';

// Hunts are enterprise-only: every hunts route renders the paid-plan
// placeholder in open builds, and the rail entry is capability-gated off.
export const HuntsListRoute = EnterprisePagePlaceholder;
export const HuntDetailRoute = EnterprisePagePlaceholder;
export const HuntLeadsRoute = EnterprisePagePlaceholder;
export const HuntLeadDetailRoute = EnterprisePagePlaceholder;
export const HuntRuleIdeasRoute = EnterprisePagePlaceholder;
export const HuntKnowledgeRoute = EnterprisePagePlaceholder;
export const HuntSuppressionsRoute = EnterprisePagePlaceholder;
export const HuntMemoryRoute = EnterprisePagePlaceholder;
export const HuntCampaignsRoute = EnterprisePagePlaceholder;
export const HuntCampaignCandidatesRoute = EnterprisePagePlaceholder;
export const HuntCampaignDetailRoute = EnterprisePagePlaceholder;
export const HuntRulingsRoute = EnterprisePagePlaceholder;
export const HuntEscalationsRoute = EnterprisePagePlaceholder;
export const HuntProfileRoute = EnterprisePagePlaceholder;
export const HuntRunnersRoute = EnterprisePagePlaceholder;
export default HuntsListRoute;
