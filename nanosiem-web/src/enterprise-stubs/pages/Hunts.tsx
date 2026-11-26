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
export const HuntActorsRoute = EnterprisePagePlaceholder;
export const HuntActorReviewRoute = EnterprisePagePlaceholder;
export const HuntActorDetailRoute = EnterprisePagePlaceholder;
export const HuntDecisionsRoute = EnterprisePagePlaceholder;
export const HuntEscalationsRoute = EnterprisePagePlaceholder;
export const HuntProfileRoute = EnterprisePagePlaceholder;
export const HuntSettingsRunnersRoute = EnterprisePagePlaceholder;
export const HuntSettingsCharterRoute = EnterprisePagePlaceholder;
export const HuntSettingsActorsRoute = EnterprisePagePlaceholder;
export default HuntsListRoute;
