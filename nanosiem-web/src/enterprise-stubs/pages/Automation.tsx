// SPDX-License-Identifier: AGPL-3.0-or-later

import { EnterprisePagePlaceholder } from '../_placeholder';

// Automation is enterprise-only: every Automation route renders the
// paid-plan placeholder in open builds.
export const AutomationRunsRoute = EnterprisePagePlaceholder;
export const AutomationFlowsRoute = EnterprisePagePlaceholder;
export const AutomationFlowRoute = EnterprisePagePlaceholder;
export const AutomationApprovalsRoute = EnterprisePagePlaceholder;
export const AutomationCapabilitiesRoute = EnterprisePagePlaceholder;
export default AutomationRunsRoute;
