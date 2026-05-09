// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for the SSO/OIDC providers page. The real implementation
// lives in `@/enterprise/pages/Settings/OidcProviders` and ships only with
// `VITE_EDITION=enterprise`. Open builds render the placeholder for both the
// page-level export and the embedded `OidcProvidersContent` (used by the
// access-control surface) so any stale route or tab still resolves cleanly.

import { EnterprisePagePlaceholder } from '../../_placeholder';

export const OidcProvidersPage = EnterprisePagePlaceholder;
export const OidcProvidersContent = EnterprisePagePlaceholder;
export default OidcProvidersPage;
