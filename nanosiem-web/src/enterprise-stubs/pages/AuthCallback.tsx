// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for the OIDC `/auth/callback/:provider` route. The real
// callback handler lives in `@/enterprise/pages/AuthCallback`. If a user
// hits the callback URL in an open build (e.g. via stale OIDC state), they
// see the standard enterprise placeholder — they're expected to log in via
// local credentials instead.

import { EnterprisePagePlaceholder } from '../_placeholder';

export const AuthCallback = EnterprisePagePlaceholder;
export default AuthCallback;
