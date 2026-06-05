// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for the Air-gapped Import surface (NAN-1201). The real
// implementation lives in `@/enterprise/airgap/AirgapImportPage`; in
// open-edition Vite builds (`VITE_EDITION=open`) the `@/enterprise/*` alias
// resolves here so the route still mounts but renders the upgrade
// placeholder. Keep both the named and default exports in sync with the real
// page's exports (NAN-1190).

import { EnterprisePagePlaceholder } from '../_placeholder';

export const AirgapImportPage = EnterprisePagePlaceholder;
export default AirgapImportPage;
