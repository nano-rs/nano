// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { LicensedFeatureUnavailable } from '@/components/LicensedFeatureUnavailable';
import { useCapabilities, type Capabilities } from '@/hooks/use-capabilities';

/** Route guard: the page when the license admits `capability`, else the unavailable panel. */
export function CapabilityRoute({
  capability,
  openWhenLicensePaused = false,
  children,
}: {
  capability: keyof Capabilities;
  /**
   * Render the page even when the license does not admit the capability, in
   * an enterprise build whose verdict is live (not the boot fallback): the
   * license hard stop. For pages that show their own paused state and keep
   * the actions the API still serves then (Agent Lane: status, revoke,
   * switch off). The open edition still gets the unavailable panel.
   */
  openWhenLicensePaused?: boolean;
  children: ReactNode;
}) {
  const { capabilities, edition, fallback } = useCapabilities();
  if (capabilities[capability]) return <>{children}</>;
  if (openWhenLicensePaused && edition === 'enterprise' && !fallback) return <>{children}</>;
  return <LicensedFeatureUnavailable capability={capability} />;
}
