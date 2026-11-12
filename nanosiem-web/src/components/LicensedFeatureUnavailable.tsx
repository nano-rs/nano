// SPDX-License-Identifier: AGPL-3.0-or-later

import { Link } from 'react-router-dom';
import { useCapabilities, type Capabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';
import { CAPABILITY_LABELS } from '@/lib/capability-labels';

/**
 * NAN-5310: name the refused feature, and send only roles that can manage the
 * license to Settings > License; everyone else is told to ask an admin.
 */
export function LicensedFeatureUnavailable({ capability }: { capability: keyof Capabilities }) {
  const { edition } = useCapabilities();
  const { hasPermission } = useAuth();
  const feature = CAPABILITY_LABELS[capability] ?? 'This feature';
  const canManageLicense = edition === 'enterprise' && hasPermission('settings:system');
  return (
    <div data-testid="licensed-feature-unavailable" className="flex h-full flex-col items-center justify-center px-8 text-center">
      <h1 className="text-xl font-semibold text-foreground">{feature} is not licensed</h1>
      <p className="mt-2 max-w-lg text-sm text-muted-foreground">
        The current license does not include {feature}. Open/core features,
        ingest, search, and stored data remain available.
        {!canManageLicense && ' Ask your administrator to install or renew the license.'}
      </p>
      <div className="mt-5 flex items-center gap-4 text-sm font-medium">
        {canManageLicense && (
          <Link className="text-primary hover:underline" to="/settings/license">
            Open Settings &gt; License
          </Link>
        )}
        <Link className="text-primary hover:underline" to="/">
          Return to Home
        </Link>
      </div>
    </div>
  );
}
