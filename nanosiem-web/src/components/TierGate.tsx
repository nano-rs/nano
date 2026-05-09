// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTierContext } from '@/hooks/use-tier';
import { Lock } from 'lucide-react';

interface TierGateProps {
  /** Return true if the feature is available */
  check: (tier: ReturnType<typeof useTierContext>) => boolean;
  /** Tier name needed for the upgrade message */
  requiredTier: string;
  /** Feature name for the upgrade message */
  featureName: string;
  children: React.ReactNode;
}

/**
 * Gates content behind a tier check. Shows an upgrade prompt
 * when the feature isn't available on the current plan.
 */
export function TierGate({ check, requiredTier, featureName, children }: TierGateProps) {
  const tierCtx = useTierContext();

  if (tierCtx.loading || !tierCtx.isEnforced) {
    return <>{children}</>;
  }

  if (!check(tierCtx)) {
    return (
      <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center mb-4">
          <Lock className="w-6 h-6 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold text-foreground mb-2">
          {featureName} is not available on your plan
        </h3>
        <p className="text-sm text-muted-foreground max-w-md">
          Upgrade to {requiredTier} or higher to access {featureName.toLowerCase()}.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
