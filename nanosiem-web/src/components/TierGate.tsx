// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTierContext } from '@/hooks/use-tier';
import { Lock } from 'lucide-react';

interface TierGateProps {
  /** Return true if the feature is available */
  check: (tier: ReturnType<typeof useTierContext>) => boolean;
  /** Deprecated compatibility prop; v2 has no feature-tier upgrades. */
  requiredTier: string;
  /** Feature name for the upgrade message */
  featureName: string;
  children: React.ReactNode;
}

/**
 * Gates content on an edition/build capability.
 */
export function TierGate({ check, requiredTier, featureName, children }: TierGateProps) {
  const tierCtx = useTierContext();
  void requiredTier;

  if (tierCtx.loading) {
    return <>{children}</>;
  }

  if (!check(tierCtx)) {
    return (
      <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center mb-4">
          <Lock className="w-6 h-6 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold text-foreground mb-2">
          {featureName} is not included in this build
        </h3>
        <p className="text-sm text-muted-foreground max-w-md">
          This deployment does not include {featureName.toLowerCase()}.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
