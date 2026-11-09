// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hook for organization tier status
 * Fetches tier limits, usage, and proactive warnings
 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { api } from '@/lib/api';
import type {
  TierStatus,
  OrganizationTier,
  AiModelTier,
  Entitlement,
} from '@/lib/api/types';

interface UseTierResult {
  status: TierStatus | null;
  loading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  /** Whether a compatibility resource/API limit remains configured. */
  isEnforced: boolean;
  /** Canonical compatibility value (`open` or `licensed`). */
  tier: OrganizationTier;
  entitlement: Entitlement;
  offeringName: 'Open source' | 'nano Self-run' | 'nano Hosted';
  /** Check if SSO is available */
  hasSso: boolean;
  /** Check if full API access is available */
  hasFullApi: boolean;
  /** Check if any API access is available */
  hasApi: boolean;
  /** Compatibility field; v2 always makes every configured model available. */
  aiModelTier: AiModelTier;
  /** AI credits used this month (lite=2, full=10 per call) */
  aiCreditsUsed: number;
  /** Hosted allowance per month; null means customer-provided, uncapped AI. */
  aiCreditsLimit: number | null;
}

export function useTier(): UseTierResult {
  const [status, setStatus] = useState<TierStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true);
      const result = await api.tier.getStatus();
      setStatus(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const limits = status?.limits;
  const tier = limits?.tier ?? 'open';
  const entitlement = limits?.entitlement ?? {
    edition: 'open' as const,
    operator: 'self-run' as const,
    capacity_gb_per_day: null,
  };
  const offeringName = entitlement.edition === 'open'
    ? 'Open source'
    : entitlement.operator === 'hosted'
      ? 'nano Hosted'
      : 'nano Self-run';
  const aiUsage = status?.ai_usage;

  return {
    status,
    loading,
    error,
    refetch: fetchStatus,
    isEnforced: Boolean(
      limits && (
        limits.max_data_sources !== null ||
        limits.max_detection_rules !== null ||
        limits.max_team_members !== null ||
        limits.api_access !== 'full'
      )
    ),
    tier,
    entitlement,
    offeringName,
    hasSso: limits?.sso_enabled ?? false,
    hasFullApi: limits?.api_access === 'full',
    hasApi: limits?.api_access !== 'none',
    aiModelTier: aiUsage?.model_tier ?? 'full',
    aiCreditsUsed: aiUsage?.credits_used ?? 0,
    aiCreditsLimit: aiUsage?.credits_limit ?? null,
  };
}

// Context for sharing tier status across the app without redundant fetches
const TierContext = createContext<UseTierResult | null>(null);

export const TierProvider = TierContext.Provider;

export function useTierContext(): UseTierResult {
  const ctx = useContext(TierContext);
  if (!ctx) {
    throw new Error('useTierContext must be used within a TierProvider');
  }
  return ctx;
}
