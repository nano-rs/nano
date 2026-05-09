// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hook for organization tier status
 * Fetches tier limits, usage, and proactive warnings
 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { api } from '@/lib/api';
import type { TierStatus, OrganizationTier, AiModelTier } from '@/lib/api/types';

interface UseTierResult {
  status: TierStatus | null;
  loading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  /** Whether the current tier enforces any limits */
  isEnforced: boolean;
  /** Current tier name */
  tier: OrganizationTier;
  /** Check if SSO is available */
  hasSso: boolean;
  /** Check if full API access is available */
  hasFullApi: boolean;
  /** Check if any API access is available */
  hasApi: boolean;
  /** AI model tier for this plan */
  aiModelTier: AiModelTier;
  /** AI credits used this month (lite=2, full=10 per call) */
  aiCreditsUsed: number;
  /** AI credits limit per month (null = unlimited) */
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
  const tier = limits?.tier ?? 'unrestricted';
  const aiUsage = status?.ai_usage;

  return {
    status,
    loading,
    error,
    refetch: fetchStatus,
    isEnforced: tier !== 'unrestricted',
    tier,
    hasSso: limits?.sso_enabled ?? true,
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
