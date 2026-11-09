// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Build capabilities — which surfaces are available in this deployment.
 *
 * Fetched on app boot and refreshed from `/api/capabilities`. The endpoint is
 * public (no auth) so the SPA can render correctly before login and react to
 * licence hard stops or renewals without a reload. In open-core builds
 * (`VITE_EDITION=open` / `cargo build` with no `enterprise` feature), the
 * enterprise pages are physically excluded from the bundle anyway via the
 * `@/enterprise` alias swap; capabilities is the runtime mirror used by:
 *   - the route + nav registries (filter out enterprise entries)
 *   - in-page guards on staging deployments where one bundle talks to either
 *     backend
 *   - observability ("which edition is this deployment running")
 *
 * Distinct from `useTier` (edition, operator, capacity, and hosted AI
 * allowance). `useCapabilities` is the live route/surface admission boundary.
 *
 * Prefer specific capability flags (`useCapabilities().capabilities.cases`)
 * over edition-level checks so future per-capability grants can evolve without
 * changing the edition.
 */

import { createContext, useContext } from 'react';

export type BuildEdition = 'open' | 'enterprise';

export interface Capabilities {
  cases: boolean;
  notebooks: boolean;
  risk: boolean;
  melod: boolean;
  customEnrichment: boolean;
  agentEnrichment: boolean;
  aiTuning: boolean;
  playbooks: boolean;
  incidents: boolean;
  siemHealth: boolean;
  /** SAML / OIDC SSO providers. Local credentials still work in open builds. */
  sso: boolean;
  /**
   * Observability ↔ security convergence cross-link (NAN-1544): the
   * "Related security signals" strip on Service detail. Enterprise-only — the
   * backing route (GET /api/observability/services/{service}/security-signals)
   * is physically absent (404) on open builds, so the strip is hidden here too.
   */
  observabilityConvergence: boolean;
  /** Code-free IOC lists (`/api/ioc-lists`, enterprise; NAN-4902 lane G). */
  iocLists: boolean;
  /**
   * SOAR governed response automation (`/api/soar/*`, enterprise; NAN-4911).
   * Build-level only: an admin still switches SOAR on in Settings > SOAR.
   */
  soar: boolean;
  /**
   * Threat-intel lookups and the Enrich flyout (`/api/threat-intel/*`,
   * enterprise; NAN-4931): external providers plus the install's own IOC
   * feeds and lists.
   */
  threatIntel: boolean;
}

export interface CapabilitiesContextValue {
  edition: BuildEdition;
  version: string;
  capabilities: Capabilities;
  /**
   * Set only on the fail-closed fallback used before `/api/capabilities`
   * answers (or when it errors). The flags are then a guess, not a licence
   * verdict, so copy that explains WHY a flag is off (NAN-5088: "needs an
   * active licence") must not render on it.
   */
  fallback?: true;
}

export const CapabilitiesContext = createContext<CapabilitiesContextValue | null>(null);

export function useCapabilities(): CapabilitiesContextValue {
  const ctx = useContext(CapabilitiesContext);
  if (!ctx) {
    throw new Error('useCapabilities must be used within a CapabilitiesProvider');
  }
  return ctx;
}

/**
 * Like {@link useCapabilities}, but `null` outside a CapabilitiesProvider
 * instead of throwing: for gates on affordances inside shared components
 * that also render in isolation (component tests, embeds). A missing
 * provider means "no enterprise capability", so callers treat `null` as off.
 */
export function useCapabilitiesOptional(): CapabilitiesContextValue | null {
  return useContext(CapabilitiesContext);
}
