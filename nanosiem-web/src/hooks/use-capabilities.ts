// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Build capabilities — which surfaces are available in this deployment.
 *
 * Fetched once on app boot from `/api/capabilities`. The endpoint is public
 * (no auth) so the SPA can render correctly before login. In open-core builds
 * (`VITE_EDITION=open` / `cargo build` with no `enterprise` feature), the
 * enterprise pages are physically excluded from the bundle anyway via the
 * `@/enterprise` alias swap; capabilities is the runtime mirror used by:
 *   - the route + nav registries (filter out enterprise entries)
 *   - in-page guards on staging deployments where one bundle talks to either
 *     backend
 *   - observability ("which edition is this deployment running")
 *
 * Distinct from `useTier` (org plan tier — starter / pro / unrestricted, AI
 * credits, SSO entitlement). useTier sits *inside* enterprise and may further
 * restrict capabilities; useCapabilities answers the prior question of
 * whether the surface ships at all.
 *
 * Prefer specific capability flags (`useCapabilities().capabilities.cases`)
 * over edition-level checks — a "starter" enterprise tier may eventually drop
 * a single capability without changing the edition.
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
}

export interface CapabilitiesContextValue {
  edition: BuildEdition;
  version: string;
  capabilities: Capabilities;
}

export const CapabilitiesContext = createContext<CapabilitiesContextValue | null>(null);

export function useCapabilities(): CapabilitiesContextValue {
  const ctx = useContext(CapabilitiesContext);
  if (!ctx) {
    throw new Error('useCapabilities must be used within a CapabilitiesProvider');
  }
  return ctx;
}
