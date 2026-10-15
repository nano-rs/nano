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
import type { TenantCapabilitySnapshot } from '@/lib/tenant-capabilities';

export type BuildEdition = 'open' | 'enterprise';

export interface Capabilities {
  /** Core nPL Search; shared mode resolves this from the tenant plan. */
  search: boolean;
  cases: boolean;
  notebooks: boolean;
  risk: boolean;
  /**
   * pivt/meloD is usable: the build ships it and, on a hosted-shared tenant,
   * the plan includes it AND a platform AI provider is enabled
   * (`GET /api/settings/ai-availability`, NAN-2361 wave 8). Every AI
   * affordance (ask-AI, wizards, tuning suggestions) gates on this — never on
   * the deployment mode — so a tenant without a provider sees no AI surface
   * and issues no AI request.
   */
  melod: boolean;
  /** Audited narrow query-correction path; does not imply generic meloD. Same platform-provider condition as `melod`. */
  queryCorrection: boolean;
  customEnrichment: boolean;
  agentEnrichment: boolean;
  /** Same platform-provider condition as `melod` on a hosted-shared tenant. */
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
  /**
   * Code-free IOC lists (NAN-3038, `/api/ioc-lists`). The routes exist only on
   * the hosted-shared tenant substrate; open-core and dedicated builds 404, so
   * the nav item and page are hidden there (NAN-3467).
   */
  iocLists: boolean;
}

/**
 * How logs reach this install (NAN-3844). `tenzir_only` is an open-core
 * `install.sh --tenzir` install with no Vector: data arrives only through the
 * Tenzir bucket drop, so push sources, pull connectors, directory sync,
 * parser deploys and synthetic checks are off (the API refuses them with 409
 * `VECTOR_NOT_INSTALLED`).
 */
export type IngestMode = 'vector' | 'tenzir_only';
/** `unknown` while `/api/capabilities` has not answered yet. */
export type IngestModeState = IngestMode | 'unknown';

export interface CapabilitiesContextValue {
  edition: BuildEdition;
  version: string;
  /**
   * `unknown` until `/api/capabilities` answers; absent on hosted-shared
   * tenants and older APIs, which means `vector`.
   */
  ingestMode?: IngestModeState;
  capabilities: Capabilities;
  /** Present only for an authenticated, exact hosted-shared tenant. */
  tenantPlan?: TenantCapabilitySnapshot;
}

export const CapabilitiesContext = createContext<CapabilitiesContextValue | null>(null);

export function useCapabilities(): CapabilitiesContextValue {
  const ctx = useContext(CapabilitiesContext);
  if (!ctx) {
    throw new Error('useCapabilities must be used within a CapabilitiesProvider');
  }
  return ctx;
}

export interface IngestGate {
  mode: IngestModeState;
  /** Known to be an `install.sh --tenzir` install: show the note. */
  tenzirOnly: boolean;
  /** Capabilities still loading: render gated controls disabled / skeleton. */
  unknown: boolean;
  /** Vector-dependent controls must not be offered (tenzir_only or unknown). */
  blocked: boolean;
}

/**
 * Vector-dependent UI gate (NAN-3844). Outside a provider (isolated component
 * tests) there is no signal, which means Vector.
 */
export function useIngestGate(): IngestGate {
  const mode = useContext(CapabilitiesContext)?.ingestMode ?? 'vector';
  return {
    mode,
    tenzirOnly: mode === 'tenzir_only',
    unknown: mode === 'unknown',
    blocked: mode !== 'vector',
  };
}
