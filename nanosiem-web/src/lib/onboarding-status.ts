// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3241: on an enterprise-shared (lean) tenant the onboarding status probe
 * reports `has_log_sources` / `has_parsers` as false because the tenant's
 * source registry lives behind `/api/log-sources`, not the deployment-global
 * tables the dedicated probe reads. Overlay what the registry says so the
 * Getting Started checklist reflects deployed sources and their parsers.
 */

import type { OnboardingStatus } from '@/lib/api/onboarding';
import type {
  LogSource,
  OrganizationalContext,
  SharedTenantMember,
  UserDetail,
} from '@/lib/api/types';

type RegistrySource = Pick<LogSource, 'deployed' | 'parser_vrl'>;

export function overlayLogSourceStatus(
  status: OnboardingStatus | null | undefined,
  sources: readonly RegistrySource[] | null | undefined,
): OnboardingStatus | null | undefined {
  if (!status || !sources || sources.length === 0) return status;
  const hasParser = sources.some(
    (s) => s.deployed || (typeof s.parser_vrl === 'string' && s.parser_vrl.trim() !== ''),
  );
  return {
    ...status,
    has_log_sources: true,
    has_parsers: status.has_parsers || hasParser,
  };
}

type OrgContextFields = Pick<
  OrganizationalContext,
  'organization_name' | 'industry' | 'environment' | 'attack_vectors' | 'compliance_frameworks' | 'custom_context'
>;

/**
 * NAN-4779: any field the AI Guidance tab saves counts as configured. Matches
 * the dedicated probe (`ORG_CONTEXT_CONFIGURED_SQL`); the name alone was
 * required before, so guidance saved without a name never cleared the step.
 */
export function isOrgContextConfigured(ctx: Partial<OrgContextFields> | null | undefined): boolean {
  if (!ctx) return false;
  const text = [ctx.organization_name, ctx.industry, ctx.environment, ctx.attack_vectors, ctx.custom_context];
  return (
    text.some((v) => typeof v === 'string' && v.trim() !== '') ||
    (Array.isArray(ctx.compliance_frameworks) && ctx.compliance_frameworks.length > 0)
  );
}

type TeamMember = Pick<UserDetail, 'status'> &
  Partial<Pick<SharedTenantMember, 'membership_status' | 'invitation_state'>>;

/**
 * NAN-4779: on a hosted-shared tenant an invited teammate stays a suspended
 * membership until they accept, and the status probe counts only active
 * members — so Team did not clear when the admin invited someone. An active
 * member or a pending invitation both count here.
 */
export function countTeamMembers(users: readonly TeamMember[] | null | undefined): number {
  if (!users) return 0;
  return users.filter((u) =>
    u.membership_status !== undefined
      ? u.membership_status === 'active' || u.invitation_state === 'pending'
      : u.status === 'active',
  ).length;
}

export interface HostedChecklistSignals {
  sources?: readonly RegistrySource[] | null;
  orgContext?: Partial<OrgContextFields> | null;
  users?: readonly TeamMember[] | null;
}

/**
 * Hosted-shared tenants: the shell's status probe cannot read the tenant
 * source registry, the tenant AI guidance or pending invitations (it reports
 * them `false`), so fold in what the tenant's own APIs return — the same APIs
 * the Log Sources, AI Guidance and Access Control pages read. Signals only
 * ever turn a step on; a missing signal (403, still loading) leaves the
 * probe's answer.
 */
export function resolveHostedChecklistStatus(
  status: OnboardingStatus | null | undefined,
  signals: HostedChecklistSignals,
): OnboardingStatus | null | undefined {
  const withSources = overlayLogSourceStatus(status, signals.sources);
  if (!withSources) return withSources;
  return {
    ...withSources,
    has_org_context: withSources.has_org_context || isOrgContextConfigured(signals.orgContext),
    has_users: withSources.has_users || countTeamMembers(signals.users) > 1,
  };
}
