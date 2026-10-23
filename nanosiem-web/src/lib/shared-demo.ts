// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-4152: per-tenant demo sessions on the shared (lean) runtime.
//
// A demo link is `/t/<segment>/d/<token>`; the claim
// (`POST /api/auth/shared/demo/claim`) answers the normal shared login
// AuthResponse + cookies, and `/api/auth/me` then carries
// `demo: { active, expires_at }` for the demo analyst only.

import { canonicalTenantSlug } from './tenant-auth-shell.ts';

export const SHARED_DEMO_CLAIM_PATH = '/api/auth/shared/demo/claim';
/** Where an expired / invalid link sends the visitor. */
export const DEMO_SIGNUP_URL = 'https://nano.rs';

export interface SharedDemoState {
  active: boolean;
  /** RFC 3339. */
  expires_at: string;
}

/** The claim body: always the canonical slug (never a path alias). */
export function sharedDemoClaimBody(tenantSlug: string, token: string): { tenant_slug: string; token: string } {
  return { tenant_slug: canonicalTenantSlug(tenantSlug), token };
}

/**
 * Whether the identity is a demo analyst: a live shared demo session
 * (`demo.active` from `/api/auth/me`) or the Saturn demo role. Normal members
 * carry neither.
 */
export function isDemoIdentity(
  user: { roles?: string[]; demo?: SharedDemoState | null } | null | undefined,
): boolean {
  if (!user) return false;
  return user.demo?.active === true || (user.roles?.includes('demo_analyst') ?? false);
}

/** The claim refusal (uniform 401 `invalid_demo_link`): expired, already claimed, unknown, or another tenant's. */
export function isInvalidDemoLinkError(error: unknown): boolean {
  if (error === null || typeof error !== 'object') return false;
  const { status, code } = error as { status?: unknown; code?: unknown };
  return status === 401 || code === 'invalid_demo_link';
}

/** Hours left until `expiresAt` (0 when past or unparseable). */
export function demoHoursRemaining(expiresAt: string, now: Date = new Date()): number {
  const end = Date.parse(expiresAt);
  if (Number.isNaN(end)) return 0;
  return Math.max(0, (end - now.getTime()) / 3_600_000);
}

/** `2d 4h remaining` / `5h remaining` / `12m remaining`. */
export function demoTimeRemainingText(hoursLeft: number): string {
  if (hoursLeft > 24) return `${Math.floor(hoursLeft / 24)}d ${Math.floor(hoursLeft % 24)}h remaining`;
  if (hoursLeft > 1) return `${Math.floor(hoursLeft)}h remaining`;
  return `${Math.max(1, Math.floor(hoursLeft * 60))}m remaining`;
}
