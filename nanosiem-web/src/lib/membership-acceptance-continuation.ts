// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Where the membership-acceptance page is in its flow (NAN-3788).
 *
 * The invitation link is `/auth/shared/memberships/accept#<token>`: outside
 * any `/t/<slug>` prefix, because the inviting admin does not know (and must
 * not learn) which tenant the invitee signs in to. On the pooled host a
 * session exists only per tenant: AuthContext refreshes with the slug read off
 * the path, and the server refuses a shared refresh without one. So a fresh
 * load of the bare link can never be signed in. The page therefore:
 *
 *   1. keeps the token for this tab only (sessionStorage, short TTL) and
 *      scrubs the fragment;
 *   2. without a tenant prefix, asks which organization the user signs in to
 *      and reloads under `/t/<slug>/auth/shared/memberships/accept`;
 *   3. under the prefix, signs in there if needed (login returns here);
 *   4. accepts with the tab bearer, then forgets the token.
 */

import { canonicalTenantSlug, tenantSlugForAuthContinuation } from './tenant-auth-shell.ts';

export const MEMBERSHIP_ACCEPTANCE_PATH = '/auth/shared/memberships/accept';
const STORAGE_KEY = 'nano.membership-acceptance';
const TTL_MS = 30 * 60 * 1000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/;

export interface ContinuationStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** The token in a `#<token>` fragment, or null when there is none / it is malformed. */
export function invitationTokenFromFragment(fragment: string): string | null {
  const token = fragment.startsWith('#') ? fragment.slice(1) : '';
  return TOKEN_PATTERN.test(token) ? token : null;
}

export function stashInvitation(storage: ContinuationStorage, token: string, now = Date.now()): void {
  if (!TOKEN_PATTERN.test(token)) return;
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify({ token, expiresAt: now + TTL_MS }));
  } catch {
    // Storage unavailable: the page still works within this load.
  }
}

export function readInvitation(storage: ContinuationStorage, now = Date.now()): string | null {
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (raw === null) return null;
    const parsed = JSON.parse(raw) as { token?: unknown; expiresAt?: unknown };
    if (
      typeof parsed?.token === 'string'
      && TOKEN_PATTERN.test(parsed.token)
      && typeof parsed.expiresAt === 'number'
      && parsed.expiresAt > now
    ) {
      return parsed.token;
    }
    storage.removeItem(STORAGE_KEY);
  } catch {
    // Unreadable entry or storage: treat as absent.
  }
  return null;
}

export function clearInvitation(storage: ContinuationStorage): void {
  try {
    storage.removeItem(STORAGE_KEY);
  } catch {
    // noop
  }
}

/** The acceptance page under one tenant's prefix. Throws on a non-canonical slug. */
export function tenantAcceptancePath(slug: string): string {
  return `/t/${canonicalTenantSlug(slug.trim().toLowerCase())}${MEMBERSHIP_ACCEPTANCE_PATH}`;
}

export type AcceptanceStep = 'missing' | 'choose-tenant' | 'loading' | 'sign-in' | 'accept';

/** What the page must do next. `pathname` is the raw browser path. */
export function acceptanceStep(input: {
  pathname: string;
  hasInvitation: boolean;
  isLoading: boolean;
  isAuthenticated: boolean;
}): AcceptanceStep {
  if (!input.hasInvitation) return 'missing';
  // The same selector AuthContext refreshes with: without it no shared
  // session can be restored on this load.
  if (tenantSlugForAuthContinuation(input.pathname) === undefined) return 'choose-tenant';
  if (input.isLoading) return 'loading';
  return input.isAuthenticated ? 'accept' : 'sign-in';
}
