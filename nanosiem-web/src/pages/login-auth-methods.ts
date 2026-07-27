// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Which authentication methods the login page may present, and how it describes
// them. Extracted from `Login.tsx` so the state matrix (open-core build, in-flight
// provider fetch, failed fetch, no providers, one provider, several) is testable
// without a DOM harness — the repo has no browser test runner, and the states
// this module encodes are exactly the ones that were previously wrong or
// unreachable (NAN-2179).

/**
 * Public provider shape returned by `GET /api/auth/oidc/providers` — slug and
 * name only, matching `OidcProviderInfo` in nanosiem-core. There is no `id` on
 * the pre-auth surface; the slug is the identifier.
 */
export interface OidcProviderRef {
  name: string;
  slug: string;
}

/**
 * What the login page should render for single sign-on.
 *
 * `hidden` covers two distinct causes that intentionally look identical to the
 * user: an open-core build with no SSO capability, and an enterprise tenant with
 * no enabled providers. The endpoint only ever returns *enabled* providers, so a
 * tenant whose providers are all disabled arrives here as an empty list — the
 * disabled case is filtered server-side and needs no separate surface.
 */
export type SsoSurface =
  | { kind: 'hidden' }
  | { kind: 'loading' }
  | { kind: 'error' }
  | { kind: 'providers'; providers: readonly OidcProviderRef[] };

export function resolveSsoSurface(input: {
  /** `capabilities.sso` — false in open-core builds (NAN-745). */
  ssoEnabled: boolean;
  /** Provider fetch still in flight. */
  loading: boolean;
  /** Provider fetch failed or returned a non-OK status. */
  failed: boolean;
  providers: readonly OidcProviderRef[];
}): SsoSurface {
  if (!input.ssoEnabled) return { kind: 'hidden' };
  if (input.loading) return { kind: 'loading' };
  if (input.failed) return { kind: 'error' };
  if (input.providers.length === 0) return { kind: 'hidden' };
  return { kind: 'providers', providers: input.providers };
}

/**
 * The line echoed after an email is submitted.
 *
 * This replaces the hard-coded `provider resolved: local-password`, which read
 * as per-account provider discovery even though no lookup happened. What the
 * page actually knows is tenant-wide configuration, so that is what it states —
 * and it names SSO alongside password so the relationship between the two is
 * explicit rather than buried in a side panel.
 */
export function authMethodsLine(surface: SsoSurface): string {
  return `→ tenant auth methods: ${authMethodsSummary(surface)}`;
}

function authMethodsSummary(surface: SsoSurface): string {
  switch (surface.kind) {
    case 'hidden':
      return 'password';
    case 'loading':
      return 'password · sso (checking providers…)';
    case 'error':
      return 'password · sso (unavailable)';
    case 'providers':
      return `password · sso (${surface.providers.map((p) => p.slug).join(', ')})`;
  }
}

/**
 * Steps that may show the SSO panel.
 *
 * Offered at identity *and* password entry — a failed password is the moment an
 * analyst most wants the SSO route. Withheld mid-MFA, where the credential has
 * already been accepted and switching methods would abandon a live challenge,
 * and after completion.
 */
export function showSsoPanel(step: string): boolean {
  return step === 'email' || step === 'password';
}

/**
 * Container classes for the central SSO panel.
 *
 * Exported so a test can assert the panel carries no viewport gate. The original
 * SSO surface lived in a `hidden lg:flex` inspector, which made SSO not merely
 * secondary but entirely unreachable below `lg`.
 */
export const SSO_PANEL_CLASS = 'mt-2 max-w-[78ch]';

/** Tailwind tokens that would hide or reveal the panel by viewport width. */
const VIEWPORT_GATE = /(^|\s|:)(hidden|invisible)(\s|$)|\b(sm|md|lg|xl|2xl):(flex|hidden|block|grid|inline-flex)\b/;

/** True when `className` would make the panel's presence depend on viewport width. */
export function hasViewportGate(className: string): boolean {
  return VIEWPORT_GATE.test(className);
}

/**
 * What the login page should present overall (NAN-2181).
 *
 * `loading` exists so an SSO-only tenant never flashes a password prompt while
 * `GET /api/auth/methods` is still in flight — that flash is precisely the
 * thing the setting is meant to remove, and it would train users to type
 * credentials into a form that cannot accept them.
 *
 * `ssoOnlyUnavailable` is the state that should be unreachable: password
 * sign-in off and no usable provider. The server guards against creating it
 * (SSO-only cannot be enabled without an enabled provider, and the last enabled
 * provider cannot be removed while it is on), but a failed provider fetch
 * reproduces it client-side, so the page owes the user an explanation and a
 * retry rather than an empty screen.
 */
export type LoginMode =
  | { kind: 'loading' }
  | { kind: 'password'; sso: SsoSurface }
  | { kind: 'ssoOnly'; providers: readonly OidcProviderRef[] }
  | { kind: 'ssoOnlyLoading' }
  | { kind: 'ssoOnlyUnavailable'; reason: 'error' | 'noProviders' };

export function resolveLoginMode(input: {
  /** `localPassword` from `/api/auth/methods`; null while unknown. */
  localPassword: boolean | null;
  sso: SsoSurface;
}): LoginMode {
  if (input.localPassword === null) return { kind: 'loading' };
  if (input.localPassword) return { kind: 'password', sso: input.sso };

  switch (input.sso.kind) {
    case 'providers':
      return { kind: 'ssoOnly', providers: input.sso.providers };
    case 'loading':
      return { kind: 'ssoOnlyLoading' };
    case 'error':
      return { kind: 'ssoOnlyUnavailable', reason: 'error' };
    case 'hidden':
      return { kind: 'ssoOnlyUnavailable', reason: 'noProviders' };
  }
}

/** Whether the page should render the email/password wizard at all. */
export function showPasswordPrompt(mode: LoginMode): boolean {
  return mode.kind === 'password';
}

export type SsoCommand =
  | { kind: 'list' }
  | { kind: 'launch'; target: string };

/**
 * Parse the terminal `sso` command.
 *
 * The panel is a row of real buttons, so pointer and Tab/Enter users are already
 * covered; this keeps the wizard's keyboard-only idiom intact for someone who
 * never leaves the prompt. `sso` lists providers, `sso <slug|index>` launches one.
 */
export function parseSsoCommand(raw: string): SsoCommand | null {
  const parts = raw.trim().split(/\s+/);
  if (parts[0]?.toLowerCase() !== 'sso') return null;
  if (parts.length === 1) return { kind: 'list' };
  return { kind: 'launch', target: parts.slice(1).join(' ') };
}

/**
 * Resolve a `sso <target>` argument against the available providers, by 1-based
 * index as listed in the panel, exact slug, or case-insensitive name.
 */
export function resolveSsoTarget(
  target: string,
  providers: readonly OidcProviderRef[],
): OidcProviderRef | null {
  const trimmed = target.trim();
  if (!trimmed) return null;

  if (/^\d+$/.test(trimmed)) {
    return providers[Number(trimmed) - 1] ?? null;
  }
  const lower = trimmed.toLowerCase();
  return (
    providers.find((p) => p.slug.toLowerCase() === lower) ??
    providers.find((p) => p.name.toLowerCase() === lower) ??
    null
  );
}
