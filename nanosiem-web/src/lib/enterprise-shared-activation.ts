// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  PASSWORD_HINT,
  PASSWORD_MAX_BYTES,
  PASSWORD_MIN_BYTES,
  validatePassword,
} from './password.ts';
import { canonicalTenantSlug, tenantMfaSetupPath } from './tenant-auth-shell.ts';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/;

/**
 * Activation-surface aliases for the single client-side password policy mirror
 * in `./password.ts`. The policy itself is NOT restated here — these names exist
 * because the activation page and its tests already refer to them.
 *
 * Source of truth: `PasswordRequirements::default()` and `MAX_PASSWORD_BYTES` in
 * `nanosiem-core/src/auth/password.rs`. Both activation paths
 * (`EnterpriseSharedActivationService::activate` and
 * `activate_member_invitation`) run exactly these checks. The lockstep is
 * asserted by `password.test.ts`.
 */
export const SHARED_ACTIVATION_PASSWORD_MIN_BYTES = PASSWORD_MIN_BYTES;
export const SHARED_ACTIVATION_PASSWORD_MAX_BYTES = PASSWORD_MAX_BYTES;

/** Rendered as the field hint so the requirements are visible before submitting. */
export const SHARED_ACTIVATION_PASSWORD_HINT = PASSWORD_HINT;

export interface SharedActivationFieldErrors {
  password: string[];
  confirmation: string[];
}

/** Mirrors `validate_password_complexity`; returns every unmet requirement. */
export const validateSharedActivationPassword = validatePassword;

/** Field-keyed validation for the activation form, so the page renders inline. */
export function validateSharedActivationForm(
  password: string,
  confirmation: string,
): SharedActivationFieldErrors {
  const passwordErrors = validateSharedActivationPassword(password);
  const confirmationErrors: string[] = [];
  if (confirmation.length === 0) {
    confirmationErrors.push('Confirm your password.');
  } else if (password !== confirmation) {
    confirmationErrors.push('Passwords do not match.');
  }
  return { password: passwordErrors, confirmation: confirmationErrors };
}

export function hasSharedActivationFieldErrors(errors: SharedActivationFieldErrors): boolean {
  return errors.password.length > 0 || errors.confirmation.length > 0;
}

export class SharedActivationBrowserError extends Error {
  constructor() {
    super('Account activation failed. Request a new invitation.');
    this.name = 'SharedActivationBrowserError';
  }
}

/**
 * The server answered 400 `password_requirements_not_met`. Distinct from the
 * uniform failure so the page can render it inline on the password field.
 */
export class SharedActivationPasswordRejectedError extends Error {
  readonly field = 'password' as const;
  readonly messages: string[];
  constructor() {
    super('Password does not meet requirements.');
    this.name = 'SharedActivationPasswordRejectedError';
    this.messages = ['Password does not meet requirements.', SHARED_ACTIVATION_PASSWORD_HINT];
  }
}

export interface SharedActivationBrowserDependencies {
  fetch: typeof globalThis.fetch;
  /** Removes the plaintext-bearing fragment before the first request. */
  replaceUrl: (path: string) => void;
  /** The page's own path without the fragment. Member links carry the
   * tenant prefix (`/t/<slug>/auth/shared/activate`, NAN-3788); owner and
   * already-issued links are bare. Defaults to the bare route. */
  activationPath?: string;
}

const BARE_ACTIVATION_PATH = '/auth/shared/activate';
const ACTIVATION_PATH_PATTERN = /^(?:\/t\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))?\/auth\/shared\/activate$/;

/** The activation page path to keep in the address bar: the browser path
 * when it is an exact (optionally tenant-prefixed) activation path, else the
 * bare route. */
export function sharedActivationPagePath(pathname: string): string {
  return ACTIVATION_PATH_PATTERN.test(pathname) ? pathname : BARE_ACTIVATION_PATH;
}

/** The tenant a prefixed activation link names, for display only (the
 * server's answer decides where the user lands). */
export function tenantSlugFromActivationPath(pathname: string): string | undefined {
  return ACTIVATION_PATH_PATTERN.exec(pathname)?.[1];
}

export interface SharedActivationBrowserResult {
  tenantSlug: string;
  destination: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertNoCredentialFields(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertNoCredentialFields);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (/token|secret|password|verifier|nonce|state/i.test(key)) {
      throw new SharedActivationBrowserError();
    }
    assertNoCredentialFields(child);
  }
}

/**
 * Reads only the stable machine-readable discriminator; server-supplied prose
 * is never rendered.
 */
async function isPasswordPolicyRejection(response: Response): Promise<boolean> {
  try {
    const body: unknown = await response.json();
    return isRecord(body) && body.error === 'password_requirements_not_met';
  } catch {
    return false;
  }
}

export async function activateEnterpriseSharedAccount(
  fragment: string,
  newPassword: string,
  dependencies: SharedActivationBrowserDependencies,
): Promise<SharedActivationBrowserResult> {
  dependencies.replaceUrl(sharedActivationPagePath(dependencies.activationPath ?? BARE_ACTIVATION_PATH));
  const token = fragment.startsWith('#') ? fragment.slice(1) : '';
  if (!TOKEN_PATTERN.test(token)) {
    throw new SharedActivationBrowserError();
  }
  // Enforce the server policy before the request so a rejectable password
  // never leaves the browser.
  if (validateSharedActivationPassword(newPassword).length > 0) {
    throw new SharedActivationPasswordRejectedError();
  }

  let response: Response;
  try {
    response = await dependencies.fetch('/api/auth/shared/activate', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activation_token: token, new_password: newPassword }),
    });
  } catch {
    throw new SharedActivationBrowserError();
  }
  if (!response.ok) {
    if (response.status === 400 && await isPasswordPolicyRejection(response)) {
      throw new SharedActivationPasswordRejectedError();
    }
    throw new SharedActivationBrowserError();
  }

  let document: unknown;
  try {
    document = await response.json();
  } catch {
    throw new SharedActivationBrowserError();
  }
  assertNoCredentialFields(document);
  if (
    !isRecord(document)
    || Object.keys(document).sort().join(',')
      !== 'assignmentRevision,deploymentMode,mfaEnrollmentRequired,planCode,planRevision,tenant'
    || document.deploymentMode !== 'enterprise_shared'
    || document.mfaEnrollmentRequired !== true
    || !Number.isSafeInteger(document.planRevision)
    || Number(document.planRevision) <= 0
    || !Number.isSafeInteger(document.assignmentRevision)
    || Number(document.assignmentRevision) <= 0
    || typeof document.planCode !== 'string'
    || !isRecord(document.tenant)
    || Object.keys(document.tenant).sort().join(',') !== 'slug,tenantId'
    || typeof document.tenant.tenantId !== 'string'
  ) {
    throw new SharedActivationBrowserError();
  }
  const tenantSlug = canonicalTenantSlug(document.tenant.slug);
  return { tenantSlug, destination: tenantMfaSetupPath(tenantSlug) };
}

