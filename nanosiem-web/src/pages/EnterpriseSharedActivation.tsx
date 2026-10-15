// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared owner activation: the invitation link lands here, the owner
 * sets a password, then enrolls an authenticator (`MfaSetup`). Rendered on
 * the guided-form shell in `auth-shell.tsx` (design kit "Activate", 2026-09-16):
 * step rail, labeled fields, a live policy checklist, one primary action.
 * Validation is the same `@/lib/enterprise-shared-activation` policy the server
 * enforces; the browser's native validation is off so refusals read in-app.
 */

import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { API_BASE_URL } from '@/lib/api/utils';
import {
  activateEnterpriseSharedAccount,
  hasSharedActivationFieldErrors,
  sharedActivationPagePath,
  tenantSlugFromActivationPath,
  SHARED_ACTIVATION_PASSWORD_MAX_BYTES,
  SHARED_ACTIVATION_PASSWORD_MIN_BYTES,
  SharedActivationPasswordRejectedError,
  validateSharedActivationForm,
  type SharedActivationFieldErrors,
} from '@/lib/enterprise-shared-activation';
import { passwordChecklist } from '@/lib/password';
import {
  AuthError,
  AuthFootnote,
  AuthHeading,
  AuthShell,
  Field,
  PolicyChecklist,
  PrimaryButton,
  StepRail,
} from './auth-shell';
import { stashMfaContinuation } from '@/lib/tenant-auth-shell';

const NO_FIELD_ERRORS: SharedActivationFieldErrors = { password: [], confirmation: [] };

export function EnterpriseSharedActivation() {
  const location = useLocation();
  const fragment = useRef(typeof window === 'undefined' ? '' : window.location.hash);
  const passwordInput = useRef<HTMLInputElement>(null);
  const confirmationInput = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<SharedActivationFieldErrors>(NO_FIELD_ERRORS);
  /** Validation only becomes live after the first submit attempt. */
  const [validationLive, setValidationLive] = useState(false);

  useDocumentTitle('Activate account');

  useEffect(() => {
    // Keep the tenant prefix of a member link (NAN-3788); drop the fragment.
    window.history.replaceState(window.history.state, '', sharedActivationPagePath(window.location.pathname));
  }, []);

  const revalidate = (nextPassword: string, nextConfirmation: string) => {
    if (!validationLive) return;
    setFieldErrors(validateSharedActivationForm(nextPassword, nextConfirmation));
  };

  const focusFirstInvalid = (errors: SharedActivationFieldErrors) => {
    if (errors.password.length > 0) passwordInput.current?.focus();
    else if (errors.confirmation.length > 0) confirmationInput.current?.focus();
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setValidationLive(true);
    const errors = validateSharedActivationForm(password, confirmation);
    setFieldErrors(errors);
    if (hasSharedActivationFieldErrors(errors)) {
      setError(null);
      focusFirstInvalid(errors);
      return;
    }
    setBusy(true);
    setError(null);
    const activationFragment = fragment.current;
    fragment.current = '';
    try {
      const result = await activateEnterpriseSharedAccount(
        activationFragment,
        password,
        {
          replaceUrl: (path) => window.history.replaceState(window.history.state, '', path),
          activationPath: window.location.pathname,
          fetch: ((input: string | URL | Request, init?: RequestInit) =>
            window.fetch(`${API_BASE_URL}${String(input)}`, init)) as typeof globalThis.fetch,
        },
      );
      setPassword('');
      setConfirmation('');
      // A full load, not a router navigation: the destination is under the
      // tenant prefix and this page is not, so the router cannot reach it.
      stashMfaContinuation({ tenantSlug: result.tenantSlug, sharedActivation: true });
      window.location.assign(result.destination);
    } catch (failure) {
      setPassword('');
      setConfirmation('');
      if (failure instanceof SharedActivationPasswordRejectedError) {
        const rejected = { password: failure.messages, confirmation: [] };
        setFieldErrors(rejected);
        setError(null);
        focusFirstInvalid(rejected);
      } else {
        setFieldErrors(NO_FIELD_ERRORS);
        setError('Account activation failed. Request a new invitation.');
      }
    } finally {
      setBusy(false);
    }
  };

  const passwordInvalid = fieldErrors.password.length > 0;
  const confirmationInvalid = fieldErrors.confirmation.length > 0;

  const version = __APP_VERSION__;
  const checks = passwordChecklist(password);
  const policyMet = checks.every((c) => c.ok);
  const confirmMatches = confirmation.length > 0 && confirmation === password;
  const confirmMismatch = confirmation.length > 0 && confirmation !== password;
  const ready = policyMet && confirmMatches;
  /* A member link names its tenant in the path (`/t/<slug>/auth/shared/activate`);
     otherwise the slug may ride on router state; the shell copes without it. */
  const tenant = tenantSlugFromActivationPath(typeof window === 'undefined' ? '' : window.location.pathname)
    ?? (location.state as { tenantSlug?: string } | null)?.tenantSlug;
  const statusText = error
    ? 'activation failed'
    : busy ? 'activating account…' : ready ? 'password ok — ready to continue' : 'awaiting password';

  return (
    <AuthShell crumb="auth / activate" version={version} status={{ text: statusText, good: ready && !error }}>
      <StepRail steps={['Set password', 'Enroll authenticator']} current={1} />
      <AuthHeading title="Set your password">
        You&apos;re activating your nano account
        {tenant && (
          <>
            {' '}for <span className="font-mono text-[12px] text-[var(--fg-2)]">{tenant}</span>
          </>
        )}
        . Next you&apos;ll enroll an authenticator app.
      </AuthHeading>

      {error && <AuthError>{error}</AuthError>}

      <form onSubmit={submit} noValidate>
        <Field
          id="activation-password"
          ref={passwordInput}
          label="Password"
          password
          autoFocus
          autoComplete="new-password"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="••••••••••••"
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
            revalidate(event.target.value, confirmation);
          }}
          onBlur={() => revalidate(password, confirmation)}
          disabled={busy}
          required
          minLength={SHARED_ACTIVATION_PASSWORD_MIN_BYTES}
          maxLength={SHARED_ACTIVATION_PASSWORD_MAX_BYTES}
          aria-invalid={passwordInvalid}
          aria-describedby="activation-password-policy"
          note={passwordInvalid ? fieldErrors.password[0] : undefined}
          noteTone="bad"
        />
        <PolicyChecklist id="activation-password-policy" checks={checks} />

        <Field
          id="activation-confirmation"
          ref={confirmationInput}
          label="Confirm password"
          password
          autoComplete="new-password"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="••••••••••••"
          value={confirmation}
          onChange={(event) => {
            setConfirmation(event.target.value);
            revalidate(password, event.target.value);
          }}
          onBlur={() => revalidate(password, confirmation)}
          disabled={busy}
          required
          minLength={SHARED_ACTIVATION_PASSWORD_MIN_BYTES}
          maxLength={SHARED_ACTIVATION_PASSWORD_MAX_BYTES}
          aria-invalid={confirmationInvalid || confirmMismatch}
          tone={confirmMismatch ? 'bad' : confirmMatches ? 'good' : 'neutral'}
          note={confirmMismatch ? "passwords don't match" : confirmationInvalid ? fieldErrors.confirmation[0] : undefined}
          noteTone="bad"
        />

        <PrimaryButton type="submit" busy={busy} disabled={!ready}>
          Continue to authenticator setup →
        </PrimaryButton>
      </form>

      <AuthFootnote>
        This activation link is single-use. Your account is created once an authenticator is enrolled.
      </AuthFootnote>
    </AuthShell>
  );
}
