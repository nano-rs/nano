// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First-run setup: create the instance's first administrator. Rendered on the
 * guided-form shell in `auth-shell.tsx`; the password policy comes from
 * `@/lib/password` and is never restated here.
 */

import { useState, FormEvent, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PASSWORD_MAX_BYTES,
  PASSWORD_MIN_BYTES,
  passwordChecklist,
  unmetPasswordRequirements,
} from '@/lib/password';
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

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

interface SetupStatus {
  initialized: boolean;
  has_users: boolean;
}

export function Setup() {
  const navigate = useNavigate();

  // Form state
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isCheckingStatus, setIsCheckingStatus] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Password validation state
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);

  const nameInput = useRef<HTMLInputElement>(null);

  // Check setup status on mount
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/setup/status`);
        if (response.ok) {
          const status: SetupStatus = await response.json();
          if (status.initialized || status.has_users) {
            // System already initialized, redirect to login
            navigate('/login', { replace: true });
          }
        }
      } catch {
        // If we can't check status, show the setup form anyway
      } finally {
        setIsCheckingStatus(false);
      }
    };

    checkStatus();
  }, [navigate]);

  // The form only mounts once the status probe resolves, so `autoFocus` on the
  // first field would not fire — focus it explicitly instead.
  useEffect(() => {
    if (!isCheckingStatus && !success) nameInput.current?.focus();
  }, [isCheckingStatus, success]);

  // Validate password on change against the shared policy mirror. Do NOT
  // re-derive the rules here: this form used to carry its own, narrower
  // special-character class and rejected passwords the server accepts.
  useEffect(() => {
    setPasswordErrors(password.length > 0 ? unmetPasswordRequirements(password) : []);
  }, [password]);

  // Clear error when inputs change
  useEffect(() => {
    if (error) setError(null);
  }, [email, name, password, confirmPassword]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate inputs
    if (!email.trim()) {
      setError('Email is required');
      return;
    }

    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    if (!password) {
      setError('Password is required');
      return;
    }

    if (passwordErrors.length > 0) {
      setError('Password does not meet requirements');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/setup/initialize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim(),
          name: name.trim(),
          password,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({ message: 'Setup failed' }));
        throw new Error(errorBody.message || errorBody.error || 'Setup failed');
      }

      setSuccess(true);

      // Redirect to login after a short delay
      setTimeout(() => {
        navigate('/login', { replace: true });
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const version = __APP_VERSION__;

  const passwordInvalid = password.length > 0 && passwordErrors.length > 0;
  const confirmMismatch = confirmPassword.length > 0 && password !== confirmPassword;
  const confirmMatches = confirmPassword.length > 0 && password.length > 0 && !confirmMismatch;
  const checks = passwordChecklist(password);
  const ready = name.trim().length > 0 && email.trim().length > 0 && checks.every((c) => c.ok) && confirmMatches;

  const statusText = isCheckingStatus
    ? 'checking instance state…'
    : success
    ? 'administrator created — redirecting to sign-in'
    : error
    ? 'setup failed'
    : isSubmitting ? 'creating administrator account…' : ready ? 'ready to create the account' : 'awaiting admin details';

  return (
    <AuthShell crumb="auth / setup" version={version} status={{ text: statusText, good: success || (ready && !error) }}>
      <StepRail steps={['Create administrator', 'Sign in']} current={success ? 2 : 1} />

      {isCheckingStatus ? (
        <div className="h-[200px] flex items-center justify-center font-mono text-[11px] text-muted-foreground">
          checking whether this instance is already initialised…
        </div>
      ) : success ? (
        <>
          <AuthHeading title="Administrator created">
            The first account now exists and holds full administrative access. Redirecting you to sign in; invite everyone else from there.
          </AuthHeading>
        </>
      ) : (
        <>
          <AuthHeading title="Create the first administrator">
            This instance has no accounts yet. This account gets full administrative access; every other user is invited from it afterwards.
          </AuthHeading>

          {error && <AuthError>{error}</AuthError>}

          <form onSubmit={handleSubmit} noValidate>
            <Field
              id="name"
              ref={nameInput}
              label="Name"
              type="text"
              placeholder="Admin User"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isSubmitting}
              autoComplete="name"
              autoFocus
            />
            <Field
              id="email"
              label="Email"
              type="email"
              placeholder="admin@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isSubmitting}
              // The email is the sign-in identifier: `username` lets a password
              // manager pair it with the `new-password` below (NAN-3146).
              autoComplete="username"
              autoCapitalize="off"
              spellCheck={false}
            />
            <Field
              id="password"
              label="Password"
              password
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isSubmitting}
              autoComplete="new-password"
              autoCapitalize="off"
              spellCheck={false}
              minLength={PASSWORD_MIN_BYTES}
              maxLength={PASSWORD_MAX_BYTES}
              aria-invalid={passwordInvalid}
              aria-describedby="setup-password-policy"
            />
            <PolicyChecklist id="setup-password-policy" checks={checks} />
            <Field
              id="confirmPassword"
              label="Confirm password"
              password
              placeholder="••••••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              disabled={isSubmitting}
              autoComplete="new-password"
              autoCapitalize="off"
              spellCheck={false}
              aria-invalid={confirmMismatch}
              tone={confirmMismatch ? 'bad' : confirmMatches ? 'good' : 'neutral'}
              note={confirmMismatch ? "passwords don't match" : undefined}
              noteTone="bad"
            />
            <PrimaryButton type="submit" busy={isSubmitting} disabled={!ready}>
              Create administrator account →
            </PrimaryButton>
          </form>
          <AuthFootnote>Created once, on first run. You&apos;ll sign in with these credentials next.</AuthFootnote>
        </>
      )}
    </AuthShell>
  );
}
