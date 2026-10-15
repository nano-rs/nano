// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Authenticator enrollment: pair (QR + manual key), verify a code, save
 * recovery codes. Reached from the activation flow (forced, with a challenge
 * token) or from settings. Rendered on the guided-form shell in
 * `auth-shell.tsx`; when it continues an activation the step rail shows
 * "Set password ✓ · Enroll authenticator" so the owner sees one journey.
 */

import { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Copy, Download, ChevronRight } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api, ApiClientError } from '@/lib/api';
import type { MfaSetupResponse, MfaSetupCompleteResponse } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import {
  canonicalTenantSlug,
  safeReturnPath,
  takeMfaContinuation,
  tenantLoginPath,
  tenantSlugFromMfaSetupPath,
} from '@/lib/tenant-auth-shell';
import {
  AuthError,
  AuthFootnote,
  AuthHeading,
  AuthShell,
  Field,
  PrimaryButton,
  SecondaryButton,
  StepRail,
} from './auth-shell';
import { Checkbox } from '@/components/ui/checkbox';

type Step = 'scan' | 'verify' | 'backup';

const AUTHENTICATOR_APPS = [
  'Google Authenticator',
  'Authy',
  '1Password',
  'Bitwarden',
  'Microsoft Authenticator',
];

export function MfaSetup() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, challengeToken: ctxChallengeToken, cancelMfa } = useAuth();
  const { toast } = useToast();

  useDocumentTitle('Set Up Two-Factor Authentication');

  // Reached via login bounce (forced) or /settings/user (voluntary).
  const [continuation] = useState(() => takeMfaContinuation());
  const locationState = (location.state as {
    challengeToken?: string;
    from?: string;
    tenantSlug?: string;
    sharedActivation?: boolean;
  } | null) ?? continuation;
  const challengeToken = ctxChallengeToken ?? locationState?.challengeToken ?? null;
  const isForced = !!challengeToken || locationState?.sharedActivation === true;
  // The router path is basename-relative (`/mfa-setup`); the tenant selector
  // lives on the browser path (`/t/<slug>/mfa-setup`).
  const browserPath = typeof window === 'undefined' ? location.pathname : window.location.pathname;
  const pathTenantSlug = browserPath.startsWith('/t/')
    ? tenantSlugFromMfaSetupPath(browserPath)
    : null;
  const tenantSlug = locationState?.tenantSlug
    ? canonicalTenantSlug(locationState.tenantSlug)
    : pathTenantSlug;
  if (pathTenantSlug && tenantSlug !== pathTenantSlug) {
    throw new Error('Tenant MFA continuation does not match the browser route');
  }
  const returnTo = safeReturnPath(locationState?.from, '/settings/user');

  const [step, setStep] = useState<Step>('scan');
  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** The forced-enrollment token is short-lived; when it lapses the only way
   *  forward is a fresh sign-in, which re-issues one. Reloading cannot. */
  const [enrollmentExpired, setEnrollmentExpired] = useState(false);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const verifyInputRef = useRef<HTMLInputElement>(null);
  // Single-call guard. Prevents `setupMfa` from re-firing if the auth deps
  // change mid-wizard or the component briefly re-renders before
  // unmounting on `Done`. Without this the second call returns 400
  // `already_enabled` after `verify_mfa_setup` has flipped the flag, and
  // the spurious error leaks into the success screen.
  const setupStartedRef = useRef(false);

  // Start setup on mount.
  useEffect(() => {
    if (setupStartedRef.current) return;
    if (!isAuthenticated && !isForced) return;
    setupStartedRef.current = true;
    const initSetup = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.auth.setupMfa(
          challengeToken ?? undefined,
          tenantSlug ?? undefined,
        );
        setSetupData(data);
      } catch (err: unknown) {
        if (isForced && err instanceof ApiClientError && err.status === 401) {
          setEnrollmentExpired(true);
          setError(null);
        } else {
          const message = err instanceof Error ? err.message : 'Failed to start MFA setup';
          setError(message);
        }
        // Allow a retry if the call genuinely failed.
        setupStartedRef.current = false;
      } finally {
        setLoading(false);
      }
    };
    initSetup();
  }, [isAuthenticated, isForced, challengeToken, tenantSlug]);

  useEffect(() => {
    if (step === 'verify' && verifyInputRef.current) verifyInputRef.current.focus();
  }, [step]);

  const handleVerify = async () => {
    if (!verifyCode.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result: MfaSetupCompleteResponse = await api.auth.verifyMfaSetup(
        verifyCode,
        challengeToken ?? undefined,
        tenantSlug ?? undefined,
      );
      setBackupCodes(result.backup_codes);
      setStep('backup');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Invalid code';
      setError(message);
      setVerifyCode('');
    } finally {
      setLoading(false);
    }
  };

  // Auto-submit on 6 digits.
  useEffect(() => {
    if (verifyCode.length === 6 && /^\d{6}$/.test(verifyCode) && step === 'verify') {
      handleVerify();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [verifyCode, step]);

  const handleComplete = async () => {
    if (isForced) {
      // Clear the AuthContext mfa-setup-pending flags before navigating —
      // otherwise Login.tsx's useEffect sees stale `mfaSetupPending` /
      // `challengeToken`, immediately bounces back to `/mfa-setup`, and
      // the resulting `setupMfa` call 400s with `already_enabled`.
      cancelMfa();
      // Basename-relative: under `/t/<slug>` this is the tenant login.
      navigate('/login', { replace: true });
      toast({
        title: 'MFA enabled',
        description: 'Two-factor authentication has been set up. Please sign in again.',
      });
    } else {
      navigate(returnTo, { replace: true });
      toast({
        title: 'MFA enabled',
        description: 'Two-factor authentication is now active on your account.',
      });
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    toast({ title: 'Copied', description: 'Backup codes copied to clipboard' });
  };

  const downloadBackupCodes = () => {
    const text = `nano Backup Codes\n${'='.repeat(30)}\n\nStore these codes in a safe place.\nEach code can only be used once.\n\n${backupCodes
      .map((c, i) => `${i + 1}. ${c}`)
      .join('\n')}\n`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nanosiem-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const version = __APP_VERSION__;
  const provisioning = loading && !setupData;
  const crumb = step === 'scan' ? 'auth / mfa / pair' : step === 'verify' ? 'auth / mfa / verify' : 'auth / mfa / recovery';
  const statusText = provisioning
    ? 'requesting enrollment secret…'
    : enrollmentExpired
    ? 'enrollment window expired — sign in to continue'
    : error && !setupData
    ? 'enrollment unavailable — reload to retry'
    : error && step === 'verify'
    ? 'code rejected — try again'
    : step === 'scan'
    ? 'awaiting authenticator pairing'
    : step === 'verify'
    ? loading ? 'verifying code…' : 'awaiting 6-digit code'
    : 'two-factor enabled — save your recovery codes';
  const rail = (
    <StepRail
      steps={isForced && locationState?.sharedActivation ? ['Set password', 'Enroll authenticator'] : ['Pair app', 'Verify code', 'Recovery codes']}
      current={isForced && locationState?.sharedActivation ? 2 : step === 'scan' ? 1 : step === 'verify' ? 2 : 3}
    />
  );

  return (
    <AuthShell crumb={crumb} version={version} status={{ text: statusText, good: step === 'backup' && !error }}>
      {rail}

      {/* ── Stage 1: pair ─────────────────────────────────────────── */}
      {step === 'scan' && (
        <>
          <AuthHeading title="Enroll an authenticator">
            Scan the code with any TOTP app ({AUTHENTICATOR_APPS.slice(0, 3).join(', ')}, …). You&apos;ll need a code from it at every sign-in.
          </AuthHeading>
          {enrollmentExpired && (
            <AuthError>
              Your enrollment window expired. Sign in with the password you just set and you&apos;ll be brought straight back here with a fresh one.
              {tenantSlug && (
                <>
                  {' '}
                  <a href={tenantLoginPath(tenantSlug)} className="underline">Sign in</a>
                </>
              )}
            </AuthError>
          )}
          {error && !setupData && (
            <AuthError>{error} — reload this page to request a new enrollment secret.</AuthError>
          )}
          {provisioning && (
            <div className="h-[200px] flex items-center justify-center font-mono text-[11px] text-muted-foreground">
              requesting enrollment secret…
            </div>
          )}
          {setupData && (
            <>
              <div className="flex flex-wrap items-start gap-x-5 gap-y-3 mb-4">
                {/* The QR keeps a real white quiet zone so it scans reliably. */}
                <div className="rounded-[5px] border border-[var(--border-2)] bg-white p-2.5 shrink-0">
                  <img
                    src={`data:image/png;base64,${setupData.qr_code_base64}`}
                    alt="TOTP QR Code"
                    className="w-40 h-40 block"
                  />
                </div>
                <dl className="font-mono text-[11px] leading-[1.8] min-w-0 m-0">
                  {[
                    ['type', 'time-based (TOTP)'],
                    ['algorithm', 'SHA1'],
                    ['digits', '6'],
                    ['period', '30 seconds'],
                    ['issuer', 'nano'],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-2 min-w-0">
                      <dt className="text-[var(--fg-4)] w-[9ch] shrink-0">{k}</dt>
                      <dd className="text-[var(--fg-2)] min-w-0 truncate m-0">{v}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="mb-4">
                <button
                  type="button"
                  onClick={() => setShowSecret((s) => !s)}
                  aria-expanded={showSecret}
                  aria-controls="mfa-manual-secret"
                  className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:text-foreground"
                >
                  <ChevronRight
                    className={cn('w-3 h-3 shrink-0 transition-transform', showSecret && 'rotate-90')}
                    strokeWidth={2}
                  />
                  Can&apos;t scan? Enter the key manually
                </button>
                {showSecret && (
                  <div
                    id="mfa-manual-secret"
                    className="mt-2 h-[38px] px-3 rounded-[5px] bg-card border border-[var(--border-2)] flex items-center gap-2 font-mono text-[13px]"
                  >
                    <code className="text-foreground flex-1 min-w-0 truncate select-all">{setupData.secret}</code>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(setupData.secret);
                        toast({ title: 'Copied', description: 'Setup key copied to clipboard' });
                      }}
                      className="inline-flex items-center gap-1 h-[22px] px-2 rounded border border-[var(--border-2)] text-muted-foreground hover:text-foreground text-[11px] shrink-0 transition-colors"
                    >
                      <Copy className="w-3 h-3" strokeWidth={2} />
                      copy
                    </button>
                  </div>
                )}
              </div>

              <PrimaryButton type="button" onClick={() => setStep('verify')}>
                I&apos;ve added it — enter a code →
              </PrimaryButton>
            </>
          )}
          <AuthFootnote>Keep the app installed. Any RFC 6238 TOTP app works; codes rotate every 30 seconds.</AuthFootnote>
        </>
      )}

      {/* ── Stage 2: verify ───────────────────────────────────────── */}
      {step === 'verify' && (
        <>
          <AuthHeading title="Enter the 6-digit code">
            The code from your authenticator app. It verifies the pairing and turns two-factor on.
          </AuthHeading>
          {error && <AuthError>{error}</AuthError>}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              handleVerify();
            }}
            noValidate
          >
            <Field
              id="mfa-verify-code"
              ref={verifyInputRef}
              label="Authenticator code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="000000"
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              disabled={loading}
              maxLength={6}
              style={{ letterSpacing: '0.35em' }}
              note="submits automatically at 6 digits · rotates every 30 seconds"
            />
            <PrimaryButton type="submit" busy={loading} disabled={verifyCode.length < 6}>
              Verify and enable →
            </PrimaryButton>
          </form>
          <div className="mt-3 flex justify-center">
            <button
              type="button"
              onClick={() => setStep('scan')}
              className="font-mono text-[11px] text-muted-foreground hover:text-foreground"
            >
              ← back to the QR code
            </button>
          </div>
        </>
      )}

      {/* ── Stage 3: recovery codes ───────────────────────────────── */}
      {step === 'backup' && (
        <>
          <AuthHeading title="Save your recovery codes">
            {backupCodes.length} single-use codes, shown once. If you lose the authenticator, these are the only way back in.
          </AuthHeading>
          <div className="rounded-[5px] border border-[var(--border-2)] bg-card px-3 py-2.5 mb-3">
            <ul className="grid grid-cols-2 gap-x-6 gap-y-0.5 m-0 p-0 list-none">
              {backupCodes.map((code, i) => (
                <li key={code} className="flex items-center gap-2 font-mono text-[13px] leading-[1.7]">
                  <span className="text-[var(--fg-4)] tabular-nums select-none shrink-0">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className="text-foreground select-all tracking-[0.06em]">{code}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="flex gap-2 mb-4">
            <SecondaryButton type="button" onClick={copyBackupCodes} className="flex-1">
              <Copy className="w-[15px] h-[15px]" strokeWidth={2} />
              Copy
            </SecondaryButton>
            <SecondaryButton type="button" onClick={downloadBackupCodes} className="flex-1">
              <Download className="w-[15px] h-[15px]" strokeWidth={2} />
              Download
            </SecondaryButton>
          </div>
          <label
            htmlFor="mfa-codes-saved"
            className="flex items-start gap-2.5 cursor-pointer text-[12.5px] text-[var(--fg-2)] leading-snug mb-1"
          >
            <Checkbox
              id="mfa-codes-saved"
              checked={savedConfirmed}
              onCheckedChange={(checked) => setSavedConfirmed(checked === true)}
              className="mt-0.5 h-3.5 w-3.5 shrink-0"
            />
            <span>I have saved these recovery codes in a secure location.</span>
          </label>
          <PrimaryButton type="button" onClick={handleComplete} disabled={!savedConfirmed}>
            {isForced ? 'Done — sign in with your new code →' : 'Done →'}
          </PrimaryButton>
        </>
      )}
    </AuthShell>
  );
}
