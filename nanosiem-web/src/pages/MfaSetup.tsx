// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MFA Setup Page — three-step TOTP enrolment wizard.
 *
 * Reached two ways:
 *   1. Forced enrolment after login when the admin requires MFA (no session
 *      yet — auth via mfa_challenge token in the body, see NAN-584).
 *   2. Voluntary enrolment from /settings/user (Bearer-authed).
 *
 * Visual was Wave-18+'d in NAN-585: tighter chrome (no shadcn Card),
 * 10px eyebrow + 22px title, segmented step rail (numbered chips with a
 * progress fill underneath, like the Onboarding wizard), mono everywhere
 * for codes / secrets / backup grid. Buttons drop to h-9 / 12.5px.
 */

import { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  ShieldCheck,
  KeyRound,
  CheckCircle2,
  Copy,
  Download,
  Loader2,
  ArrowLeft,
  ArrowRight,
  ChevronRight,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Logo } from '@/components/ui/logo';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { MfaSetupResponse, MfaSetupCompleteResponse } from '@/lib/api/types';
import { cn } from '@/lib/utils';

type Step = 'scan' | 'verify' | 'backup';

const STEPS: { id: Step; label: string; eyebrow: string }[] = [
  { id: 'scan', label: 'Pair authenticator', eyebrow: '01' },
  { id: 'verify', label: 'Verify code', eyebrow: '02' },
  { id: 'backup', label: 'Save backup codes', eyebrow: '03' },
];

export function MfaSetup() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, challengeToken: ctxChallengeToken, cancelMfa } = useAuth();
  const { toast } = useToast();

  useDocumentTitle('Set Up Two-Factor Authentication');

  // Reached via login bounce (forced) or /settings/user (voluntary).
  const locationState = location.state as { challengeToken?: string; from?: string } | null;
  const challengeToken = ctxChallengeToken ?? locationState?.challengeToken ?? null;
  const isForced = !!challengeToken;
  const returnTo = locationState?.from || '/settings/user';

  const [step, setStep] = useState<Step>('scan');
  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
        const data = await api.auth.setupMfa(challengeToken ?? undefined);
        setSetupData(data);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to start MFA setup';
        setError(message);
        // Allow a retry if the call genuinely failed.
        setupStartedRef.current = false;
      } finally {
        setLoading(false);
      }
    };
    initSetup();
  }, [isAuthenticated, isForced, challengeToken]);

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

  // ── Loading gate ──────────────────────────────────────────────────
  if (loading && !setupData) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--background)' }}>
        <div className="text-center">
          <Loader2 className="w-6 h-6 animate-spin text-primary mx-auto mb-3" />
          <p className="text-[12px] text-muted-foreground">Setting up two-factor authentication…</p>
        </div>
      </div>
    );
  }

  const stepIndex = STEPS.findIndex((s) => s.id === step);
  const progress = ((stepIndex + 1) / STEPS.length) * 100;

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-10"
      style={{ background: 'var(--background)' }}
    >
      <div className="w-full max-w-[520px]">
        {/* Brand mark */}
        <div className="flex items-center gap-2 mb-6">
          <Logo className="w-6 h-6" size="small" />
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-muted-foreground">
            nano · auth
          </span>
        </div>

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-md border border-border bg-card flex items-center justify-center shrink-0">
              <ShieldCheck className="w-[18px] h-[18px] text-primary" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
                Two-factor authentication
              </div>
              <h1 className="text-[22px] font-semibold tracking-[-0.018em] text-foreground leading-tight">
                Set up two-factor auth
              </h1>
            </div>
          </div>

          {isForced ? (
            <div className="rounded-md border border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[color-mix(in_srgb,var(--warning)_8%,transparent)] px-3 py-2 flex items-start gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-[var(--warning)] mt-px shrink-0" />
              <div className="text-[11.5px] text-foreground/85 leading-relaxed">
                Your administrator requires MFA to be enabled on every account. Finish enrolling
                below to complete sign-in.
              </div>
            </div>
          ) : (
            <p className="text-[12px] text-muted-foreground leading-relaxed">
              Add an extra layer of security with a TOTP code from an authenticator app
              (Google Authenticator, Authy, 1Password, etc.).
            </p>
          )}
        </div>

        {/* Step rail — numbered chips + progress underline */}
        <div className="mb-6">
          <div className="grid grid-cols-3 gap-2">
            {STEPS.map((s, i) => {
              const isCurrent = s.id === step;
              const isDone = stepIndex > i;
              return (
                <div
                  key={s.id}
                  className={cn(
                    'flex items-center gap-2 px-2.5 py-2 rounded-md border transition-colors',
                    isCurrent
                      ? 'border-primary/40 bg-primary/[0.06]'
                      : isDone
                      ? 'border-border bg-card'
                      : 'border-border/60 bg-card',
                  )}
                >
                  <div
                    className={cn(
                      'w-5 h-5 rounded-full border flex items-center justify-center text-[10px] font-mono shrink-0',
                      isCurrent
                        ? 'border-primary bg-primary text-[var(--primary-foreground)]'
                        : isDone
                        ? 'border-[var(--success)]/60 bg-[color-mix(in_srgb,var(--success)_18%,transparent)] text-[var(--success)]'
                        : 'border-border text-muted-foreground',
                    )}
                  >
                    {isDone ? <CheckCircle2 className="w-3 h-3" /> : i + 1}
                  </div>
                  <div className="min-w-0">
                    <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/80">
                      {s.eyebrow}
                    </div>
                    <div
                      className={cn(
                        'text-[11.5px] truncate',
                        isCurrent ? 'text-foreground' : 'text-foreground/70',
                      )}
                    >
                      {s.label}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="mt-2 h-[2px] rounded-full bg-border overflow-hidden">
            <div
              className="h-full bg-primary transition-[width] duration-200"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {error && (
          <div className="mb-5 rounded-md border border-destructive/30 bg-destructive/[0.08] px-3 py-2 text-[11.5px] text-destructive font-mono">
            {error}
          </div>
        )}

        {/* Step 1: Scan QR */}
        {step === 'scan' && setupData && (
          <div className="space-y-4">
            <div className="rounded-md border border-border bg-card px-5 py-5 flex flex-col items-center">
              <p className="text-[12px] text-foreground text-center">
                Scan this QR code with your authenticator app
              </p>
              <p className="text-[10.5px] font-mono text-muted-foreground/70 mt-0.5">
                Google Authenticator · Authy · 1Password · Bitwarden
              </p>
              <div className="mt-4 p-3 rounded-md bg-white shadow-[0_8px_24px_rgba(0,0,0,0.35)]">
                <img
                  src={`data:image/png;base64,${setupData.qr_code_base64}`}
                  alt="TOTP QR Code"
                  className="w-44 h-44"
                />
              </div>
              <button
                type="button"
                onClick={() => setShowSecret((s) => !s)}
                className="mt-4 inline-flex items-center gap-1.5 text-[11.5px] text-foreground/85 hover:text-foreground"
              >
                <ChevronRight
                  className={cn('w-3 h-3 transition-transform', showSecret && 'rotate-90')}
                />
                Can't scan? Enter key manually
              </button>
              {showSecret && (
                <div className="mt-3 w-full rounded-md border border-border bg-[var(--card-2)] px-3 py-2 flex items-center gap-2">
                  <span className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                    secret
                  </span>
                  <code className="font-mono text-[12px] text-[var(--str)] flex-1 truncate select-all">
                    {setupData.secret}
                  </code>
                </div>
              )}
            </div>

            <Button
              onClick={() => setStep('verify')}
              size="sm"
              className="w-full h-9 text-[12.5px] font-semibold"
            >
              Continue
              <ArrowRight className="w-3.5 h-3.5 ml-2" />
            </Button>
          </div>
        )}

        {/* Step 2: Verify code */}
        {step === 'verify' && (
          <div className="space-y-4">
            <div className="rounded-md border border-border bg-card px-5 py-5">
              <p className="text-[12px] text-foreground/85 mb-3">
                Enter the 6-digit code from your authenticator app to verify the pairing.
              </p>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input
                  ref={verifyInputRef}
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  value={verifyCode}
                  onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  disabled={loading}
                  className="pl-9 h-10 text-[18px] tracking-[0.4em] font-mono text-center"
                  maxLength={6}
                />
              </div>
              <p className="text-[10.5px] font-mono text-muted-foreground/70 mt-2">
                The code rotates every 30 seconds.
              </p>
            </div>

            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setStep('scan')}
                className="h-9 text-[12.5px]"
              >
                <ArrowLeft className="w-3.5 h-3.5 mr-1.5" />
                Back
              </Button>
              <Button
                onClick={handleVerify}
                disabled={loading || verifyCode.length < 6}
                size="sm"
                className="h-9 text-[12.5px] font-semibold flex-1"
              >
                {loading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" />
                ) : (
                  <ShieldCheck className="w-3.5 h-3.5 mr-2" />
                )}
                Verify
              </Button>
            </div>
          </div>
        )}

        {/* Step 3: Backup codes */}
        {step === 'backup' && (
          <div className="space-y-4">
            <div className="rounded-md border border-border bg-card px-5 py-5">
              <div className="flex items-start gap-2 mb-3">
                <KeyRound className="w-3.5 h-3.5 text-[var(--warning)] mt-0.5 shrink-0" />
                <div>
                  <p className="text-[12.5px] font-medium text-foreground">Save your backup codes</p>
                  <p className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed">
                    If you lose access to your authenticator app, use these one-time codes to sign
                    in. Each code can only be used once.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-1.5 mt-3">
                {backupCodes.map((code, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-border bg-[var(--card-2)] px-2.5 py-1.5 font-mono text-[11.5px] text-center text-foreground"
                  >
                    {code}
                  </div>
                ))}
              </div>

              <div className="flex gap-2 mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={copyBackupCodes}
                  className="h-8 text-[11.5px] flex-1"
                >
                  <Copy className="w-3 h-3 mr-1.5" />
                  Copy
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={downloadBackupCodes}
                  className="h-8 text-[11.5px] flex-1"
                >
                  <Download className="w-3 h-3 mr-1.5" />
                  Download
                </Button>
              </div>
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer px-1">
              <input
                type="checkbox"
                checked={savedConfirmed}
                onChange={(e) => setSavedConfirmed(e.target.checked)}
                className="mt-0.5 rounded border-border"
              />
              <span className="text-[11.5px] text-foreground/85 leading-snug">
                I have saved these backup codes in a secure location.
              </span>
            </label>

            <Button
              onClick={handleComplete}
              disabled={!savedConfirmed}
              size="sm"
              className="w-full h-9 text-[12.5px] font-semibold"
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-2" />
              Done
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
