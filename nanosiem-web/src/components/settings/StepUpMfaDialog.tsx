// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared MFA step-up prompt (NAN-2361 wave 5).
 *
 * The shared step-up admin surfaces (SSO provider administration) require a
 * second factor proven within the last five minutes. Instead of sending the
 * admin back to the sign-in page, this prompt asks for a TOTP code and calls
 * `POST /api/auth/shared/mfa/step-up`, which re-mints the session with a
 * fresh `mfa_time`. `useStepUpMfa()` gives a page one `requestStepUp()` it
 * can await before retrying the refused action.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { KeyRound } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { ApiClientError } from '@/lib/api';

interface StepUpMfaDialogProps {
  open: boolean;
  /** Resolves the pending `requestStepUp()`; `true` when MFA was re-proved. */
  onSettled: (ok: boolean) => void;
}

export function StepUpMfaDialog({ open, onSettled }: StepUpMfaDialogProps) {
  const { stepUpMfa } = useAuth();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setCode('');
    setError(null);
    setBusy(false);
    const t = setTimeout(() => inputRef.current?.focus(), 30);
    return () => clearTimeout(t);
  }, [open]);

  const submit = async () => {
    if (busy || !/^\d{6}$/.test(code)) return;
    setBusy(true);
    setError(null);
    try {
      await stepUpMfa(code);
      onSettled(true);
    } catch (err) {
      setError(err instanceof Error && err.message !== 'Request failed' ? err.message : 'Invalid code — please try again');
      setBusy(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={(v) => { if (!v && !busy) onSettled(false); }}>
      <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border">
        <AlertDialogHeader className="border-b border-border px-5 py-4 space-y-1">
          <AlertDialogTitle className="text-[14px] font-semibold flex items-center gap-2">
            <KeyRound className="w-[14px] h-[14px] text-primary" />
            Confirm it is you
          </AlertDialogTitle>
          <AlertDialogDescription className="text-[11.5px] text-muted-foreground">
            Changing sign-in providers needs a second factor proven in the last five minutes. Enter the six-digit code from your authenticator to continue; your session stays signed in.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="px-5 py-4">
          <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Authenticator code</label>
          <input
            ref={inputRef}
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]*"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            onKeyDown={(e) => { if (e.key === 'Enter') void submit(); }}
            placeholder="000000"
            className="w-full h-8 px-2.5 rounded-md border border-border bg-background font-mono text-[13px] tracking-[0.3em] text-foreground outline-none focus:border-primary/60"
          />
          {error && <div className="text-[10.5px] text-red-500 mt-1.5">{error}</div>}
        </div>
        <AlertDialogFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <Button variant="ghost" size="sm" className="h-8 text-[11.5px]" disabled={busy} onClick={() => onSettled(false)}>Cancel</Button>
          <Button size="sm" className="h-8 text-[11.5px]" disabled={busy || code.length !== 6} onClick={() => void submit()}>
            {busy && <LoadingIcon className="w-3 h-3" />}
            Verify
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** Error code the step-up admin API answers when the session's MFA is stale. */
export const OIDC_ADMIN_DENIED = 'oidc_provider_admin_denied';

export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiClientError && err.status === 403 && err.code === OIDC_ADMIN_DENIED;
}

/**
 * One step-up prompt per page. `run(action)` executes the action; when the
 * API refuses it for stale MFA the prompt opens and, once re-proved, the
 * action is retried exactly once.
 */
export function useStepUpMfa(): {
  run: <T>(action: () => Promise<T>) => Promise<T>;
  dialog: ReactNode;
} {
  const [open, setOpen] = useState(false);
  const pending = useRef<((ok: boolean) => void) | null>(null);

  const requestStepUp = useCallback((): Promise<boolean> => new Promise((resolve) => {
    pending.current = resolve;
    setOpen(true);
  }), []);

  const onSettled = useCallback((ok: boolean) => {
    setOpen(false);
    const resolve = pending.current;
    pending.current = null;
    resolve?.(ok);
  }, []);

  const run = useCallback(async <T,>(action: () => Promise<T>): Promise<T> => {
    try {
      return await action();
    } catch (err) {
      if (!isStepUpRequired(err)) throw err;
      const ok = await requestStepUp();
      if (!ok) throw new Error('Verification was cancelled; no change was made.');
      return await action();
    }
  }, [requestStepUp]);

  return { run, dialog: <StepUpMfaDialog open={open} onSettled={onSettled} /> };
}
