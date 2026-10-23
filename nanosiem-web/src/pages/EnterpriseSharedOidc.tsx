// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useNavigate } from 'react-router-dom';
import { useAuth, type User } from '@/contexts/AuthContext';
import {
  beginEnterpriseSharedOidc,
  completeEnterpriseSharedOidc,
  SsoAdmissionError,
  type SharedOidcBrowserDependencies,
} from '@/lib/enterprise-shared-oidc';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import {
  ALL_COOKIE_SLOTS,
  broadcastSessionInvalidation,
  withBrowserCookieMutationLock,
} from '@/lib/refresh-coordinator';
import { API_BASE_URL } from '@/lib/api/utils';
import { Button } from '@/components/ui/button';

const UNIFORM_ERROR = 'Single sign-on failed. Please try again.';

function browserDependencies(): SharedOidcBrowserDependencies {
  return {
    fetch: ((input: string | URL | Request, init?: RequestInit) => {
      const path = String(input);
      if (!path.startsWith('/api/')) return Promise.reject(new Error('invalid API path'));
      return window.fetch(`${API_BASE_URL}${path}`, init);
    }) as typeof globalThis.fetch,
    sessionStorage: window.sessionStorage,
    runtime: browserTenantRuntime,
    replaceUrl: (path) => window.history.replaceState(window.history.state, '', path),
  };
}

function SharedOidcStatus({ error }: { error: string | null }) {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md border border-border bg-card p-6 text-center">
        {error === null ? (
          <>
            <LoadingIcon className="mx-auto h-7 w-7 text-primary" />
            <h1 className="mt-4 text-[16px] font-semibold text-foreground">Completing sign in</h1>
            <p className="mt-2 font-mono text-[11px] text-muted-foreground">
              verifying tenant identity and access
            </p>
          </>
        ) : (
          <>
            <ShieldAlert className="mx-auto h-7 w-7 text-destructive" />
            <h1 className="mt-4 text-[16px] font-semibold text-foreground">Sign in unavailable</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">{error}</p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-5 h-8 text-[11px]"
              onClick={() => navigate('/login', { replace: true })}
            >
              Return to sign in
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Owner-plane entry landing page. The platform delivers the opaque value only in
 * the fragment (`/auth/shared/oidc/entry#<opaque>`), which is stripped before
 * the first request and never copied to storage.
 */
export function EnterpriseSharedOidcEntry() {
  const started = useRef(false);
  const fragment = useRef(typeof window === 'undefined' ? '' : window.location.hash);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const entryFragment = fragment.current;
    fragment.current = '';
    void beginEnterpriseSharedOidc(entryFragment, browserDependencies())
      .then((authorizeUrl) => window.location.replace(authorizeUrl))
      .catch(() => setError(UNIFORM_ERROR));
  }, []);

  return <SharedOidcStatus error={error} />;
}

/** IdP callback. Only code/state are posted; tokens remain HttpOnly cookies. */
export function EnterpriseSharedOidcCallback() {
  const started = useRef(false);
  const search = useRef(
    new URLSearchParams(typeof window === 'undefined' ? '' : window.location.search),
  );
  const [error, setError] = useState<string | null>(null);
  const { acceptSharedOidcSession, discardFailedSharedOidcSession } = useAuth();

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const callbackQuery = search.current;
    search.current = new URLSearchParams();
    void withBrowserCookieMutationLock(async () => {
      const dependencies = browserDependencies();
      let cookieMutated = false;
      dependencies.onCookieMutation = () => { cookieMutated = true; };
      try {
        const result = await completeEnterpriseSharedOidc(callbackQuery, dependencies);
        // Acceptance emits the credential-free replacement signal while the
        // cookie lock is still held, closing the Set-Cookie/notification gap.
        await acceptSharedOidcSession(
          result.user as unknown as User,
          result.tenant.tenant.slug,
          result.session,
        );
        return result;
      } catch (error) {
        if (cookieMutated) {
          // The browser already accepted the callback's Set-Cookie. Clear that
          // replacement before releasing the origin-wide lock. Cleanup is
          // best effort, but local/broadcast authority is always invalidated.
          try {
            await dependencies.fetch('/api/auth/logout', {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({}),
            });
          } catch {
            // Local and cross-tab invalidation below remains fail closed.
          } finally {
            discardFailedSharedOidcSession();
            broadcastSessionInvalidation('enterprise-shared-oidc-callback-failed', ALL_COOKIE_SLOTS);
          }
        }
        throw error;
      }
    }, { requireCoordination: true })
      .then((result) => {
        // Full load: the destination is under the tenant prefix.
        window.location.assign(result.destination);
      })
      .catch((error: unknown) => setError(error instanceof SsoAdmissionError ? error.message : UNIFORM_ERROR));
  }, [acceptSharedOidcSession, discardFailedSharedOidcSession]);

  return <SharedOidcStatus error={error} />;
}
