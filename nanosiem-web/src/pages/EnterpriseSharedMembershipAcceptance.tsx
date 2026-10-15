// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { CheckCircle2, ShieldAlert } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Logo } from '@/components/ui/logo';
import { useAuth } from '@/contexts/AuthContext';
import { API_BASE_URL } from '@/lib/api/utils';
import { getAccessToken } from '@/lib/auth-token';
import {
  acceptEnterpriseSharedMembership,
  type SharedMembershipAcceptanceBrowserResult,
} from '@/lib/enterprise-shared-membership-acceptance';
import {
  MEMBERSHIP_ACCEPTANCE_PATH,
  acceptanceStep,
  clearInvitation,
  invitationTokenFromFragment,
  readInvitation,
  stashInvitation,
  tenantAcceptancePath,
  type ContinuationStorage,
} from '@/lib/membership-acceptance-continuation';
import { browserTenantRuntime } from '@/lib/tenant-runtime';

const UNIFORM_ERROR = 'The invitation could not be accepted. Invitations accept only from a fresh sign-in (within 5 minutes), and they expire, can be revoked and work once. Sign in again to retry, or ask the admin who invited you for a new invitation.';
const MISSING_ERROR = 'This page needs the full invitation link. Open the link from your invitation again, or ask the admin who invited you to send a new one.';

const NO_STORAGE: ContinuationStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
function tabStorage(): ContinuationStorage {
  try {
    return window.sessionStorage;
  } catch {
    return NO_STORAGE;
  }
}

/**
 * Accept an invitation to another tenant with an existing nano login
 * (NAN-3788). The link has no tenant prefix, so the page first resolves the
 * tenant the user signs in to, signs in there, then accepts with the tab's
 * bearer. The token lives only in this tab (see membership-acceptance-continuation).
 */
export function EnterpriseSharedMembershipAcceptance() {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading, logout } = useAuth();
  const [invitation] = useState<string | null>(() => {
    if (typeof window === 'undefined') return null;
    const storage = tabStorage();
    const fromLink = invitationTokenFromFragment(window.location.hash);
    if (fromLink) stashInvitation(storage, fromLink);
    return fromLink ?? readInvitation(storage);
  });
  const attempted = useRef(false);
  const [result, setResult] = useState<SharedMembershipAcceptanceBrowserResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [leaving, setLeaving] = useState(false);
  const [organization, setOrganization] = useState('');
  const [organizationError, setOrganizationError] = useState<string | null>(null);

  const pathname = typeof window === 'undefined' ? MEMBERSHIP_ACCEPTANCE_PATH : window.location.pathname;
  const step = acceptanceStep({ pathname, hasInvitation: invitation !== null, isLoading, isAuthenticated });

  // Never leave the token in the address bar or history; keep the tenant prefix.
  useEffect(() => {
    if (window.location.hash) {
      window.history.replaceState(window.history.state, '', window.location.pathname);
    }
  }, []);

  useEffect(() => {
    if (step === 'sign-in') {
      // Basename-relative: under `/t/<slug>` this is that tenant's login, and
      // login returns here once the session (and MFA) is established.
      navigate('/login', { replace: true, state: { from: MEMBERSHIP_ACCEPTANCE_PATH } });
      return;
    }
    if (step !== 'accept' || attempted.current || invitation === null) return;
    attempted.current = true;
    setError(null);
    void acceptEnterpriseSharedMembership(`#${invitation}`, {
      runtime: browserTenantRuntime,
      replaceUrl: (path) => window.history.replaceState(window.history.state, '', path),
      randomUuid: () => window.crypto.randomUUID(),
      bearer: getAccessToken,
      acceptancePath: window.location.pathname,
      fetch: ((input: string | URL | Request, init?: RequestInit) =>
        window.fetch(`${API_BASE_URL}${String(input)}`, init)) as typeof globalThis.fetch,
    })
      .then((accepted) => {
        clearInvitation(tabStorage());
        setResult(accepted);
      })
      .catch(() => setError(UNIFORM_ERROR));
  }, [step, invitation, navigate]);

  const chooseOrganization = (event: FormEvent) => {
    event.preventDefault();
    try {
      // A full load: the router's tenant basename is fixed per page load.
      window.location.assign(tenantAcceptancePath(organization));
    } catch {
      setOrganizationError('Enter the organization name exactly as it appears after /t/ in your nano address.');
    }
  };

  const signInAgain = async () => {
    setLeaving(true);
    try {
      // The token stays in this tab; once signed out the page sends the user
      // to this tenant's login, which returns here for a fresh attempt.
      attempted.current = false;
      await logout();
    } catch {
      setError(UNIFORM_ERROR);
    } finally {
      setLeaving(false);
    }
  };

  const signOutAndContinue = async () => {
    if (!result) return;
    setLeaving(true);
    setError(null);
    try {
      // Acceptance itself never changes the source session. This explicit user
      // action ends it before starting a new MFA-bound login for the target.
      await logout();
      // Full load: the target login lives under ANOTHER tenant prefix, which
      // a basename-relative navigate cannot reach.
      window.location.assign(result.targetLogin);
    } catch {
      setError(UNIFORM_ERROR);
      setLeaving(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-background">
      <div className="w-full max-w-md border border-border bg-card p-6 text-center">
        <div className="flex items-center justify-center gap-2 mb-6">
          <Logo className="w-6 h-6" size="small" />
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            nano · tenant invitation
          </span>
        </div>
        {result ? (
          <>
            <CheckCircle2 className="mx-auto h-7 w-7 text-[var(--success)]" />
            <h1 className="mt-4 text-[17px] font-semibold">Membership accepted</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">
              Your access to <span className="font-mono text-foreground">{result.targetTenantSlug}</span>{' '}
              is active. Your current tenant session and credentials were not changed.
            </p>
            <Button className="mt-5 w-full" disabled={leaving} onClick={signOutAndContinue}>
              {leaving && <LoadingIcon className="mr-2 h-4 w-4" />}
              Sign out and continue to tenant
            </Button>
          </>
        ) : step === 'missing' ? (
          <>
            <ShieldAlert className="mx-auto h-7 w-7 text-destructive" />
            <h1 className="mt-4 text-[17px] font-semibold">Invitation unavailable</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">{MISSING_ERROR}</p>
          </>
        ) : error ? (
          <>
            <ShieldAlert className="mx-auto h-7 w-7 text-destructive" />
            <h1 className="mt-4 text-[17px] font-semibold">Invitation not accepted</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">{error}</p>
            <Button className="mt-5 w-full" variant="outline" disabled={leaving} onClick={signInAgain}>
              {leaving && <LoadingIcon className="mr-2 h-4 w-4" />}
              Sign in again and retry
            </Button>
          </>
        ) : step === 'choose-tenant' ? (
          <form onSubmit={chooseOrganization} className="text-left">
            <h1 className="text-center text-[17px] font-semibold">Accept with your nano login</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">
              This invitation adds a tenant to the nano login you already have. Enter the organization you
              sign in to (the name after <span className="font-mono">/t/</span> in your nano address); you will
              sign in there and the invitation is accepted.
            </p>
            <label htmlFor="organization" className="mt-4 block font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground">
              Organization
            </label>
            <Input
              id="organization"
              className="mt-1 font-mono text-[12px]"
              autoComplete="organization"
              autoCapitalize="none"
              spellCheck={false}
              value={organization}
              onChange={(event) => { setOrganization(event.target.value); setOrganizationError(null); }}
              placeholder="acme"
            />
            {organizationError && <p className="mt-1 text-[11px] text-destructive">{organizationError}</p>}
            <Button type="submit" className="mt-4 w-full" disabled={organization.trim() === ''}>
              Continue
            </Button>
            <p className="mt-3 text-[11px] text-muted-foreground">
              No other organization, or no longer able to sign in to it? Ask the admin who invited you to
              delete this invitation and invite you again; you will get a link to set up a new login.
            </p>
          </form>
        ) : (
          <>
            <LoadingIcon className="mx-auto h-7 w-7 text-primary" />
            <h1 className="mt-4 text-[17px] font-semibold">Accepting membership</h1>
            <p className="mt-2 text-[12px] text-muted-foreground">
              Revalidating your current tenant identity and invitation.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
