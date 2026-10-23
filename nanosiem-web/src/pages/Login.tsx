// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Login page — terminal aesthetic
 *
 * Port of `design-ref/login-terminal.html` + `design-ref/shadcn/login-terminal.jsx`
 * (zip 14 / design system 13). The visual is a fake terminal session running an
 * `auth login --interactive` wizard inside the redesigned app chrome (collapsed
 * rail, breadcrumb topbar, right inspector, bottom status bar). The authentication
 * is real — `login()` / `verifyMfa()` from `AuthContext`. Only the presentation
 * is theatrical.
 *
 * What's wired to real data:
 *   - Release version → `__APP_VERSION__` (vite.define from package.json)
 *   - Email + password submit → `login(email, password)` from AuthContext
 *   - 6-digit TOTP / backup code → `verifyMfa(code)` from AuthContext
 *   - MFA setup-required redirect to `/mfa-setup`
 *   - SSO providers fetched from `/api/auth/oidc/providers` and offered in the
 *     primary column directly under the prompt, plus an `sso` prompt command.
 *     They deliberately do NOT live in the inspector: that panel is
 *     `hidden lg:flex`, so SSO was unreachable below the lg breakpoint
 *     (NAN-2179). Presentation state lives in `login-auth-methods.ts`.
 *
 * What's intentionally NOT exposed:
 *   - Last-login user / IP / "from" location lines from the mockup. Pre-auth
 *     we don't surface other accounts' identity or any session-history hint.
 *
 * Mostly visual flair (boot lines, status chips, trust marks, keyboard hints,
 * MTTR / events-per-second numbers) matches the mockup. They're cosmetic — no
 * backend probes feed them and that's OK; they live on a pre-auth page.
 */

import { useState, useEffect, useRef, FormEvent, KeyboardEvent } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { RefreshCw, Check, ArrowUpRight } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { getSsoIcon } from '@/enterprise/components/icons/SsoIcons';
import { useAuth, OidcProvider } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { cn } from '@/lib/utils';
import { safeReturnPath } from '@/lib/tenant-auth-shell';
import { authenticatedFetch } from '@/lib/authenticated-fetch';
import {
  discoverEnterpriseSharedLoginMethods,
  startEnterpriseSharedOidcLogin,
  type SharedLoginMethods,
  type SharedOidcBrowserDependencies,
} from '@/lib/enterprise-shared-oidc';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import {
  AuthTerminalFrame,
  InspectorPanel,
  InspectorSection,
  KeyboardInspectorSection,
  PromptCard,
  PromptCardHeader,
  TenantInspectorSection,
  TermGroup,
  TermLine,
  WelcomeBanner,
  type StatusLine,
} from './auth-terminal-chrome';
import {
  SSO_PANEL_CLASS,
  authMethodsLine,
  parseSsoCommand,
  resolveLoginMode,
  resolveSsoSurface,
  resolveSsoTarget,
  showPasswordPrompt,
  showSsoPanel,
  type SsoSurface,
} from './login-auth-methods';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

function sharedOidcDependencies(): SharedOidcBrowserDependencies {
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

/**
 * One provider discovery per tenant per page visit. The login route remounts
 * more than once while auth boots (and twice more under StrictMode), and the
 * shared discovery answers a uniform 401 for a tenant without SSO — four
 * identical 401s per visit on the live lake. A settled promise is reused;
 * the "retry" affordance drops the entry first.
 */
const tenantProviderDiscovery = new Map<string, { at: number; pending: Promise<SharedLoginMethods> }>();
const TENANT_PROVIDER_DISCOVERY_TTL_MS = 60_000;

function discoverTenantLoginMethodsOnce(tenantSlug: string, fresh: boolean): Promise<SharedLoginMethods> {
  const cached = tenantProviderDiscovery.get(tenantSlug);
  if (!fresh && cached && Date.now() - cached.at < TENANT_PROVIDER_DISCOVERY_TTL_MS) {
    return cached.pending;
  }
  const pending = discoverEnterpriseSharedLoginMethods(tenantSlug, sharedOidcDependencies());
  tenantProviderDiscovery.set(tenantSlug, { at: Date.now(), pending });
  pending.catch(() => tenantProviderDiscovery.delete(tenantSlug));
  return pending;
}

type Step = 'email' | 'password' | 'mfa' | 'done';

type LineKind = 'cmd' | 'sys' | 'err' | 'warn' | 'good' | 'hint' | 'help';

interface CmdPayload {
  prompt: string;
  cmd: string;
}

interface Line {
  id: string;
  kind: LineKind;
  text: string | CmdPayload | null;
}

let lineCounter = 0;
const makeLine = (kind: LineKind, text: Line['text']): Line => ({
  id: `l-${++lineCounter}`,
  kind,
  text,
});

function CmdEcho({ prompt, cmd }: CmdPayload) {
  return (
    <div className="flex items-start gap-2 font-mono text-[12.5px] leading-[1.6]">
      <span className="text-muted-foreground/60 select-none shrink-0 whitespace-nowrap">{prompt}</span>
      <span className="text-primary select-none shrink-0">$</span>
      <span className="flex-1 min-w-0 break-words text-foreground">{cmd}</span>
    </div>
  );
}

function HelpCard({ ssoAvailable }: { ssoAvailable: boolean }) {
  const rows: [string, string][] = [
    ['help · ?', 'show this table'],
    ['back', 'step back one prompt'],
    ['clear', 'clear scrollback'],
    ['^C', 'abort current prompt'],
  ];
  // Only advertised when the tenant actually has providers — listing a command
  // that always answers "none configured" is noise on a password-only tenant.
  if (ssoAvailable) {
    rows.splice(1, 0, ['sso', 'list single sign-on providers']);
    rows.splice(2, 0, ['sso <name>', 'continue with that provider']);
  }
  return (
    <div
      className="my-1.5 ml-[9ch] rounded-md border border-border px-3 py-2.5 max-w-[78ch]"
      style={{ background: 'var(--card-2)' }}
    >
      <div className="font-mono text-[10.5px] text-muted-foreground uppercase tracking-[0.14em] mb-1.5">
        commands
      </div>
      <div className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 font-mono text-[11.5px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <span className="text-foreground">{k}</span>
            <span className="text-muted-foreground">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Inspector({ ssoEnabled }: { ssoEnabled: boolean }) {
  return (
    <InspectorPanel>
      <TenantInspectorSection />

      {/*
        No SSO section here. Provider actions live in the primary column beside
        the prompt (NAN-2179) — this panel is `hidden lg:flex`, so anything that
        only appears here is unreachable below the lg breakpoint.
      */}

      <KeyboardInspectorSection
        rows={[
          ['enter', 'submit'],
          ['^C', 'abort'],
          ['^L', 'clear'],
          ['?', 'help'],
        ]}
      />

      <InspectorSection title="commands">
        <div className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 font-mono text-[10.5px]">
          {[
            ['help', 'show help'],
            ...(ssoEnabled ? [['sso', 'list providers']] : []),
            ['back', 'prev prompt'],
            ['clear', 'clear log'],
          ].map(([k, v]) => (
            <div key={k} className="contents">
              <span className="text-foreground whitespace-nowrap">{k}</span>
              <span className="text-muted-foreground whitespace-nowrap truncate">{v}</span>
            </div>
          ))}
        </div>
      </InspectorSection>
    </InspectorPanel>
  );
}

export function Login({ tenantSlug }: { tenantSlug?: string } = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    login,
    loginWithOidc,
    isAuthenticated,
    isLoading: authLoading,
    error: authError,
    clearError,
    mfaPending,
    mfaSetupPending,
    challengeToken,
    verifyMfa,
    cancelMfa,
    user,
    pendingTenantSlug,
  } = useAuth();

  useDocumentTitle('Login');

  // SSO/OIDC is enterprise-only (NAN-745). Open builds skip the providers
  // fetch, hide the inspector SSO panel, and drop the email-step "or use SSO"
  // hint — local credentials remain the only auth path.
  const { capabilities } = useCapabilities();
  // A canonical shared tenant URL uses the server-owned tenant-local discovery
  // contract. Dedicated/open-core keep the existing capability-gated global
  // provider endpoint unchanged.
  const ssoEnabled = tenantSlug !== undefined || capabilities.sso;

  const version = __APP_VERSION__;

  const [step, setStep] = useState<Step>('email');
  const [email, setEmail] = useState('');
  const [, setPassword] = useState('');
  const [draft, setDraft] = useState('');
  const [history, setHistory] = useState<Line[]>([]);
  const [busy, setBusy] = useState(false);
  const [oidcProviders, setOidcProviders] = useState<OidcProvider[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(true);
  // Distinguishes "endpoint unreachable" from "no providers configured". These
  // used to collapse into the same empty array, so a broken SSO backend was
  // presented as a tenant that had simply never enabled SSO.
  const [providersFailed, setProvidersFailed] = useState(false);
  const [providersReload, setProvidersReload] = useState(0);
  const [ssoLoading, setSsoLoading] = useState<string | null>(null);
  // NAN-2181: null until `/api/auth/methods` answers. Deliberately not
  // defaulted to true — an optimistic default renders a password prompt on
  // every load of an SSO-only tenant, which is the exact thing the setting
  // exists to remove.
  const [localPasswordEnabled, setLocalPasswordEnabled] = useState<boolean | null>(null);
  // Per-session counter for password attempts. Resets when the user goes
  // back to the email step or successfully authenticates. Drives the
  // attempts chip under the password prompt + the escalating hint copy
  // ("check caps lock", then "consider a password reset").
  const [attempts, setAttempts] = useState(0);

  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  // True once the terminal has rendered for the first time. After that we
  // never replace the page with the global auth spinner — the input's
  // own busy indicator covers in-flight login() / verifyMfa() calls.
  const terminalShownRef = useRef(false);

  const sessionExpired = (location.state as { sessionExpired?: boolean })?.sessionExpired;

  // Single source of truth for every SSO presentation decision on this page.
  const ssoSurface: SsoSurface = resolveSsoSurface({
    ssoEnabled,
    loading: loadingProviders,
    failed: providersFailed,
    providers: oidcProviders,
  });
  const ssoProviders = ssoSurface.kind === 'providers' ? ssoSurface.providers : [];

  // NAN-2181: whether this tenant offers the password wizard at all.
  const loginMode = resolveLoginMode({
    localPassword: localPasswordEnabled,
    sso: ssoSurface,
  });
  const passwordPromptVisible = showPasswordPrompt(loginMode);

  const prompt =
    step === 'email'
      ? 'nano@auth:~$'
      : step === 'password'
      ? 'nano@auth:~$'
      : step === 'mfa'
      ? 'nano@auth/mfa:~$'
      : 'nano@auth:~$';

  // ── Effects ────────────────────────────────────────────────────────
  useEffect(() => {
    if (isAuthenticated && !authLoading) {
      // A shared-lake tenant lands in the product like everyone else; the
      // `/t/<slug>` shell is gone (see ProductRouteGate).
      const returnTo = safeReturnPath((location.state as { from?: string })?.from);
      navigate(returnTo, { replace: true });
    }
  }, [isAuthenticated, authLoading, navigate, location.state, user]);

  // Fetch OIDC providers once. Skipped in open-core builds (no SSO surface).
  useEffect(() => {
    if (!ssoEnabled) {
      setLoadingProviders(false);
      return;
    }
    let cancelled = false;
    setLoadingProviders(true);
    setProvidersFailed(false);
    // A tenant URL learns both answers (providers + whether password sign-in
    // is on) from the one uniform tenant-local discovery call (NAN-2361 wave
    // 8); the dedicated page keeps its two endpoints.
    const providersRequest = tenantSlug === undefined
      ? authenticatedFetch('/api/auth/oidc/providers', `${API_BASE_URL}/api/auth/oidc/providers`).then(async (res) => {
          if (!res.ok) throw new Error(`providers request failed: ${res.status}`);
          return { providers: (await res.json()) as OidcProvider[], localPasswordEnabled: null };
        })
      : discoverTenantLoginMethodsOnce(tenantSlug, providersReload > 0);
    providersRequest
      .then(({ providers, localPasswordEnabled }) => {
        if (cancelled) return;
        setOidcProviders(providers);
        if (localPasswordEnabled !== null) setLocalPasswordEnabled(localPasswordEnabled);
      })
      .catch(() => {
        // Never blocks sign-in: local credentials remain available, and the
        // panel says so rather than silently pretending SSO isn't configured.
        // On a tenant URL this is also the NAN-2181 fallback: a failed
        // discovery falls back to a password prompt, and the server still
        // rejects the credentials if the tenant really is SSO-only.
        if (!cancelled) {
          setOidcProviders([]);
          setProvidersFailed(true);
          if (tenantSlug !== undefined) setLocalPasswordEnabled(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingProviders(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ssoEnabled, providersReload, tenantSlug]);

  // NAN-2181: which methods this deployment accepts. Public endpoint — the page
  // has to know before anyone authenticates. A failure falls back to enabled,
  // because the alternative is a login page offering nothing at all; the server
  // still rejects the credentials if the tenant really is SSO-only.
  useEffect(() => {
    // A tenant URL is answered by the discovery effect above (stays null
    // until it settles, so an SSO-only tenant never flashes the prompt).
    if (tenantSlug !== undefined) return;
    let cancelled = false;
    authenticatedFetch('/api/auth/methods', `${API_BASE_URL}/api/auth/methods`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`auth methods request failed: ${res.status}`);
        return (await res.json()) as { localPassword: boolean };
      })
      .then((methods) => {
        if (!cancelled) setLocalPasswordEnabled(methods.localPassword);
      })
      .catch(() => {
        if (!cancelled) setLocalPasswordEnabled(true);
      });
    return () => {
      cancelled = true;
    };
  }, [providersReload, tenantSlug]);

  // When the AuthContext flips MFA-pending, jump our wizard to the mfa step.
  useEffect(() => {
    if (mfaPending) setStep('mfa');
  }, [mfaPending]);

  // MFA setup-required redirect (preserve legacy behavior).
  useEffect(() => {
    if (mfaSetupPending && challengeToken) {
      // Basename-relative: under `/t/<slug>` this is `/t/<slug>/mfa-setup`.
      navigate(
        '/mfa-setup',
        {
          state: {
            challengeToken,
            from: safeReturnPath((location.state as { from?: string })?.from),
            tenantSlug: pendingTenantSlug ?? tenantSlug,
          },
        },
      );
    }
  }, [mfaSetupPending, challengeToken, navigate, location.state, pendingTenantSlug, tenantSlug]);

  // Echo a sessionExpired notice + auth errors into the terminal scroll.
  // Lives in an effect so the scroll order matches user-perceived time.
  useEffect(() => {
    if (sessionExpired) {
      setHistory((h) => [
        ...h,
        makeLine('warn', 'session expired · please re-authenticate'),
      ]);
      // Clear the location state so a refresh doesn't repeat the line.
      navigate(location.pathname, { replace: true, state: {} });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionExpired]);

  // Backstop auto-push for auth errors that didn't come through the
  // password submit path (SSO, OIDC redirect failures, etc.). The
  // password path pushes its own richer line + attempt count + hints,
  // and clears `authError` after handling so this effect stays silent
  // for that flow.
  useEffect(() => {
    if (!authError) return;
    setHistory((h) => [...h, makeLine('err', `× ${authError}`)]);
    setBusy(false);
  }, [authError]);

  // Focus input when step changes; scroll to bottom on new lines.
  useEffect(() => {
    inputRef.current?.focus();
  }, [step]);
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history, step]);

  // ── Boot lines ─────────────────────────────────────────────────────
  // Active config locks `skipBoot: true` per
  // design_handoff_login_terminal/README.md — welcome banner sits directly
  // above the prompt with no `auth login --interactive` preamble.
  const bootLines = useRef<Line[]>([]);

  // ── Submit handlers ────────────────────────────────────────────────
  const pushLines = (...lines: Line[]) => setHistory((h) => [...h, ...lines]);

  const submitEmail = (val: string) => {
    pushLines(makeLine('cmd', { prompt, cmd: `email: ${val}` }));
    if (!/.+@.+\..+/.test(val)) {
      pushLines(makeLine('err', '× invalid email format'));
      return;
    }
    setEmail(val);
    setAttempts(0); // Fresh identity → fresh attempt budget.
    // States the tenant's configured methods. The previous line claimed
    // `provider resolved: local-password`, which read as per-account provider
    // discovery even though no lookup happens here (NAN-2179).
    pushLines(makeLine('sys', authMethodsLine(ssoSurface)));
    setStep('password');
  };

  const submitPassword = async (val: string) => {
    pushLines(
      makeLine('cmd', { prompt, cmd: `password: ${'•'.repeat(Math.max(10, val.length))}` }),
    );
    if (val.length < 1) {
      pushLines(makeLine('err', '× password required'));
      return;
    }
    setPassword(val);
    setBusy(true);
    clearError();
    try {
      await login(email, val, tenantSlug);
      // login() resolves before MFA state flips on AuthContext when MFA is
      // required; the mfaPending effect above transitions us to the mfa
      // step. When no MFA is set up, we'll get redirected by the
      // isAuthenticated effect.
      setAttempts(0);
      pushLines(makeLine('good', '✓ credentials accepted'));
    } catch (err) {
      // Push a richer feedback line in place of the auto-effect. Cap the
      // displayed counter at 5 (server still owns lockout policy).
      const message = err instanceof Error ? err.message : 'Invalid email or password';
      const next = Math.min(attempts + 1, 5);
      setAttempts(next);
      // Suppress the auto-push effect so the row isn't doubled.
      clearError();
      const followups: Line[] = [];
      if (next === 1) {
        followups.push(
          makeLine(
            'hint',
            ssoProviders.length > 0
              ? 'check caps lock and confirm the email is correct · or continue with single sign-on below'
              : 'check caps lock and confirm the email is correct',
          ),
        );
      } else if (next >= 3) {
        followups.push(
          makeLine(
            'warn',
            '  consider resetting your password if this keeps happening',
          ),
        );
      }
      pushLines(
        makeLine('err', `× ${message} · attempt ${next} of 5`),
        ...followups,
      );
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async (val: string) => {
    const code = val.replace(/\s/g, '');
    pushLines(makeLine('cmd', { prompt, cmd: `code: ${code}` }));
    if (!code) {
      pushLines(makeLine('err', '× code required'));
      return;
    }
    setBusy(true);
    clearError();
    try {
      await verifyMfa(code);
      pushLines(makeLine('good', '✓ mfa verified'));
      pushLines(makeLine('sys', '→ redirecting…'));
      setStep('done');
    } catch {
      // authError effect echoes the message.
    } finally {
      setBusy(false);
    }
  };

  const handleSsoClick = async (slug: string) => {
    setSsoLoading(slug);
    clearError();
    pushLines(makeLine('sys', `→ launching SSO handoff · ${slug}`));
    try {
      if (tenantSlug === undefined) {
        await loginWithOidc(slug, safeReturnPath((location.state as { from?: string })?.from));
      } else {
        const authorizeUrl = await startEnterpriseSharedOidcLogin(
          tenantSlug,
          slug,
          sharedOidcDependencies(),
          safeReturnPath((location.state as { from?: string })?.from),
        );
        window.location.assign(authorizeUrl);
      }
    } catch {
      setSsoLoading(null);
    }
  };

  // Global commands available at every prompt.
  const handleGlobalCommand = (lower: string, raw: string): boolean => {
    if (lower === 'help' || lower === '?') {
      pushLines(makeLine('cmd', { prompt, cmd: raw }), makeLine('help', null));
      return true;
    }
    if (lower === 'clear' || lower === 'cls') {
      setHistory([]);
      return true;
    }
    // `sso` / `sso <slug|index>` — keeps the SSO route reachable without
    // leaving the prompt, for keyboard-only use.
    const ssoCommand = parseSsoCommand(raw);
    if (ssoCommand) {
      pushLines(makeLine('cmd', { prompt, cmd: raw }));
      // Gated on the same steps as the panel. Without this the command could
      // hand off to an IdP mid-MFA and abandon a live challenge — exactly what
      // withholding the panel at that step is meant to prevent.
      if (!showSsoPanel(step)) {
        pushLines(
          makeLine('warn', 'single sign-on is unavailable at this prompt · press ^C to start over'),
        );
        return true;
      }
      if (ssoSurface.kind === 'loading') {
        pushLines(makeLine('sys', '→ still checking configured providers · try again shortly'));
        return true;
      }
      if (ssoProviders.length === 0) {
        pushLines(
          makeLine(
            'warn',
            ssoSurface.kind === 'error'
              ? 'sso providers could not be loaded · continue with email + password'
              : 'no sso providers configured · continue with email + password',
          ),
        );
        return true;
      }
      if (ssoCommand.kind === 'list') {
        pushLines(
          makeLine('sys', '→ configured providers · run `sso <name>` to continue'),
          ...ssoProviders.map((p, i) =>
            makeLine('sys', `  [${i + 1}] ${p.slug} · ${p.name}`),
          ),
        );
        return true;
      }
      const target = resolveSsoTarget(ssoCommand.target, ssoProviders);
      if (!target) {
        pushLines(
          makeLine('err', `× unknown provider: ${ssoCommand.target}`),
          makeLine('hint', 'run `sso` to list configured providers'),
        );
        return true;
      }
      void handleSsoClick(target.slug);
      return true;
    }
    if (lower === 'back') {
      pushLines(makeLine('cmd', { prompt, cmd: raw }));
      if (step === 'password') {
        setStep('email');
        setPassword('');
      } else if (step === 'mfa') {
        cancelMfa();
        setStep('email');
        setEmail('');
        setPassword('');
        pushLines(makeLine('sys', '→ stepping back to identity'));
      } else {
        pushLines(makeLine('warn', 'nothing to go back to'));
      }
      return true;
    }
    return false;
  };

  const onSubmitDraft = (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const raw = draft.trim();
    if (!raw) return;
    setDraft('');
    const lower = raw.toLowerCase();
    if (handleGlobalCommand(lower, raw)) return;
    if (step === 'email') return submitEmail(raw);
    if (step === 'password') return submitPassword(raw);
    if (step === 'mfa') return submitMfa(raw);
  };

  // ^C — restart the wizard from scratch. There's no inline edit on a
  // submitted line in a real terminal, so this is the analyst's escape
  // hatch when they realize they typed the wrong email two prompts ago.
  // Drops every per-session field, clears any MFA challenge that may
  // have been issued, wipes scrollback, and lands back on the email
  // prompt. ^L preserved as the simpler "just clear the scroll" command.
  const resetSession = () => {
    setHistory([
      makeLine('warn', '^C · session reset · starting over'),
    ]);
    setStep('email');
    setEmail('');
    setPassword('');
    setDraft('');
    setAttempts(0);
    setBusy(false);
    clearError();
    // If we got bounced into the MFA flow before the reset, clear the
    // AuthContext challenge state too so a fresh email submit starts
    // from the same baseline as a brand-new tab.
    if (mfaPending || mfaSetupPending || challengeToken) {
      cancelMfa();
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) {
      e.preventDefault();
      resetSession();
    } else if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      setHistory([]);
    }
  };

  const renderLine = (line: Line) => {
    if (line.kind === 'cmd' && line.text && typeof line.text === 'object') {
      return <CmdEcho key={line.id} {...(line.text as CmdPayload)} />;
    }
    if (line.kind === 'help') {
      return <HelpCard key={line.id} ssoAvailable={ssoProviders.length > 0} />;
    }
    return (
      <TermGroup key={line.id}>
        <TermLine kind={line.kind as Exclude<LineKind, 'cmd' | 'help'>}>
          {String(line.text ?? '')}
        </TermLine>
      </TermGroup>
    );
  };

  const activePromptLabel =
    step === 'email' ? 'email: ' : step === 'password' ? 'password: ' : step === 'mfa' ? 'code: ' : '';
  const placeholder =
    step === 'email' ? 'you@company.co' : step === 'password' ? '' : step === 'mfa' ? '000000' : '';
  const isPassword = step === 'password';
  // Per-prompt identity of the one wizard input, in the shape password
  // managers key on (NAN-3146): a real `type="password"` field with
  // `current-password`, a `username` field before it, and `one-time-code`
  // for the MFA prompt. The email prompt stays `type="text"` (with an email
  // keyboard) because it also accepts commands like `help` / `sso`, which
  // native `type="email"` validation would block from submitting.
  const inputField =
    step === 'email'
      ? { type: 'text', inputMode: 'email', name: 'username', id: 'username', autoComplete: 'username' } as const
      : step === 'password'
      ? { type: 'password', name: 'password', id: 'password', autoComplete: 'current-password' } as const
      : step === 'mfa'
      ? { type: 'text', inputMode: 'numeric', name: 'otp', id: 'otp', autoComplete: 'one-time-code' } as const
      : null;

  // Step indicator chip values match design_handoff_login_terminal/README.md
  // (active config "anchored"). Email = [1/3] IDENTIFY, password = [2/3]
  // VERIFY, mfa = [3/3] MFA CHALLENGE.
  const stepIndicator =
    step === 'email'
      ? { num: '[1/3]', label: 'IDENTIFY' }
      : step === 'password'
      ? { num: '[2/3]', label: 'VERIFY' }
      : step === 'mfa'
      ? { num: '[3/3]', label: 'MFA CHALLENGE' }
      : null;

  // Breadcrumb + status-bar copy for the shared pre-auth chrome. Same values
  // the page rendered inline before the chrome was extracted.
  const breadcrumbStep =
    step === 'email'
      ? 'identify'
      : step === 'password'
      ? 'verify'
      : step === 'mfa'
      ? 'mfa challenge'
      : 'established';
  const stepStatusLabel = {
    email: 'awaiting identity',
    password: 'awaiting password',
    mfa: 'awaiting mfa · 6-digit code',
    done: 'session established',
  }[step];
  const status: StatusLine = authError
    ? { label: 'auth failed · retry', tone: 'error' }
    : { label: stepStatusLabel, tone: step === 'done' ? 'done' : 'active' };

  // ── Authenticating-loader gate ────────────────────────────────────
  // Only show the full-page spinner during the *initial* auth probe (when
  // AuthContext is calling /api/auth/me on first mount and we don't yet
  // know whether the user is logged in). Once the terminal has rendered
  // once, subsequent `authLoading=true` cycles come from the in-flight
  // `login()` call — those need to stay inline on the prompt's busy
  // indicator. Otherwise the screen flashes spinner → terminal between
  // submitting password and the MFA-code prompt appearing. The
  // `terminalShownRef` flips on the first non-loading render and
  // suppresses the spinner forever after.
  if (authLoading && !terminalShownRef.current) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--background)' }}>
        <LoadingIcon className="w-6 h-6 text-primary" />
      </div>
    );
  }
  terminalShownRef.current = true;

  return (
    <AuthTerminalFrame
      version={version}
      trail={[{ label: 'auth' }, { label: breadcrumbStep }]}
      tab={{ label: 'auth login', sublabel: 'interactive' }}
      status={status}
      inspector={<Inspector ssoEnabled={ssoEnabled} />}
      scrollRef={scrollRef}
      onScrollClick={() => inputRef.current?.focus()}
    >
      <WelcomeBanner version={version}>
        Welcome to nano. Authenticated sessions are logged and tied to your identity for audit.
        Type <span className="text-foreground/85">help</span> for commands ·{' '}
        <span className="text-foreground/85">^C</span> to abort at any prompt.
      </WelcomeBanner>

      {bootLines.current.map((l) => renderLine(l))}
      {history.map((l) => renderLine(l))}

      {step !== 'done' && passwordPromptVisible && (
        <div className="pt-1">
          {/*
            Anchored prompt — design_handoff_login_terminal/README.md
            "anchored" treatment. Bordered card + brand-tinted header
            strip (status + path + step indicator) over the input row.
          */}
          <PromptCard>
            <PromptCardHeader
              caption="awaiting input"
              prompt={prompt}
              stepIndicator={stepIndicator}
            />
            <form
              onSubmit={onSubmitDraft}
              className="px-2.5 py-1.5 flex items-center gap-2 font-mono text-[12.5px] leading-none"
            >
              <span className="text-primary select-none shrink-0 leading-none">&gt;</span>
              {activePromptLabel && inputField && (
                <label
                  htmlFor={inputField.id}
                  className="text-muted-foreground select-none shrink-0 whitespace-nowrap"
                >
                  {activePromptLabel}
                </label>
              )}
              {/*
                NAN-3146 — password managers associate a saved password with
                the username field of the SAME form. The email prompt is gone
                by the time the password prompt renders, so the identity rides
                along in a visually-hidden (not `hidden` / display:none, which
                managers skip) read-only username field.
              */}
              {(step === 'password' || step === 'mfa') && (
                <input
                  type="text"
                  name="username"
                  autoComplete="username"
                  value={email}
                  readOnly
                  tabIndex={-1}
                  aria-hidden="true"
                  className="sr-only"
                />
              )}
              <div className="relative flex-1 min-w-0 flex items-center">
                {inputField && (
                  <input
                    // A fresh element per prompt, so a manager never sees one
                    // field flip from username to password to one-time code.
                    key={step}
                    ref={inputRef}
                    {...inputField}
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={onKeyDown}
                    maxLength={step === 'mfa' ? 12 : undefined}
                    placeholder={placeholder}
                    autoCapitalize="off"
                    spellCheck={false}
                    disabled={busy}
                    className={cn(
                      'w-full bg-transparent outline-none border-0 text-foreground font-mono text-[12.5px] caret-[var(--primary)]',
                      // Native bullets, spaced like the echo line's `•` run.
                      isPassword && 'tracking-[0.12em]',
                      // Keep the terminal look when a manager fills the field:
                      // no UA autofill background, same foreground colour.
                      '[&:-webkit-autofill]:[-webkit-text-fill-color:var(--foreground)] [&:-webkit-autofill]:[transition:background-color_600000s_0s]',
                    )}
                  />
                )}
                {busy && (
                  <LoadingIcon className="w-3.5 h-3.5 text-muted-foreground absolute right-1" />
                )}
              </div>
              {/*
                NAN-3238 — a real submit button, not a bare <kbd>. Once the
                NAN-3146 username field joins the form on the password / MFA
                steps, the form has two text-like fields, and HTML implicit
                submission (Enter) only fires when a submit button exists.
                Always rendered (also tappable on mobile).
              */}
              <button
                type="submit"
                aria-label="Submit"
                disabled={busy}
                className="inline-flex items-center h-[16px] px-1 rounded-sm border border-border bg-foreground/[0.06] font-mono text-[9.5px] text-muted-foreground shrink-0 hover:text-foreground disabled:opacity-50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              >
                ↵
              </button>
            </form>
          </PromptCard>

          {step === 'email' && (
            <TermGroup>
              <div className="text-muted-foreground/60 text-[10.5px] mt-0.5">
                your work email · type <span className="text-muted-foreground">help</span> for commands
              </div>
            </TermGroup>
          )}
          {step === 'password' && attempts > 0 && (
            <TermGroup>
              <div className="text-[10.5px] mt-0.5 flex items-center gap-1.5">
                <span
                  className={cn(
                    'inline-flex items-center gap-1 h-[16px] px-1.5 rounded-sm border font-mono tabular-nums',
                    attempts >= 3
                      ? 'border-destructive/40 text-destructive bg-destructive/[0.08]'
                      : 'border-[var(--border-2)] text-[var(--warning)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)]',
                  )}
                >
                  attempt {attempts}/5
                </span>
                <span className="text-muted-foreground/60">
                  re-enter your password to try again
                </span>
              </div>
            </TermGroup>
          )}
          {step === 'mfa' && (
            <TermGroup>
              <div className="text-muted-foreground/60 text-[10.5px] mt-0.5">
                open your authenticator · 6-digit TOTP or a backup code
              </div>
            </TermGroup>
          )}

          {/*
            Single sign-on, in the primary column directly under the
            prompt. Previously this lived only in the `hidden lg:flex`
            inspector, which made SSO both visually secondary and
            entirely unreachable below the lg breakpoint (NAN-2179).
          */}
          {showSsoPanel(step) && ssoSurface.kind !== 'hidden' && (
            <div className={SSO_PANEL_CLASS}>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground/70 shrink-0">
                  or single sign-on
                </span>
                <span className="flex-1 h-px bg-border" />
              </div>

              {ssoSurface.kind === 'loading' && (
                <div className="flex items-center gap-2 h-9 px-2.5 rounded-md border border-border bg-card font-mono text-[11px] text-muted-foreground">
                  <LoadingIcon className="w-3.5 h-3.5" />
                  checking configured providers…
                </div>
              )}

              {ssoSurface.kind === 'error' && (
                <div
                  className="flex items-center gap-2 h-9 px-2.5 rounded-md border font-mono text-[11px]"
                  style={{
                    borderColor: 'color-mix(in srgb, var(--warning) 40%, var(--border))',
                    background: 'color-mix(in srgb, var(--warning) 8%, transparent)',
                  }}
                >
                  <span className="text-[var(--warning)] truncate">
                    sso unavailable · email + password still works
                  </span>
                  <span className="flex-1" />
                  <button
                    type="button"
                    onClick={() => setProvidersReload((n) => n + 1)}
                    className="inline-flex items-center gap-1 h-[20px] px-1.5 rounded-sm border border-border text-muted-foreground hover:text-foreground hover:border-[var(--border-2)] text-[10px] shrink-0 transition-colors"
                  >
                    <RefreshCw className="w-3 h-3" />
                    retry
                  </button>
                </div>
              )}

              {ssoSurface.kind === 'providers' && (
                <>
                  <div
                    role="group"
                    aria-label="Single sign-on providers"
                    className="space-y-1.5"
                  >
                    {ssoSurface.providers.map((p, i) => {
                      const Icon = getSsoIcon(p);
                      const launching = ssoLoading === p.slug;
                      return (
                        <button
                          // Keyed by slug, not id: the public
                          // providers endpoint returns only
                          // {slug, name}, so every `p.id` was
                          // undefined. Slug is unique per tenant.
                          key={p.slug}
                          type="button"
                          onClick={() => handleSsoClick(p.slug)}
                          disabled={ssoLoading !== null || busy}
                          aria-label={`Continue with ${p.name}`}
                          aria-busy={launching}
                          className="w-full h-9 rounded-md border border-border bg-card hover:border-[var(--border-2)] hover:bg-[var(--card-2)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--primary)] flex items-center gap-2 px-2.5 text-[11.5px] text-foreground/85 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          <span
                            aria-hidden="true"
                            className="font-mono text-[10px] text-muted-foreground/60 tabular-nums shrink-0"
                          >
                            [{i + 1}]
                          </span>
                          <Icon className="w-4 h-4 text-muted-foreground shrink-0" />
                          <span className="truncate">Continue with {p.name}</span>
                          <span className="flex-1" />
                          {launching ? (
                            <LoadingIcon className="w-3 h-3 text-muted-foreground shrink-0" />
                          ) : (
                            <ArrowUpRight className="w-3 h-3 text-muted-foreground/60 shrink-0" />
                          )}
                        </button>
                      );
                    })}
                  </div>
                  <div className="text-muted-foreground/60 text-[10.5px] mt-1">
                    or type{' '}
                    <span className="text-muted-foreground">
                      sso {ssoSurface.providers[0].slug}
                    </span>{' '}
                    at the prompt
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/*
        NAN-2181 — SSO-only tenants. The password wizard is not
        rendered at all: soliciting credentials the server will refuse
        is worse than not offering them. Providers become the primary
        action, in the same primary column at every viewport width.
      */}
      {step !== 'done' && loginMode.kind === 'loading' && (
        <div className="pt-1 flex items-center gap-2 text-[11.5px] font-mono text-muted-foreground">
          <LoadingIcon className="w-3.5 h-3.5" />
          resolving sign-in methods…
        </div>
      )}

      {step !== 'done' && loginMode.kind === 'ssoOnlyLoading' && (
        <div className="pt-1 flex items-center gap-2 text-[11.5px] font-mono text-muted-foreground">
          <LoadingIcon className="w-3.5 h-3.5" />
          password sign-in is disabled · loading providers…
        </div>
      )}

      {step !== 'done' && loginMode.kind === 'ssoOnly' && (
        <div className="pt-1">
          <TermGroup>
            <div className="text-[11.5px] text-muted-foreground mb-2">
              this organization requires single sign-on · password
              sign-in is disabled
            </div>
          </TermGroup>
          <div className={SSO_PANEL_CLASS}>
            <div
              role="group"
              aria-label="Single sign-on providers"
              className="space-y-1.5"
            >
              {loginMode.providers.map((p, i) => {
                const Icon = getSsoIcon(p);
                const launching = ssoLoading === p.slug;
                return (
                  <button
                    key={p.slug}
                    type="button"
                    onClick={() => handleSsoClick(p.slug)}
                    disabled={ssoLoading !== null}
                    aria-label={`Continue with ${p.name}`}
                    aria-busy={launching}
                    className="w-full h-10 rounded-md border bg-card hover:bg-[var(--card-2)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--primary)] flex items-center gap-2 px-2.5 text-[12.5px] text-foreground disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    style={{
                      borderColor:
                        'color-mix(in srgb, var(--primary) 45%, var(--border))',
                    }}
                  >
                    <span
                      aria-hidden="true"
                      className="font-mono text-[10px] text-muted-foreground/60 tabular-nums shrink-0"
                    >
                      [{i + 1}]
                    </span>
                    <Icon className="w-4 h-4 text-muted-foreground shrink-0" />
                    <span className="truncate">Continue with {p.name}</span>
                    <span className="flex-1" />
                    {launching ? (
                      <LoadingIcon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    ) : (
                      <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {step !== 'done' && loginMode.kind === 'ssoOnlyUnavailable' && (
        <div className="pt-1">
          <TermGroup>
            <div
              className="rounded-md border px-3.5 py-3 max-w-[72ch]"
              style={{
                borderColor: 'color-mix(in srgb, var(--destructive) 40%, transparent)',
                background: 'color-mix(in srgb, var(--destructive) 8%, transparent)',
              }}
            >
              <div className="text-[12.5px] text-foreground font-medium mb-1">
                No sign-in method is available
              </div>
              <div className="text-[11.5px] text-muted-foreground">
                {loginMode.reason === 'error'
                  ? 'Password sign-in is disabled and the SSO providers could not be loaded.'
                  : 'Password sign-in is disabled and no SSO provider is enabled.'}{' '}
                Contact an administrator.
              </div>
              <button
                type="button"
                onClick={() => setProvidersReload((n) => n + 1)}
                className="mt-2 inline-flex items-center gap-1 h-[22px] px-2 rounded-sm border border-border text-muted-foreground hover:text-foreground hover:border-[var(--border-2)] text-[11px] transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                retry
              </button>
            </div>
          </TermGroup>
        </div>
      )}

      {step === 'done' && (
        <div className="mt-2">
          <TermGroup>
            <div
              className="rounded-md border px-3.5 py-3 max-w-[72ch]"
              style={{
                borderColor: 'color-mix(in srgb, var(--success) 40%, transparent)',
                background: 'color-mix(in srgb, var(--success) 9%, transparent)',
              }}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <Check className="w-4 h-4 text-[var(--success)]" />
                <span className="font-sans text-[13px] font-semibold text-foreground">
                  Session established
                </span>
              </div>
              <div className="font-mono text-[11px] text-foreground/85 space-y-0.5">
                <div>
                  <span className="text-muted-foreground/60">identity</span>  {email}
                </div>
                <div>
                  <span className="text-muted-foreground/60">issued</span>{'   '}
                  {new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z'}
                </div>
              </div>
            </div>
          </TermGroup>
        </div>
      )}
    </AuthTerminalFrame>
  );
}
