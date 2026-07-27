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
import { Loader2, Terminal, RefreshCw, Check, ArrowUpRight } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { getSsoIcon } from '@/enterprise/components/icons/SsoIcons';
import { Logo } from '@/components/ui/logo';
import { useAuth, OidcProvider } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { cn } from '@/lib/utils';
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

// Inline terminal-line renderer. Tone follows the mockup:
//   sys = muted, err = destructive, warn = warning, good = success,
//   hint = italic muted, help = special card render
function TermLine({ kind, children }: { kind: Exclude<LineKind, 'cmd' | 'help'>; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        'font-mono text-[12.5px] leading-[1.6] min-w-0 break-words',
        kind === 'sys' && 'text-foreground/85',
        kind === 'err' && 'text-destructive',
        kind === 'warn' && 'text-[var(--warning)]',
        kind === 'good' && 'text-[var(--success)]',
        kind === 'hint' && 'text-muted-foreground/60 italic',
      )}
    >
      {children}
    </div>
  );
}

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

function TermGroup({ children }: { children: React.ReactNode }) {
  return <div style={{ paddingLeft: '9ch' }}>{children}</div>;
}

// ── Fake telemetry ──────────────────────────────────────────────────
//
// The mockup has a live-tenant feel — events/s + open-cases + MTTR + sensor
// counts that drift every couple of seconds. Pre-auth we have no real
// telemetry to wire, so this is theatre. Stable per-mount baselines + a
// small jitter on the busy values, frozen on the labels.
//
// Things deliberately NOT surfaced (security):
//   - Last-login user / timestamp / IP
//   - Tenant identifier tied to the email being typed
//   - Anything that would help an attacker fingerprint the install
const STATIC_BUILD_HASH = '2a7c91f'; // matches the mockup; cosmetic only.
const STATIC_SIG = 'sha256:2a7c…e91f';
const STATIC_LATENCY_P50 = 34;

interface FakeStats {
  eps: number;
  cases: number;
  mttr: number;
  sensorsUp: number;
  sensorsTotal: number;
}

function useFakeStats(): FakeStats {
  // Stable base on first render — mount-time random within a sensible
  // SOC-ish range. eps drifts via a 1.8s ticker; everything else is fixed
  // for this session. Don't reseed on re-render or the values will jiggle
  // on every state change.
  const baseRef = useRef<FakeStats | null>(null);
  if (!baseRef.current) {
    baseRef.current = {
      eps: 12_700 + Math.floor(Math.random() * 800),
      cases: 47,
      mttr: 14,
      sensorsUp: 312,
      sensorsTotal: 314,
    };
  }
  const [stats, setStats] = useState<FakeStats>(baseRef.current);
  useEffect(() => {
    const id = setInterval(() => {
      setStats((prev) => ({ ...prev, eps: Math.max(8000, prev.eps + (Math.floor(Math.random() * 401) - 200)) }));
    }, 1800);
    return () => clearInterval(id);
  }, []);
  return stats;
}

function useClock(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

function fmtClock(d: Date): string {
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss} UTC`;
}

function WelcomeBanner({ version, stats }: { version: string; stats: FakeStats }) {
  return (
    <div className="mb-4">
      <Logo className="h-6 select-none" size="normal" />
      <div className="mt-3 font-mono text-[11.5px] text-muted-foreground leading-[1.65]">
        <div>
          <span className="text-muted-foreground/60">release</span>{' '}
          <span className="text-foreground/85">v{version}</span>{'   '}
          <span className="text-muted-foreground/60">· build</span>{' '}
          <span className="text-foreground/85">{STATIC_BUILD_HASH}</span>
        </div>
        <div>
          <span className="text-muted-foreground/60">status</span>{'    '}
          <span className="text-[var(--success)]">● operational</span>{'   '}
          <span className="text-muted-foreground/60">· latency p50</span>{' '}
          <span className="text-foreground/85">{STATIC_LATENCY_P50}ms</span>{'   '}
          <span className="text-muted-foreground/60">· events/s</span>{' '}
          <span className="text-foreground/85 tabular-nums">{stats.eps.toLocaleString()}</span>
        </div>
      </div>
      <div
        className="mt-3 font-mono text-[11px] text-muted-foreground/60 leading-[1.55] max-w-[78ch]"
        style={{ textWrap: 'pretty' as React.CSSProperties['textWrap'] }}
      >
        Welcome to nano. Authenticated sessions are logged and tied to your identity for audit.
        Type <span className="text-foreground/85">help</span> for commands ·{' '}
        <span className="text-foreground/85">^C</span> to abort at any prompt.
      </div>
    </div>
  );
}

function Rail() {
  // Collapsed/locked rail per mockup — visual only, matches the rest of the
  // app's left-rail width so the chrome reads as continuous post-login.
  // Uses the real nano Logo so brand identity stays consistent post-login;
  // the mockup's `n + dot` letter-mark was a placeholder.
  return (
    <div
      className="hidden md:flex flex-col border-r border-border shrink-0 w-[44px]"
      style={{ background: 'var(--background)' }}
    >
      <div className="h-[42px] flex items-center justify-center">
        <Logo className="w-5 h-5" size="small" />
      </div>
      <div className="flex-1" />
      <div className="py-2 flex justify-center border-t border-border">
        <button
          className="w-8 h-8 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
          title="Switch tenant"
          type="button"
          disabled
        >
          <RefreshCw className="w-[14px] h-[14px]" />
        </button>
      </div>
    </div>
  );
}

function Topbar({ step, version }: { step: Step; version: string }) {
  const trail = [
    { label: 'auth', mono: false },
    {
      label:
        step === 'email'
          ? 'identify'
          : step === 'password'
          ? 'verify'
          : step === 'mfa'
          ? 'mfa challenge'
          : 'established',
      mono: false,
    },
  ];
  return (
    <div
      className="h-[42px] px-3 flex items-center gap-3 border-b border-border shrink-0"
      style={{ background: 'var(--panel)' }}
    >
      <div className="flex items-center gap-1.5 text-[12px] min-w-0 shrink-0">
        {trail.map((t, i) => (
          <div key={i} className="flex items-center gap-1.5 shrink-0">
            {i > 0 && <span className="text-muted-foreground/60 shrink-0">/</span>}
            <span
              className={cn(
                'whitespace-nowrap shrink-0',
                t.mono && 'font-mono',
                i === trail.length - 1 ? 'text-foreground/85' : 'text-muted-foreground',
              )}
            >
              {t.label}
            </span>
          </div>
        ))}
      </div>
      <span className="flex-1" />
      <div className="hidden sm:flex items-center gap-1.5 text-[11px] shrink-0">
        <span className="h-[22px] inline-flex items-center gap-1.5 px-2 rounded-md border border-border text-muted-foreground font-mono whitespace-nowrap">
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" />
          operational
        </span>
        <span className="h-[22px] inline-flex items-center gap-1.5 px-2 rounded-md border border-border text-muted-foreground font-mono whitespace-nowrap">
          v{version}
        </span>
      </div>
    </div>
  );
}

function StatusBar({
  step,
  version,
  authError,
  stats,
  clock,
}: {
  step: Step;
  version: string;
  authError: string | null;
  stats: FakeStats;
  clock: Date;
}) {
  const stepLabel = {
    email: 'awaiting identity',
    password: 'awaiting password',
    mfa: 'awaiting mfa · 6-digit code',
    done: 'session established',
  }[step];
  return (
    <div
      className="h-[26px] px-3 flex items-center gap-3 border-t border-border font-mono text-[10.5px] text-muted-foreground tracking-[0.02em] shrink-0 whitespace-nowrap overflow-hidden"
      style={{ background: 'var(--panel)' }}
    >
      <span
        className={cn(
          'flex items-center gap-1.5 shrink-0 whitespace-nowrap',
          step === 'done' ? 'text-[var(--success)]' : 'text-primary',
          authError && 'text-destructive',
        )}
      >
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            step === 'done' ? 'bg-[var(--success)]' : 'bg-primary animate-pulse',
            authError && 'bg-destructive',
          )}
        />
        {authError ? 'auth failed · retry' : stepLabel}
      </span>
      <span className="text-muted-foreground/60 shrink-0">·</span>
      <span className="shrink-0 whitespace-nowrap">TLS 1.3 · cert pinned</span>
      <span className="text-muted-foreground/60 shrink-0 hidden xl:inline">·</span>
      <span className="shrink-0 whitespace-nowrap hidden xl:inline">
        sig <span className="text-foreground/85">{STATIC_SIG}</span>
      </span>
      <span className="flex-1" />
      <span className="shrink-0 whitespace-nowrap">
        <span className="text-muted-foreground/60">events/s</span>{' '}
        <span className="text-foreground/85 tabular-nums">{stats.eps.toLocaleString()}</span>
      </span>
      <span className="text-muted-foreground/60 shrink-0">·</span>
      <span className="shrink-0 whitespace-nowrap tabular-nums">{fmtClock(clock)}</span>
      <span className="text-muted-foreground/60 shrink-0">·</span>
      <span className="shrink-0 whitespace-nowrap">
        <span className="text-muted-foreground/60">build</span>{' '}
        <span className="text-foreground/85">v{version}</span>
      </span>
    </div>
  );
}

function StatCell({ k, v, sub }: { k: string; v: string | number; sub: string }) {
  return (
    <div className="px-2.5 py-2">
      <div className="text-[9.5px] font-mono text-muted-foreground uppercase tracking-[0.1em]">{k}</div>
      <div className="text-[15px] font-semibold text-foreground tracking-[-0.01em] tabular-nums mt-0.5">{v}</div>
      <div className="text-[9.5px] font-mono text-muted-foreground/60 mt-0.5">{sub}</div>
    </div>
  );
}

// Hoisted out of Inspector so its identity is stable across re-renders.
// Defining it inside Inspector caused React to treat each tick of the
// useClock / useFakeStats updates (1s / 1.8s) as a new component type
// and remount every Section's subtree — visible as the nano Logo
// flickering under TENANT every second, because Logo's own
// mounted-gate useEffect ran from scratch on each remount.
function InspectorSection({
  title,
  rightSlot,
  children,
}: {
  title: string;
  rightSlot?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-border">
      <div className="px-3 py-2 flex items-center gap-2 whitespace-nowrap">
        <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.14em] whitespace-nowrap">
          {title}
        </span>
        <span className="flex-1" />
        {rightSlot}
      </div>
      <div className="px-3 pb-3">{children}</div>
    </div>
  );
}

function Inspector({ stats, ssoEnabled }: { stats: FakeStats; ssoEnabled: boolean }) {
  const Section = InspectorSection;

  return (
    <div
      className="hidden lg:flex w-[300px] shrink-0 border-l border-border flex-col"
      style={{ background: 'var(--panel)' }}
    >
      <Section title="tenant">
        <div
          className="rounded-md border border-border p-2.5 space-y-1.5"
          style={{ background: 'var(--card)' }}
        >
          <div className="flex items-center gap-2">
            <Logo className="w-7 h-7" size="small" />
            <div className="min-w-0">
              <div className="text-[12.5px] font-semibold text-foreground truncate">nano</div>
              <div className="text-[10.5px] font-mono text-muted-foreground whitespace-nowrap">
                control-plane
              </div>
            </div>
          </div>
          <div className="flex items-center justify-between pt-1 border-t border-border">
            <span className="text-[10.5px] font-mono text-muted-foreground">environment</span>
            <span className="text-[11px] font-mono text-foreground">production</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[10.5px] font-mono text-muted-foreground">release channel</span>
            <span className="text-[11px] font-mono text-foreground">stable</span>
          </div>
        </div>
      </Section>

      <Section
        title="live · tenant metrics"
        rightSlot={<span className="text-[9.5px] font-mono text-muted-foreground/60">tick 1.8s</span>}
      >
        <div
          className="rounded-md border border-border overflow-hidden"
          style={{ background: 'var(--card)' }}
        >
          <div className="grid grid-cols-2 divide-x divide-border">
            <StatCell k="events/s" v={stats.eps.toLocaleString()} sub="rolling 5m" />
            <StatCell k="open cases" v={stats.cases} sub="3 critical" />
          </div>
          <div className="grid grid-cols-2 divide-x divide-border border-t border-border">
            <StatCell k="mttr p50" v={`${stats.mttr}m`} sub="24h" />
            <StatCell
              k="sensors"
              v={`${stats.sensorsUp}/${stats.sensorsTotal}`}
              sub={`${stats.sensorsTotal - stats.sensorsUp} degraded`}
            />
          </div>
        </div>
      </Section>

      {/*
        No SSO section here. Provider actions live in the primary column beside
        the prompt (NAN-2179) — this panel is `hidden lg:flex`, so anything that
        only appears here is unreachable below the lg breakpoint.
      */}

      <Section title="keyboard">
        <div className="space-y-1 font-mono text-[10.5px]">
          {[
            ['enter', 'submit'],
            ['^C', 'abort'],
            ['^L', 'clear'],
            ['?', 'help'],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center justify-between gap-2 whitespace-nowrap">
              <kbd className="px-1.5 py-px rounded bg-foreground/[0.06] text-foreground text-[10px] border border-border shrink-0">
                {k}
              </kbd>
              <span className="text-muted-foreground shrink-0">{v}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="commands">
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
      </Section>

      <div className="px-3 py-3 mt-auto">
        <div className="text-[10px] font-mono text-muted-foreground/60 uppercase tracking-[0.14em] mb-1.5">
          trust
        </div>
        <div className="flex flex-wrap gap-1">
          {['SOC 2 · Type II', 'ISO 27001', 'HIPAA', 'FedRAMP Mod'].map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 rounded border border-border text-[10px] font-mono text-muted-foreground whitespace-nowrap"
            >
              {t}
            </span>
          ))}
        </div>
        <div className="mt-2.5 text-[10px] font-mono text-muted-foreground/60">
          docs.nano.sh · status.nano.sh
        </div>
      </div>
    </div>
  );
}

export function Login() {
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
  } = useAuth();

  useDocumentTitle('Login');

  // SSO/OIDC is enterprise-only (NAN-745). Open builds skip the providers
  // fetch, hide the inspector SSO panel, and drop the email-step "or use SSO"
  // hint — local credentials remain the only auth path.
  const { capabilities } = useCapabilities();
  const ssoEnabled = capabilities.sso;

  const version = __APP_VERSION__;
  const stats = useFakeStats();
  const clock = useClock();

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
      const returnTo = (location.state as { from?: string })?.from || '/';
      navigate(returnTo, { replace: true });
    }
  }, [isAuthenticated, authLoading, navigate, location.state]);

  // Fetch OIDC providers once. Skipped in open-core builds (no SSO surface).
  useEffect(() => {
    if (!ssoEnabled) {
      setLoadingProviders(false);
      return;
    }
    let cancelled = false;
    setLoadingProviders(true);
    setProvidersFailed(false);
    fetch(`${API_BASE_URL}/api/auth/oidc/providers`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`providers request failed: ${res.status}`);
        return (await res.json()) as OidcProvider[];
      })
      .then((providers) => {
        if (!cancelled) setOidcProviders(providers);
      })
      .catch(() => {
        // Never blocks sign-in: local credentials remain available, and the
        // panel says so rather than silently pretending SSO isn't configured.
        if (!cancelled) {
          setOidcProviders([]);
          setProvidersFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingProviders(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ssoEnabled, providersReload]);

  // NAN-2181: which methods this deployment accepts. Public endpoint — the page
  // has to know before anyone authenticates. A failure falls back to enabled,
  // because the alternative is a login page offering nothing at all; the server
  // still rejects the credentials if the tenant really is SSO-only.
  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE_URL}/api/auth/methods`)
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
  }, [providersReload]);

  // When the AuthContext flips MFA-pending, jump our wizard to the mfa step.
  useEffect(() => {
    if (mfaPending) setStep('mfa');
  }, [mfaPending]);

  // MFA setup-required redirect (preserve legacy behavior).
  useEffect(() => {
    if (mfaSetupPending && challengeToken) {
      navigate('/mfa-setup', {
        state: { challengeToken, from: (location.state as { from?: string })?.from || '/' },
      });
    }
  }, [mfaSetupPending, challengeToken, navigate, location.state]);

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
      await login(email, val);
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
      await loginWithOidc(slug, location.pathname);
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
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    );
  }
  terminalShownRef.current = true;

  return (
    <div className="flex min-h-screen" style={{ background: 'var(--background)' }}>
      <Rail />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar step={step} version={version} />
        <div className="flex-1 flex min-h-0">
          <div className="flex-1 flex flex-col min-w-0 p-3 md:p-5" style={{ background: 'var(--background)' }}>
            <div
              className="flex-1 flex flex-col min-h-0 rounded-[10px] border border-border overflow-hidden"
              style={{ background: 'var(--card)' }}
            >
              {/* Tab strip */}
              <div
                className="h-[34px] px-1 flex items-end gap-0 border-b border-border shrink-0 whitespace-nowrap"
                style={{ background: 'var(--card-2)' }}
              >
                <div
                  className="h-full px-3 flex items-center gap-2 rounded-t-md border-t border-l border-r border-border text-[11.5px] -mb-px shrink-0 whitespace-nowrap"
                  style={{ background: 'var(--card)' }}
                >
                  <Terminal className="w-[12px] h-[12px] text-primary shrink-0" />
                  <span className="font-mono text-foreground whitespace-nowrap">auth login</span>
                  <span className="text-muted-foreground/60">·</span>
                  <span className="font-mono text-muted-foreground text-[10.5px] whitespace-nowrap">interactive</span>
                </div>
                <div className="flex-1" />
                <div className="h-full px-2 flex items-center gap-2 font-mono text-[10px] text-muted-foreground/60 shrink-0 whitespace-nowrap">
                  <span>ansi · 256</span>
                  <span>·</span>
                  <span>utf-8</span>
                </div>
              </div>

              {/* Terminal scroll */}
              <div
                ref={scrollRef}
                className="flex-1 min-h-0 overflow-y-auto scrollbar-thin px-5 py-4 font-mono"
                onClick={() => inputRef.current?.focus()}
              >
                <WelcomeBanner version={version} stats={stats} />

                {bootLines.current.map((l) => renderLine(l))}
                {history.map((l) => renderLine(l))}

                {step !== 'done' && passwordPromptVisible && (
                  <div className="pt-1">
                    {/*
                      Anchored prompt — design_handoff_login_terminal/README.md
                      "anchored" treatment. Bordered card + brand-tinted header
                      strip (status + path + step indicator) over the input row.
                    */}
                    <div
                      className="max-w-[78ch] rounded-md overflow-hidden border bg-card"
                      style={{
                        borderColor:
                          'color-mix(in srgb, var(--primary) 45%, var(--border))',
                        backgroundColor:
                          'color-mix(in srgb, var(--primary) 4%, var(--card))',
                      }}
                    >
                      <div
                        className="h-[22px] px-2.5 flex items-center gap-2 border-b border-border"
                        style={{
                          backgroundColor:
                            'color-mix(in srgb, var(--primary) 7%, var(--card))',
                        }}
                      >
                        <span className="w-1 h-1 rounded-full bg-primary animate-pulse shrink-0" />
                        <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground">
                          awaiting input
                        </span>
                        <span className="text-muted-foreground/50 text-[10px]">·</span>
                        <span className="font-mono text-[9.5px] text-muted-foreground truncate">
                          {prompt}
                        </span>
                        <div className="flex-1" />
                        {stepIndicator && (
                          <div className="h-[18px] px-1.5 rounded-sm border border-border inline-flex items-center gap-1 font-mono text-[10px] text-muted-foreground shrink-0">
                            <span className="text-primary tabular-nums">
                              {stepIndicator.num}
                            </span>
                            <span className="uppercase tracking-[0.12em]">
                              {stepIndicator.label}
                            </span>
                          </div>
                        )}
                      </div>
                      <form
                        onSubmit={onSubmitDraft}
                        className="px-2.5 py-1.5 flex items-center gap-2 font-mono text-[12.5px] leading-none"
                      >
                        <span className="text-primary select-none shrink-0 leading-none">&gt;</span>
                        {activePromptLabel && (
                          <span className="text-muted-foreground select-none shrink-0 whitespace-nowrap">
                            {activePromptLabel}
                          </span>
                        )}
                        <div className="relative flex-1 min-w-0 flex items-center">
                          {isPassword ? (
                            <>
                              <span className="text-foreground">{'•'.repeat(draft.length)}</span>
                              <span className="text-primary animate-pulse">▍</span>
                              <input
                                ref={inputRef}
                                value={draft}
                                onChange={(e) => setDraft(e.target.value)}
                                onKeyDown={onKeyDown}
                                type="text"
                                autoComplete="current-password"
                                autoCapitalize="off"
                                spellCheck={false}
                                disabled={busy}
                                className="absolute inset-0 w-full h-full bg-transparent text-transparent caret-transparent outline-none"
                              />
                            </>
                          ) : (
                            <input
                              ref={inputRef}
                              value={draft}
                              onChange={(e) => setDraft(e.target.value)}
                              onKeyDown={onKeyDown}
                              inputMode={step === 'mfa' ? 'numeric' : 'text'}
                              maxLength={step === 'mfa' ? 12 : undefined}
                              placeholder={placeholder}
                              autoComplete={step === 'email' ? 'email' : 'off'}
                              autoCapitalize="off"
                              spellCheck={false}
                              disabled={busy}
                              className="w-full bg-transparent outline-none border-0 text-foreground font-mono text-[12.5px] caret-[var(--primary)]"
                            />
                          )}
                          {busy && (
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground absolute right-1" />
                          )}
                        </div>
                        <kbd className="hidden sm:inline-flex items-center h-[16px] px-1 rounded-sm border border-border bg-foreground/[0.06] font-mono text-[9.5px] text-muted-foreground shrink-0">
                          ↵
                        </kbd>
                      </form>
                    </div>

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
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
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
                                      <Loader2 className="w-3 h-3 animate-spin text-muted-foreground shrink-0" />
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
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    resolving sign-in methods…
                  </div>
                )}

                {step !== 'done' && loginMode.kind === 'ssoOnlyLoading' && (
                  <div className="pt-1 flex items-center gap-2 text-[11.5px] font-mono text-muted-foreground">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
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
                                <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground shrink-0" />
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
              </div>
            </div>
          </div>
          <Inspector stats={stats} ssoEnabled={ssoEnabled} />
        </div>
        <StatusBar
          step={step}
          version={version}
          authError={authError ?? null}
          stats={stats}
          clock={clock}
        />
      </div>
    </div>
  );
}
