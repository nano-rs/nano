import { useEffect, useState, type FormEvent } from 'react';

import logoWhite from '../assets/nano_white.png';
import { Button, ErrorNote, Field, Spinner } from '../components/ui';
import { api, errorMessage, isIpcError } from '../lib/ipc';
import type { ServerConfig, User } from '../lib/types';

/**
 * Sign-in — handoff mock 8a. Brand panel left, sign-in right.
 *
 * Two deliberate departures from the mock, both because the mock describes an
 * auth model nano doesn't have yet:
 *
 * 1. The mock offers "Continue with Okta SSO" and "Continue with Google". nano's
 *    API has no SSO callback flow wired to this app, so there is ONE generic SSO
 *    button and it is visibly disabled — a dead button that looks alive is worse
 *    than an honest one. Google is gone entirely.
 * 2. The mock takes an email and continues. Real auth here is email + password
 *    (+ MFA), so the form carries both.
 */

type Step = 'server' | 'credentials' | 'mfa' | 'mfa_setup';

interface Props {
  initialServer: ServerConfig | null;
  /** The keychain holds a refresh token: Touch ID can get us in without a password. */
  trusted: boolean;
  trustedEmail: string | null;
  onAuthenticated: (user: User, server: ServerConfig) => void;
}

export function Auth({ initialServer, trusted, trustedEmail, onAuthenticated }: Props) {
  const [step, setStep] = useState<Step>(initialServer ? 'credentials' : 'server');
  const [server, setServer] = useState<ServerConfig | null>(initialServer);
  const [editingHost, setEditingHost] = useState(!initialServer);

  const [url, setUrl] = useState(initialServer?.base_url ?? '');
  const [searchUrl, setSearchUrl] = useState(initialServer?.search_url ?? '');
  const [showAdvanced, setShowAdvanced] = useState(Boolean(initialServer?.search_url));
  const [email, setEmail] = useState(trustedEmail ?? '');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [challengeToken, setChallengeToken] = useState('');

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [untrustedCert, setUntrustedCert] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (caught) {
      setError(errorMessage(caught));
      if (isIpcError(caught) && caught.kind === 'tls') setUntrustedCert(true);
    } finally {
      setBusy(false);
    }
  }

  const connect = (allowInsecure: boolean) => (event?: FormEvent) => {
    event?.preventDefault();
    void run(async () => {
      const connected = await api.connect(url, searchUrl.trim() || null, allowInsecure);
      setServer(connected);
      setUntrustedCert(false);
      setEditingHost(false);
      setStep('credentials');
    });
  };

  const signIn = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const outcome = await api.login(email, password);
      if (outcome.status === 'authenticated') {
        onAuthenticated(outcome.user, server!);
        return;
      }
      setChallengeToken(outcome.challenge_token);
      setStep(outcome.status === 'mfa_required' ? 'mfa' : 'mfa_setup');
    });
  };

  const verify = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const outcome = await api.verifyMfa(challengeToken, code);
      if (outcome.status === 'authenticated') onAuthenticated(outcome.user, server!);
    });
  };

  /** Touch ID → refresh the stored token → straight in. No password. */
  function unlock() {
    void run(async () => {
      const user = await api.unlockSession();
      onAuthenticated(user, server!);
    });
  }

  return (
    <div className="flex h-full overflow-hidden rounded-[16px] border border-line-strong bg-window">
      <BrandPanel />

      <div className="flex flex-1 flex-col justify-center px-[72px]">
        <h1 className="text-[21px] font-bold text-t1">Sign in to nano</h1>

        <div className="mt-1.5 mb-7 text-[12.5px] text-t3">
          {editingHost || !server ? (
            <form onSubmit={connect(false)} className="mt-3 flex flex-col gap-3">
              <Field
                label="Deployment"
                mono
                autoFocus
                spellCheck={false}
                autoCapitalize="off"
                placeholder="acme.nano.rs"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
              />

              {showAdvanced ? (
                <Field
                  label="Search service"
                  mono
                  spellCheck={false}
                  placeholder="http://localhost:3002"
                  value={searchUrl}
                  onChange={(event) => setSearchUrl(event.target.value)}
                  hint={
                    <span className="text-[11px] text-t4">
                      Only if search is on a different host than the API.
                    </span>
                  }
                />
              ) : (
                <button
                  type="button"
                  onClick={() => setShowAdvanced(true)}
                  className="self-start text-[11px] text-t3 hover:text-accent"
                >
                  Search service is on a different host
                </button>
              )}

              {error && <ErrorNote>{error}</ErrorNote>}
              {untrustedCert && (
                <Button type="button" variant="ghost" onClick={() => connect(true)()} disabled={busy}>
                  Connect without verifying the certificate
                </Button>
              )}
              <Button type="submit" disabled={busy || !url.trim()}>
                {busy ? <Spinner /> : 'Continue'}
              </Button>
            </form>
          ) : (
            <>
              deployment: <span className="font-mono text-t2">{hostOf(server.base_url)}</span>{' '}
              <button
                onClick={() => setEditingHost(true)}
                className="text-accent hover:opacity-80"
              >
                · change
              </button>
              {server.allow_insecure && (
                <span className="ml-1 font-mono text-warn">· unverified TLS</span>
              )}
            </>
          )}
        </div>

        {!editingHost && server && (
          <>
            {/* One generic SSO button, honestly disabled: nano has no SSO
                callback wired to this app yet. Google is gone entirely. */}
            <button
              disabled
              title="Single sign-on is not available for this deployment yet"
              className="w-full cursor-default rounded-[9px] border border-line-strong bg-white/[0.04] py-3 text-[13.5px] font-semibold text-t4"
            >
              Continue with SSO
              <span className="ml-2 text-[11px] font-normal text-t4">· not configured</span>
            </button>

            <div className="my-6 flex items-center gap-3">
              <span className="h-px flex-1 bg-line" />
              <span className="text-[11px] text-t4">or</span>
              <span className="h-px flex-1 bg-line" />
            </div>

            {step === 'credentials' && (
              <form onSubmit={signIn} className="flex flex-col gap-3">
                <input
                  type="email"
                  autoFocus={!trusted}
                  autoComplete="username"
                  placeholder="work email…"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="w-full rounded-[9px] border border-line-strong bg-input px-3.5 py-3 text-[13px] text-t1 outline-none placeholder:text-t4 focus:border-accent"
                />
                <input
                  type="password"
                  autoComplete="current-password"
                  placeholder="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="w-full rounded-[9px] border border-line-strong bg-input px-3.5 py-3 text-[13px] text-t1 outline-none placeholder:text-t4 focus:border-accent"
                />
                {error && <ErrorNote>{error}</ErrorNote>}
                <button
                  type="submit"
                  disabled={busy || !email.trim() || !password}
                  className="w-full rounded-[9px] border border-accent-line bg-accent-fill py-2.5 text-[13px] font-semibold text-accent disabled:opacity-40"
                >
                  {busy ? <Spinner /> : 'Continue'}
                </button>
              </form>
            )}

            {step === 'mfa' && (
              <form onSubmit={verify} className="flex flex-col gap-3">
                <input
                  autoFocus
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  className="w-full rounded-[9px] border border-line-strong bg-input px-3.5 py-3 font-mono text-[13px] text-t1 outline-none placeholder:text-t4 focus:border-accent"
                />
                <span className="text-[11px] text-t4">
                  Code from your authenticator. A backup code works too.
                </span>
                {error && <ErrorNote>{error}</ErrorNote>}
                <button
                  type="submit"
                  disabled={busy || code.trim().length < 6}
                  className="w-full rounded-[9px] border border-accent-line bg-accent-fill py-2.5 text-[13px] font-semibold text-accent disabled:opacity-40"
                >
                  {busy ? <Spinner /> : 'Verify'}
                </button>
              </form>
            )}

            {step === 'mfa_setup' && (
              <ErrorNote>
                Your administrator requires multi-factor authentication and this account has not
                enrolled. Enroll in the nano web app once, then come back.
              </ErrorNote>
            )}

            {/* Trusted device. Only when the keychain actually holds a token for
                this server — never as decoration. */}
            {trusted && step === 'credentials' && (
              <div className="mt-[34px] flex items-center gap-3.5 rounded-[12px] border border-line-strong bg-white/[0.025] px-4 py-3.5">
                <TouchIdGlyph />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-semibold text-t1">This device is trusted</div>
                  <div className="truncate text-[11.5px] text-t3">
                    {trustedEmail ?? 'saved session'} · unlock with Touch ID
                  </div>
                </div>
                <button
                  onClick={unlock}
                  disabled={busy}
                  className="shrink-0 text-[12px] font-semibold text-accent hover:opacity-80 disabled:opacity-40"
                >
                  Unlock
                </button>
              </div>
            )}

            <p className="mt-[22px] text-[11px] leading-[1.6] text-t4">
              Signing in registers this device with your org policy. The session token is held in
              the system keychain and released only after you unlock.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

/** Left column: logo, promise, and a live-ish ingest sparkline. */
function BrandPanel() {
  const [bars, setBars] = useState<number[]>(() =>
    Array.from({ length: 30 }, () => 30 + Math.random() * 70)
  );

  // It stands for live local ingest, so it moves. Slowly — it's a background
  // detail, not a chart to read.
  useEffect(() => {
    const handle = setInterval(() => {
      setBars((current) => [...current.slice(1), 30 + Math.random() * 70]);
    }, 900);
    return () => clearInterval(handle);
  }, []);

  return (
    <div
      data-tauri-drag-region
      className="relative flex w-[480px] shrink-0 flex-col justify-center overflow-hidden bg-[linear-gradient(160deg,#0A0D12_0%,#0D1421_55%,#0A1119_100%)] px-[52px]"
    >
      <div className="pointer-events-none absolute -bottom-[180px] -left-[140px] size-[560px] rounded-full bg-[radial-gradient(closest-side,color-mix(in_srgb,var(--color-accent)_16%,transparent),transparent)]" />

      <img
        src={logoWhite}
        alt="nano"
        className="w-[168px] drop-shadow-[0_0_26px_color-mix(in_srgb,var(--color-accent)_30%,transparent)]"
      />
      <h2 className="mt-[26px] text-[30px] leading-[1.2] font-bold tracking-[-0.02em] whitespace-pre-line text-t1">
        {'The SIEM,\non your desk.'}
      </h2>
      <p className="mt-3.5 max-w-[320px] text-[13.5px] leading-[1.65] text-t3">
        Search 7 days of hot data offline. Let your coding agent work the queue. Everything else
        stays on the cluster.
      </p>

      <div className="absolute right-[52px] bottom-[26px] left-[52px]">
        <div className="flex h-11 items-end gap-[3px]">
          {bars.map((height, index) => (
            <div
              key={index}
              style={{ height: `${height}%` }}
              className="flex-1 rounded-t-[1.5px] bg-accent/55 transition-[height] duration-700"
            />
          ))}
        </div>
        <div className="mt-2.5 flex justify-between font-mono text-[10.5px]">
          <span className="text-t4">local index · 2.1 GB · ready</span>
          <span className="text-accent">● live</span>
        </div>
      </div>
    </div>
  );
}

/** Stand-in for the SF Symbol `touchid`: concentric rings, dashed inner. */
function TouchIdGlyph() {
  return (
    <div className="flex size-10 shrink-0 items-center justify-center rounded-full border-[1.5px] border-accent/55">
      <div className="size-6 rounded-full border-[1.5px] border-dashed border-accent/75" />
    </div>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
