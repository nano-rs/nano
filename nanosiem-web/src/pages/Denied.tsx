// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Styled inline, with hardcoded fallbacks, on purpose: this renders for a
 * client the edge has refused, so it must survive the app shell not being there.
 *
 * The token NAMES were the bug — `--color-text-primary`, `--color-bg-primary`
 * and friends do not exist anywhere in `index.css`, so every `var()` here always
 * fell through to its slate literal and the page was hardcoded dark in practice.
 * Pointed at real tokens, it now follows the theme (matte included) whenever the
 * stylesheet IS present, and still degrades to the same literals when it isn't.
 */
export default function Denied() {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--background, #0a0a0f)',
      color: 'var(--foreground, #e2e8f0)',
      fontFamily: 'system-ui, -apple-system, sans-serif',
    }}>
      <div style={{
        maxWidth: '480px',
        textAlign: 'center',
        padding: '2rem',
      }}>
        <div style={{
          width: '64px',
          height: '64px',
          margin: '0 auto 1.5rem',
          borderRadius: '50%',
          backgroundColor: 'color-mix(in srgb, var(--destructive, #ef4444) 10%, transparent)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--destructive, #ef4444)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
          </svg>
        </div>

        <h1 style={{
          fontSize: '1.5rem',
          fontWeight: 600,
          marginBottom: '0.75rem',
          color: 'var(--foreground, #e2e8f0)',
        }}>
          Access Denied
        </h1>

        <p style={{
          fontSize: '0.9rem',
          lineHeight: 1.6,
          color: 'var(--muted-foreground, #94a3b8)',
          marginBottom: '2rem',
        }}>
          Your IP address is not authorized to access this service.
        </p>

        <p style={{
          fontSize: '0.8rem',
          color: 'var(--fg-4, #64748b)',
        }}>
          If you believe this is an error, contact your system administrator.
        </p>
      </div>
    </div>
  );
}
