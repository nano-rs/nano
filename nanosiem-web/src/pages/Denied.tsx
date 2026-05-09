// SPDX-License-Identifier: AGPL-3.0-or-later

export default function Denied() {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--color-bg-primary, #0a0a0f)',
      color: 'var(--color-text-primary, #e2e8f0)',
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
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
          </svg>
        </div>

        <h1 style={{
          fontSize: '1.5rem',
          fontWeight: 600,
          marginBottom: '0.75rem',
          color: 'var(--color-text-primary, #e2e8f0)',
        }}>
          Access Denied
        </h1>

        <p style={{
          fontSize: '0.9rem',
          lineHeight: 1.6,
          color: 'var(--color-text-secondary, #94a3b8)',
          marginBottom: '2rem',
        }}>
          Your IP address is not authorized to access this service.
        </p>

        <p style={{
          fontSize: '0.8rem',
          color: 'var(--color-text-muted, #64748b)',
        }}>
          If you believe this is an error, contact your system administrator.
        </p>
      </div>
    </div>
  );
}
