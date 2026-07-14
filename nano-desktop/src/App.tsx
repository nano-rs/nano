import { useEffect, useState } from 'react';

import { Spinner } from './components/ui';
import { api } from './lib/ipc';
import type { ServerConfig, User } from './lib/types';
import { setWindowChrome } from './lib/window';
import { Auth } from './screens/Auth';
import { Search } from './screens/Search';

interface Session {
  server: ServerConfig;
  user: User;
}

export function App() {
  const [booting, setBooting] = useState(true);
  const [server, setServer] = useState<ServerConfig | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  /** Keychain holds a token for this server — offer Touch ID instead of a password. */
  const [trusted, setTrusted] = useState(false);
  const [trustedEmail, setTrustedEmail] = useState<string | null>(null);

  // Launch no longer signs anyone in. A remembered device surfaces as a trusted
  // -device card that Touch ID unlocks — otherwise opening the app on an
  // unlocked Mac put whoever sat down straight inside the SIEM.
  useEffect(() => {
    void (async () => {
      try {
        const restored = await api.restoreSession();
        setServer(restored.server);
        setTrusted(restored.trusted);
        setTrustedEmail(restored.email);
      } catch {
        // Treat any restore failure as "not signed in".
      } finally {
        setBooting(false);
      }
    })();
  }, []);

  useEffect(() => {
    if (booting) return;
    void setWindowChrome(session ? 'app' : 'auth');
  }, [booting, session]);

  if (booting) {
    return (
      <div className="flex h-full items-center justify-center rounded-[14px] border border-line-strong bg-window">
        <Spinner className="text-accent" />
      </div>
    );
  }

  if (!session) {
    return (
      <Auth
        initialServer={server}
        trusted={trusted}
        trustedEmail={trustedEmail}
        onAuthenticated={(user, connected) => {
          setServer(connected);
          setSession({ server: connected, user });
        }}
      />
    );
  }

  return (
    <Search
      server={session.server}
      user={session.user}
      // Lock keeps the keychain token, so the sign-in screen offers Touch ID.
      onLock={async () => {
        await api.lockSession();
        setTrusted(true);
        setTrustedEmail(session.user.email);
        setSession(null);
      }}
      // Sign out destroys it: the device is no longer trusted.
      onSignOut={async () => {
        await api.logout();
        setTrusted(false);
        setTrustedEmail(null);
        setSession(null);
      }}
    />
  );
}
