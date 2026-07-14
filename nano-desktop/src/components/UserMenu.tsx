import { useEffect, useRef, useState } from 'react';

import { NavGear } from '@/components/layout/nav-icons';

import { api, errorMessage } from '../lib/ipc';
import type { AgentStatus, ServerConfig, User } from '../lib/types';

/**
 * The account avatar in the titlebar (mock 1a's "JK" chip), opened into a menu.
 *
 * It holds the things that are genuinely account-scoped: who you are, which
 * deployment you're on, the agent tools minted against your key, and the two
 * ways to end a session. There is no "Settings…" item, because there is no
 * settings screen — a menu entry that opens nothing is worse than its absence.
 */
interface Props {
  server: ServerConfig;
  user: User;
  onLock: () => void;
  onSignOut: () => void;
}

export function UserMenu({ server, user, onLock, onSignOut }: Props) {
  const [open, setOpen] = useState(false);
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    // Read the agent state when the menu opens, not on every render.
    void api
      .agentStatus()
      .then(setAgent)
      .catch(() => setAgent(null));

    function onPointerDown(event: MouseEvent) {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  async function revokeAgent() {
    setBusy(true);
    setError(null);
    try {
      setAgent(await api.revokeAgent());
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div ref={root} className="relative shrink-0">
      <button
        onClick={() => setOpen((current) => !current)}
        title={user.email}
        className={`flex size-[26px] items-center justify-center rounded-full border text-[10px] font-bold text-t1 ${
          open
            ? 'border-accent-line bg-accent-soft'
            : 'border-line-strong bg-[linear-gradient(135deg,#3A4152,#232833)] hover:border-accent-line'
        }`}
      >
        {initials(user)}
      </button>

      {open && (
        <div className="absolute top-full right-0 z-50 mt-2 w-[280px] overflow-hidden rounded-[10px] border border-line-strong bg-[rgba(36,39,46,0.96)] shadow-[0_18px_44px_rgba(0,0,0,0.5)] backdrop-blur-[40px]">
          <div className="border-b border-line px-3.5 py-3">
            <div className="truncate text-[13px] font-semibold text-t1">
              {user.name || user.email}
            </div>
            {user.name && (
              <div className="truncate text-[11.5px] text-t3">{user.email}</div>
            )}
            <div className="mt-2 truncate font-mono text-[10.5px] text-t4">
              {server.base_url}
            </div>
            {server.allow_insecure && (
              <div className="mt-1 font-mono text-[10.5px] text-warn">unverified TLS</div>
            )}
            {user.roles.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {user.roles.map((role) => (
                  <span
                    key={role}
                    className="rounded-[4px] bg-raised px-1.5 py-0.5 font-mono text-[10px] text-t3"
                  >
                    {role}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Agent tools live here because they're minted against this account. */}
          <div className="border-b border-line px-3.5 py-3">
            <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold text-t2">
              <NavGear className="size-[13px]" />
              Agent tools
            </div>
            {agent?.provisioned ? (
              <>
                <div className="font-mono text-[10.5px] text-t4">
                  read-only key {agent.key_prefix}… · {agent.granted_permissions.length} scopes
                </div>
                <button
                  onClick={revokeAgent}
                  disabled={busy}
                  className="mt-1.5 text-[11.5px] text-danger hover:opacity-80 disabled:opacity-40"
                >
                  {busy ? 'Revoking…' : 'Revoke key'}
                </button>
              </>
            ) : (
              <div className="text-[11.5px] text-t4">
                Not connected. Connect them from MCP tools in the rail.
              </div>
            )}
            {error && <div className="mt-1.5 text-[11px] text-danger">{error}</div>}
          </div>

          <div className="p-1.5">
            <MenuItem onClick={onLock}>
              Lock
              <span className="ml-auto text-[10.5px] text-t4">Touch ID to return</span>
            </MenuItem>
            <MenuItem onClick={onSignOut} danger>
              Sign out
              <span className="ml-auto text-[10.5px] text-t4">forgets this device</span>
            </MenuItem>
          </div>
        </div>
      )}
    </div>
  );
}

function MenuItem({
  onClick,
  danger,
  children,
}: {
  onClick: () => void;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center gap-2 rounded-[6px] px-2.5 py-1.5 text-left text-[12.5px] hover:bg-hover ${
        danger ? 'text-t3 hover:text-danger' : 'text-t2 hover:text-t1'
      }`}
    >
      {children}
    </button>
  );
}

function initials(user: User): string {
  const source = user.name?.trim() || user.email;
  const parts = source.split(/[\s.@]+/).filter(Boolean);
  return (parts[0]?.[0] ?? '?').concat(parts[1]?.[0] ?? '').toUpperCase();
}
