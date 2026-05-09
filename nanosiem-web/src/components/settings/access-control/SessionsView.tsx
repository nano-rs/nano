// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sessions — Access Control deep-dive (table only, no detail pane).
 *
 * Mirrors `design-ref/shadcn/settings-users.jsx` `SessionsView`. Active
 * browser + API sessions with per-row revoke. The mockup shows device,
 * region, started, last seen — backend exposes `user_agent` (parsed
 * client-side for device label), `ip_address`, `created_at`, `last_used_at`,
 * `expires_at`. We map best-effort:
 *
 *   • device — best guess from user_agent
 *   • IP — `ip_address`
 *   • region — left blank until a GeoIP enrichment is wired
 *   • started — `created_at`
 *   • last seen — `last_used_at`
 *
 * The legacy SessionsContent fetched sessions per-user; the redesign shows
 * all sessions. Permission gate matches the legacy: any user with `users:view`.
 */

import { useEffect, useMemo, useState } from 'react';
import { Bolt, User as UserIcon, Search as SearchIcon, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api, type SessionInfo, type UserDetail } from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { formatRelativeCompact } from '@/lib/date-utils';

function deviceFromUA(ua: string | undefined): string {
  if (!ua) return 'Unknown';
  const lower = ua.toLowerCase();
  let os = 'Unknown';
  if (lower.includes('mac os') || lower.includes('macintosh')) os = 'macOS';
  else if (lower.includes('windows')) os = 'Windows';
  else if (lower.includes('linux')) os = 'Linux';
  else if (lower.includes('android')) os = 'Android';
  else if (lower.includes('iphone') || lower.includes('ipad')) os = 'iOS';

  let browser = '';
  if (lower.includes('chrome/')) browser = 'Chrome';
  else if (lower.includes('safari/') && !lower.includes('chrome')) browser = 'Safari';
  else if (lower.includes('firefox/')) browser = 'Firefox';
  else if (lower.includes('edg/')) browser = 'Edge';
  else if (lower.includes('python') || lower.includes('curl') || lower.includes('go-http')) {
    return `API · ${ua.split(/[\/ ]/)[0]}`;
  }
  return browser ? `${os} · ${browser}` : os;
}

interface SessionRowMeta {
  session: SessionInfo;
  user: UserDetail | null;
}

export function SessionsView() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canRevoke = hasPermission('users:edit');

  const [rows, setRows] = useState<SessionRowMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [pendingRevoke, setPendingRevoke] = useState<SessionInfo | null>(null);
  const [revokeAll, setRevokeAll] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [sessionsRes, usersRes] = await Promise.all([
        api.listAllSessions(),
        api.listUsers().catch(() => ({ users: [] as UserDetail[], total: 0 })),
      ]);
      const userMap = new Map(usersRes.users.map(u => [u.id, u]));
      setRows(sessionsRes.sessions.map(s => ({ session: s, user: userMap.get(s.user_id) || null })));
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load sessions',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(({ session, user }) =>
      (user?.name?.toLowerCase().includes(q) ?? false)
      || (user?.email?.toLowerCase().includes(q) ?? false)
      || (session.ip_address?.toLowerCase().includes(q) ?? false)
      || (session.user_agent?.toLowerCase().includes(q) ?? false),
    );
  }, [query, rows]);

  const handleRevoke = async () => {
    if (!pendingRevoke) return;
    setActionLoading(true);
    try {
      await api.terminateSession(pendingRevoke.id);
      toast({ title: 'Session revoked' });
      setPendingRevoke(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to revoke session',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevokeAll = async () => {
    setActionLoading(true);
    try {
      const others = rows.filter(r => !r.session.is_current);
      await Promise.all(others.map(r => api.terminateSession(r.session.id).catch(() => undefined)));
      toast({ title: 'All non-current sessions revoked' });
      setRevokeAll(false);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to revoke sessions',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <div className="flex-1 flex flex-col min-h-0">
        <div className="shrink-0 px-5 pt-4 pb-2.5 flex items-center gap-2 flex-wrap">
          <div className="h-8 rounded-md border border-border bg-card flex items-center gap-2 px-2.5 w-[300px]">
            <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search by user, email, IP…"
              className="flex-1 bg-transparent outline-none text-[12px] text-foreground placeholder:text-muted-foreground/70"
            />
          </div>
          <div className="text-[12.5px] text-muted-foreground ml-2">
            Active sessions across users and API clients. Revoking ends a session immediately.
          </div>
          <div className="flex-1" />
          {canRevoke && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-[11.5px] px-2.5 text-red-500 hover:text-red-500/90"
              onClick={() => setRevokeAll(true)}
              disabled={rows.filter(r => !r.session.is_current).length === 0}
            >
              Revoke all (except current)
            </Button>
          )}
        </div>

        <div className="shrink-0 grid grid-cols-[minmax(140px,1.2fr)_minmax(160px,1.4fr)_minmax(120px,1fr)_100px_100px_80px] gap-3 px-3 py-1.5 border-y border-border bg-card/50 text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
          <span>User / client</span>
          <span>Device</span>
          <span>IP</span>
          <span>Started</span>
          <span>Last seen</span>
          <span />
        </div>

        <div className="flex-1 overflow-y-auto scrollbar-thin">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div className="px-6 py-12 text-center text-[12px] text-muted-foreground">
              {rows.length === 0 ? 'No active sessions.' : 'No sessions match.'}
            </div>
          )}
          {!loading && filtered.map(({ session, user }) => {
            const isApi = (session.user_agent || '').toLowerCase().includes('python')
              || (session.user_agent || '').toLowerCase().includes('curl')
              || (session.user_agent || '').toLowerCase().startsWith('go-http');
            return (
              <div
                key={session.id}
                className={cn(
                  'grid grid-cols-[minmax(140px,1.2fr)_minmax(160px,1.4fr)_minmax(120px,1fr)_100px_100px_80px] gap-3 items-center px-3 h-10 border-b border-border/60 transition-colors',
                  session.is_current ? 'bg-primary/5' : 'hover:bg-foreground/[0.025]',
                )}
              >
                <div className="flex items-center gap-2 min-w-0">
                  {isApi ? (
                    <Bolt className="w-[12px] h-[12px] text-muted-foreground shrink-0" />
                  ) : (
                    <UserIcon className="w-[12px] h-[12px] text-muted-foreground shrink-0" />
                  )}
                  <span className="text-[12.5px] text-foreground truncate">
                    {user?.name || user?.email || `user ${session.user_id.slice(0, 8)}`}
                  </span>
                  {session.is_current && (
                    <span className="text-[9.5px] text-primary uppercase font-mono tracking-wider shrink-0">current</span>
                  )}
                </div>
                <div className="text-[11.5px] text-foreground/80 truncate">{deviceFromUA(session.user_agent)}</div>
                <div className="font-mono text-[11px] text-muted-foreground truncate">{session.ip_address || '—'}</div>
                <div className="font-mono text-[11px] text-muted-foreground">
                  {formatRelativeCompact(session.created_at)}
                </div>
                <div className="font-mono text-[11px] text-muted-foreground">
                  {formatRelativeCompact(session.last_used_at)}
                </div>
                {canRevoke ? (
                  <button
                    disabled={session.is_current}
                    onClick={() => setPendingRevoke(session)}
                    className={cn(
                      'text-[11px] text-right',
                      session.is_current
                        ? 'text-muted-foreground/40 cursor-not-allowed'
                        : 'text-red-500 hover:underline',
                    )}
                  >
                    Revoke
                  </button>
                ) : (
                  <span />
                )}
              </div>
            );
          })}
        </div>

        <div className="shrink-0 h-8 px-5 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground tracking-wide">
          <span>{filtered.length} of {rows.length} sessions</span>
          <span className="ml-auto">
            {rows.filter(r => r.session.is_current).length} current ·{' '}
            {rows.filter(r => !r.session.is_current).length} others
          </span>
        </div>
      </div>

      <AlertDialog open={!!pendingRevoke} onOpenChange={(open) => !open && setPendingRevoke(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke session</AlertDialogTitle>
            <AlertDialogDescription>
              End this session immediately? The user will need to sign in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleRevoke}
              disabled={actionLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={revokeAll} onOpenChange={(open) => !open && setRevokeAll(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke all other sessions</AlertDialogTitle>
            <AlertDialogDescription>
              End every active session except your current one. Affected users will need to sign in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleRevokeAll}
              disabled={actionLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Revoke all
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
