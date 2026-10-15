// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared console acceptance (NAN-2361 wave 5): the signed-in identity's
 * pending invitations from OTHER organizations, accepted in place. Acceptance
 * never changes the current session; the member signs in to the new
 * organization afterwards.
 */

import { useCallback, useEffect, useState } from 'react';
import { Building2, LogIn } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { api, ApiClientError, type MySharedTenantInvitation } from '@/lib/api';
import { useSharedTenant } from '@/hooks/use-shared-tenant';

function relativeExpiry(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms) || ms <= 0) return 'expired';
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 48) return `expires in ${Math.floor(hours / 24)} days`;
  if (hours >= 1) return `expires in ${hours} h`;
  return `expires in ${Math.max(1, Math.floor(ms / 60_000))} min`;
}

export function PendingTenantInvitations() {
  const sharedTenant = useSharedTenant();
  const { toast } = useToast();
  const [invitations, setInvitations] = useState<MySharedTenantInvitation[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [accepted, setAccepted] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const res = await api.listMySharedTenantInvitations();
      setInvitations(res.invitations);
    } catch {
      setInvitations([]);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (!sharedTenant) return;
    void load();
  }, [sharedTenant, load]);

  if (!sharedTenant || !loaded || invitations.length === 0) return null;

  const accept = async (invitation: MySharedTenantInvitation) => {
    setBusy(invitation.id);
    try {
      const res = await api.acceptMySharedTenantInvitation(invitation.id, globalThis.crypto.randomUUID().toLowerCase());
      setAccepted(prev => ({ ...prev, [invitation.id]: res.target_login_path }));
      toast({
        title: 'Invitation accepted',
        description: `You are now a member of ${invitation.tenant_display_name}. Sign in to that organization to use it.`,
      });
    } catch (err) {
      const stale = err instanceof ApiClientError && err.status === 401;
      toast({
        title: 'Could not accept the invitation',
        description: stale
          ? 'Accepting needs a session signed in within the last five minutes. Sign in again and retry.'
          : err instanceof Error ? err.message : 'The invitation could not be accepted.',
        variant: 'destructive',
      });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="rounded-[10px] border border-primary/30 bg-primary/5">
      <div className="px-5 pt-3.5 pb-2.5 border-b border-border/60 flex items-center gap-2">
        <Building2 className="w-[13px] h-[13px] text-primary" />
        <span className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">Organization invitations</span>
        <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums ml-auto">{invitations.length}</span>
      </div>
      <ul className="divide-y divide-border/60">
        {invitations.map(inv => {
          const loginPath = accepted[inv.id];
          return (
            <li key={inv.id} className="px-5 py-2.5 flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-[12.5px] text-foreground">
                  {inv.tenant_display_name}
                  <span className="font-mono text-[10.5px] text-muted-foreground ml-2">{inv.tenant_slug}</span>
                </div>
                <div className="text-[10.5px] text-muted-foreground mt-0.5">
                  as <span className="font-mono">{inv.role_name}</span>
                  {inv.invited_by_name ? <> · invited by {inv.invited_by_name}</> : null}
                  {' · '}<span className="font-mono">{relativeExpiry(inv.expires_at)}</span>
                </div>
              </div>
              {loginPath ? (
                <a href={loginPath} className="inline-flex items-center gap-1 text-[11.5px] text-primary hover:text-primary/90">
                  <LogIn className="w-[12px] h-[12px]" /> Sign in
                </a>
              ) : (
                <Button size="sm" className="h-7 text-[11.5px]" disabled={busy !== null} onClick={() => void accept(inv)}>
                  {busy === inv.id && <LoadingIcon className="w-3 h-3" />}
                  Accept
                </Button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
