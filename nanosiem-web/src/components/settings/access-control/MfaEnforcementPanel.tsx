// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MFA enforcement policy panel — a one-row admin control rendered above
 * the Users filter bar in Access Control.
 *
 * The whole stack already exists end-to-end:
 *   - `system_settings.mfa_required` boolean (Postgres)
 *   - `PUT /api/settings/mfa-required` (admin gated on `settings:system`,
 *     audit-logged)
 *   - Login enforcement in `nanosiem-core/src/auth/service.rs` — non-OIDC
 *     users without MFA enrolled get bounced to `/mfa-setup` with a
 *     challenge token before login completes.
 *
 * This component is the missing UI surface to flip the toggle. Hidden
 * for users without `settings:system` so it never appears for tier-1
 * analysts browsing the user list.
 */

import { useEffect, useState } from 'react';
import { ShieldCheck, Loader2 } from 'lucide-react';
import { Switch } from '@/components/ui/switch';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

export function MfaEnforcementPanel() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const canManage = hasPermission('settings:system');

  const [required, setRequired] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Fetch current state on mount. Uses the existing MFA status endpoint
  // (already returns `mfa_required_globally` for any authenticated user)
  // so we don't add a new round trip for the admin-only flag.
  useEffect(() => {
    if (!canManage) {
      setLoading(false);
      return;
    }
    api.auth
      .getMfaStatus()
      .then((s) => setRequired(s.mfa_required_globally))
      .catch(() => setRequired(null))
      .finally(() => setLoading(false));
  }, [canManage]);

  if (!canManage) return null;

  const onToggle = async (next: boolean) => {
    if (saving) return;
    const prev = required;
    setSaving(true);
    setRequired(next); // optimistic
    try {
      await api.auth.setMfaRequired(next);
      toast({
        title: next ? 'MFA required for all users' : 'MFA enforcement disabled',
        description: next
          ? 'Non-MFA users will be required to enrol on next login.'
          : 'Users may sign in without MFA. Existing enrolments are unaffected.',
      });
    } catch (err) {
      setRequired(prev);
      toast({
        title: 'Update failed',
        description: err instanceof Error ? err.message : 'Could not save MFA policy',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const enabled = required === true;

  return (
    <div className="mx-5 mt-4 mb-1">
      <div
        className={cn(
          'rounded-md border px-4 py-3 flex items-center gap-3',
          enabled
            ? 'border-[color-mix(in_srgb,var(--success)_30%,transparent)] bg-[color-mix(in_srgb,var(--success)_6%,transparent)]'
            : 'border-border bg-card',
        )}
      >
        <ShieldCheck
          className={cn(
            'w-4 h-4 shrink-0',
            enabled ? 'text-[var(--success)]' : 'text-muted-foreground',
          )}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] font-semibold text-foreground">
              Require multi-factor authentication
            </span>
            {enabled && (
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--success)] bg-[color-mix(in_srgb,var(--success)_15%,transparent)] px-1.5 py-px rounded-sm">
                org-wide
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-snug">
            {enabled ? (
              <>
                Local-account users without MFA will be forced to enrol on next login. SSO
                users follow their identity provider's policy.
              </>
            ) : (
              <>
                Users may sign in with email + password alone. Toggle on to require TOTP
                enrolment for every local account.
              </>
            )}
          </div>
        </div>
        {loading || required === null ? (
          <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
        ) : (
          <Switch
            checked={enabled}
            onCheckedChange={onToggle}
            disabled={saving}
            className="h-4 w-7"
            aria-label="Require MFA for all users"
          />
        )}
      </div>
    </div>
  );
}
