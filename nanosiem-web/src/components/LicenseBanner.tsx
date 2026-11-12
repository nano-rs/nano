// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * License enforcement banners
 *
 * Grace period: dismissable warning banner at top of content area
 * Locked: persistent warning; open/core surfaces remain usable
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, X, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import type { LicenseStatusResponse } from '../lib/api';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';

export function LicenseBanner() {
  // License enforcement is enterprise-only — the open edition strips the
  // /api/license endpoint entirely (NAN-1193), so skip the poll (and the
  // 404s it would otherwise generate) and never render in open builds.
  const { edition } = useCapabilities();
  const isEnterprise = edition === 'enterprise';
  const { hasPermission } = useAuth();
  const isAdmin = hasPermission('settings:system');

  const [status, setStatus] = useState<LicenseStatusResponse | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (!isEnterprise) return;

    const fetchStatus = async () => {
      try {
        const s = await api.getLicenseStatus();
        setStatus(s);
      } catch {
        // Ignore — endpoint might not exist yet (self-hosted)
      }
    };

    fetchStatus();
    // Keep recovery and hard-stop presentation aligned with live admission.
    const interval = setInterval(fetchStatus, 60_000);
    return () => clearInterval(interval);
  }, [isEnterprise]);

  // All enterprise admission modes are enforced. Keep the air-gap fallback for
  // compatibility with an older API response during rolling upgrades.
  const enforced = !!status?.enforcement_enabled || !!status?.airgap;

  // NAN-5194: the license server refused the token. Only an admin can fix
  // it (.env + install.sh), and it outranks the other license banners because
  // it is the cause of any lock that follows. Not dismissable; it clears after
  // the next successful check-in.
  if (isEnterprise && isAdmin && status?.token_rejected) {
    return <LicenseTokenRejectedBanner rejection={status.token_rejected} />;
  }

  const trial = status?.entitlement?.kind === 'trial' ? status.entitlement : null;
  if (isEnterprise && status && enforced && trial) {
    const warning = trial.warning_days;
    // An older API serialized `warning_days: null` outside a warning step.
    if (status.state === 'active' && (warning === undefined || warning === null)) return null;
    if (dismissed && status.state !== 'locked') return null;
    return (
      <div className={`mx-6 mt-3 flex items-center justify-between gap-3 rounded-lg border px-4 py-2.5 text-sm ${status.state === 'locked'
        ? 'border-red-200 bg-red-50/80 dark:border-red-500/30 dark:bg-red-500/10'
        : 'border-amber-200 bg-amber-50/80 dark:border-amber-500/30 dark:bg-amber-500/10'}`}>
        <div className="flex items-center gap-3">
          <AlertTriangle className={`h-4 w-4 ${status.state === 'locked' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400'}`} />
          <span className="font-medium">Trial — {trial.days_remaining} days left</span>
          <span className="text-muted-foreground">
            {status.state === 'locked'
              ? 'The seven-day grace period ended. Licensed-only features are disabled; search, ingest, and all stored data remain available.'
              : status.state === 'grace_period'
                ? `The trial ended; licensed features remain available during grace until ${new Date(trial.grace_ends_at).toLocaleDateString()}.`
                : `${warning}-day expiry warning. Contact nano to continue licensed features.`}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <a href="https://app.nano.rs" target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center rounded-md bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700">
            Contact nano
          </a>
          {status.state !== 'locked' && (
            <button onClick={() => setDismissed(true)} className="rounded p-1 text-amber-500 hover:bg-amber-100" aria-label="Dismiss trial warning">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>
    );
  }

  // Don't show anything if not enforced, active, or no status yet
  if (!isEnterprise || !status || !enforced || status.state === 'active') {
    return null;
  }

  // A hard stop removes licensed-only surfaces, not the open/core product.
  if (status.state === 'locked') {
    return <LicenseHardStopBanner status={status} canManageLicense={isAdmin} />;
  }

  // Grace period warning (dismissable)
  if (status.state === 'grace_period' && !dismissed) {
    const legacyUpgrade = status.runtime_state === 'legacy_upgrade_grace';
    const graceEnd = status.grace_ends_at
      ? new Date(status.grace_ends_at)
      : null;
    const daysLeft = graceEnd
      ? Math.max(0, Math.ceil((graceEnd.getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
      : null;

    return (
      <div className="mx-6 mt-3 flex items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50/80 px-4 py-2.5 text-sm dark:border-amber-500/30 dark:bg-amber-500/10">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
            <AlertTriangle className="h-4 w-4" />
            <span className="font-medium">
              {daysLeft !== null ? `${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining` : 'Expiring soon'}
            </span>
          </div>
          <span className="text-amber-700 dark:text-amber-300">
            {legacyUpgrade
              ? status.notice || 'Import a license before the legacy upgrade grace ends.'
              : `Your subscription is expiring${graceEnd ? ` on ${graceEnd.toLocaleDateString()}` : ''}.${isAdmin ? ' Update your billing to avoid service interruption.' : ''}`}
            {isAdmin ? '' : ` ${ASK_ADMIN}`}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {!isAdmin ? null : status.mode === 'offline' ? (
            <Link
              to="/settings/license"
              className="inline-flex items-center gap-1.5 rounded-md bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700 transition-colors"
            >
              {legacyUpgrade ? 'Import license' : 'Upload renewal'}
            </Link>
          ) : (
            <a
              href="https://app.nano.rs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-md bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700 transition-colors"
            >
              Update Billing
            </a>
          )}
          <button
            onClick={() => setDismissed(true)}
            className="rounded p-1 text-amber-400 hover:text-amber-600 hover:bg-amber-100 dark:hover:bg-amber-500/20 transition-colors"
            aria-label="Dismiss banner"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    );
  }

  return null;
}

/** Shown instead of a license CTA to roles that cannot manage the license. */
export const ASK_ADMIN = 'Ask your administrator to install or renew the license.';

export function LicenseHardStopBanner({ status, canManageLicense }: { status: LicenseStatusResponse; canManageLicense: boolean }) {
  const offline = status.mode === 'offline' || status.airgap;
  return (
    <div className="mx-6 mt-3 flex items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50/80 px-4 py-3 text-sm dark:border-red-500/30 dark:bg-red-500/10">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" />
        <div>
          <div className="font-medium text-red-700 dark:text-red-300">
            Licensed features are unavailable
          </div>
          <div className="text-red-700/90 dark:text-red-300/90">
            {status.locked_reason || 'This license reached its hard-stop boundary.'}{' '}
            Open/core features, ingest, search, and stored data remain available.
            {/* NAN-5310: only roles that can manage the license get a CTA. */}
            {!canManageLicense && <> {ASK_ADMIN}</>}
          </div>
        </div>
      </div>
      {!canManageLicense ? null : offline ? (
        <Link
          to="/settings/license"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-red-700"
        >
          <KeyRound className="h-3.5 w-3.5" />
          Import license
        </Link>
      ) : (
        <a
          href="https://app.nano.rs"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex shrink-0 rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-red-700"
        >
          Renew license
        </a>
      )}
    </div>
  );
}

function LicenseTokenRejectedBanner({ rejection }: { rejection: NonNullable<LicenseStatusResponse['token_rejected']> }) {
  return (
    <div role="alert" className="mx-6 mt-3 flex items-start gap-3 rounded-md border border-red-200 bg-red-50/80 px-3 py-2 text-[12px] dark:border-red-500/30 dark:bg-red-500/10">
      <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" strokeWidth={1.5} />
      <div className="min-w-0">
        <div className="font-medium text-red-700 dark:text-red-300">
          License token rejected <span className="font-mono text-[10.5px]">HTTP {rejection.http_status}</span>
        </div>
        <div className="text-red-700/90 dark:text-red-300/90">{rejection.message}</div>
      </div>
    </div>
  );
}
