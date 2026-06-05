// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * License enforcement banners
 *
 * Grace period: dismissable warning banner at top of content area
 * Locked: full-page lockout overlay (cannot be dismissed)
 */

import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { AlertTriangle, Lock, X, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import type { LicenseStatusResponse } from '../lib/api';
import { useCapabilities } from '@/hooks/use-capabilities';

export function LicenseBanner() {
  // License enforcement is enterprise-only — the open edition strips the
  // /api/license endpoint entirely (NAN-1193), so skip the poll (and the
  // 404s it would otherwise generate) and never render in open builds.
  const { edition } = useCapabilities();
  const isEnterprise = edition === 'enterprise';

  const [status, setStatus] = useState<LicenseStatusResponse | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const location = useLocation();

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
    // Re-check every 5 minutes
    const interval = setInterval(fetchStatus, 5 * 60_000);
    return () => clearInterval(interval);
  }, [isEnterprise]);

  // Air-gap installs enforce a signed offline license but have no phone-home,
  // so `enforcement_enabled` (which tracks LICENSE_URL) is false; treat air-gap
  // as enforced too (NAN-1222).
  const enforced = !!status?.enforcement_enabled || !!status?.airgap;

  // Don't show anything if not enforced, active, or no status yet
  if (!isEnterprise || !status || !enforced || status.state === 'active') {
    return null;
  }

  // Full lockout page
  if (status.state === 'locked') {
    // Air-gapped: the only recovery is importing a signed offline license, so
    // point at the import surface (app.nano.rs is unreachable across the gap).
    // Suppress the overlay while the operator is on the import page itself so
    // the dropzone underneath stays usable.
    if (status.airgap) {
      if (location.pathname.startsWith('/settings/airgap-import')) {
        return null;
      }
      return <AirgapLockoutOverlay reason={status.locked_reason} />;
    }
    return <LicenseLockoutOverlay reason={status.locked_reason} />;
  }

  // Grace period warning (dismissable)
  if (status.state === 'grace_period' && !dismissed) {
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
            Your subscription is expiring{graceEnd ? ` on ${graceEnd.toLocaleDateString()}` : ''}.
            Update your billing to avoid service interruption.
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <a
            href="https://app.nano.rs"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700 transition-colors"
          >
            Update Billing
          </a>
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

function LicenseLockoutOverlay({ reason }: { reason?: string }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/95 backdrop-blur-sm">
      <div className="mx-auto max-w-md text-center space-y-6 p-8">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-500/10">
          <Lock className="h-8 w-8 text-red-600 dark:text-red-400" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            Subscription Expired
          </h1>
          <p className="text-muted-foreground">
            {reason || 'Your subscription has expired. Data is preserved but inaccessible until you resubscribe.'}
          </p>
        </div>
        <a
          href="https://app.nano.rs"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center justify-center rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          Resubscribe at app.nano.rs
        </a>
        <p className="text-xs text-muted-foreground">
          Your data is safe. Full access will be restored within 5 minutes of resubscribing.
        </p>
      </div>
    </div>
  );
}

/**
 * Air-gapped lockout (NAN-1222). An air-gapped deployment without a valid,
 * non-expired signed offline license fails closed. There is no outbound network
 * to resubscribe over, so the only recovery is importing a signed offline
 * license bundle. The CTA routes to the in-app import surface (which is
 * license-guard-exempt server-side and un-overlaid client-side).
 */
function AirgapLockoutOverlay({ reason }: { reason?: string }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/95 backdrop-blur-sm">
      <div className="mx-auto max-w-md text-center space-y-6 p-8">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-500/10">
          <Lock className="h-8 w-8 text-red-600 dark:text-red-400" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            License Required
          </h1>
          <p className="text-muted-foreground">
            {reason ||
              'This air-gapped deployment requires a signed offline license. Import a license bundle to unlock access.'}
          </p>
        </div>
        <Link
          to="/settings/airgap-import"
          className="inline-flex items-center justify-center gap-2 rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <KeyRound className="h-4 w-4" />
          Import offline license
        </Link>
        <p className="text-xs text-muted-foreground">
          Your data is safe. Access is restored as soon as a valid signed
          license bundle is imported.
        </p>
      </div>
    </div>
  );
}
