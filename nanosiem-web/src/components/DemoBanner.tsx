// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Demo mode banner
 *
 * Shown at the top of the content area when the user is a demo user.
 * Displays remaining time, a brief message, and a CTA to sign up.
 */

import { useEffect, useState } from 'react';
import { Clock, ExternalLink, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import type { DemoSessionStatus } from '../lib/api/demo';
import { DEMO_SIGNUP_URL, demoHoursRemaining, demoTimeRemainingText } from '../lib/shared-demo';

export function DemoBanner() {
  const { isDemoUser, user } = useAuth();
  // NAN-4152: a shared demo analyst carries its expiry on /api/auth/me; the
  // Saturn demo deployment asks its own status endpoint.
  const sharedExpiresAt = user?.demo?.active ? user.demo.expires_at : undefined;
  const [status, setStatus] = useState<DemoSessionStatus | null>(null);
  const [now, setNow] = useState(() => new Date());
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (!isDemoUser) return;
    if (sharedExpiresAt !== undefined) {
      const interval = setInterval(() => setNow(new Date()), 60_000);
      return () => clearInterval(interval);
    }

    const fetchStatus = async () => {
      try {
        const s = await api.demo.getSessionStatus();
        setStatus(s);
      } catch {
        // Ignore — might not have demo service
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 60_000); // Update every minute
    return () => clearInterval(interval);
  }, [isDemoUser, sharedExpiresAt]);

  if (!isDemoUser || dismissed) return null;

  const hoursLeft = sharedExpiresAt !== undefined
    ? demoHoursRemaining(sharedExpiresAt, now)
    : status?.remaining_hours ?? 0;
  const timeText = demoTimeRemainingText(hoursLeft);

  return (
    <div
      role="status"
      data-testid="demo-banner"
      className="mx-6 mt-3 flex items-center justify-between gap-3 rounded-md border border-blue-200 bg-blue-50/80 px-3 py-2 text-[12.5px] dark:border-blue-500/30 dark:bg-blue-500/10"
    >
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-blue-600 dark:text-blue-400">
          <Clock className="h-3.5 w-3.5" />
          <span className="font-mono text-[11.5px] font-medium">{timeText}</span>
        </div>
        <span className="text-blue-700 dark:text-blue-300">
          You're exploring a demo instance with sample data. Create rules, investigate cases, and try AI-powered analysis.
        </span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <a
          href={DEMO_SIGNUP_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-2.5 py-1 text-[11.5px] font-medium text-white hover:bg-blue-700 transition-colors"
        >
          Get Full Access
          <ExternalLink className="h-3 w-3" />
        </a>
        <button
          onClick={() => setDismissed(true)}
          className="rounded p-1 text-blue-400 hover:text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-500/20 transition-colors"
          aria-label="Dismiss banner"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
