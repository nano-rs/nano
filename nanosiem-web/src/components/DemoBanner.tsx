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

export function DemoBanner() {
  const { isDemoUser } = useAuth();
  const [status, setStatus] = useState<DemoSessionStatus | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (!isDemoUser) return;

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
  }, [isDemoUser]);

  if (!isDemoUser || dismissed) return null;

  const hoursLeft = status?.remaining_hours ?? 0;
  const timeText = hoursLeft > 24
    ? `${Math.floor(hoursLeft / 24)}d ${Math.floor(hoursLeft % 24)}h remaining`
    : hoursLeft > 1
    ? `${Math.floor(hoursLeft)}h remaining`
    : `${Math.max(1, Math.floor(hoursLeft * 60))}m remaining`;

  return (
    <div className="mx-6 mt-3 flex items-center justify-between gap-3 rounded-lg border border-blue-200 bg-blue-50/80 px-4 py-2.5 text-sm dark:border-blue-500/30 dark:bg-blue-500/10">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-blue-600 dark:text-blue-400">
          <Clock className="h-4 w-4" />
          <span className="font-medium">{timeText}</span>
        </div>
        <span className="text-blue-700 dark:text-blue-300">
          You're exploring a demo instance with sample data. Create rules, investigate cases, and try AI-powered analysis.
        </span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <a
          href="https://nano.rs"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 transition-colors"
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
