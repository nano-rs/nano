// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Alert Summary Component
 *
 * Shows alert severity breakdown as clickable badges on the dashboard.
 * Each badge links to /cases since alerts are grouped into cases.
 */

import { Link } from 'react-router-dom';
import { Loader2, CircleAlert } from 'lucide-react';
import { useAlertCounts } from '@/hooks/use-api';

const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    activeTextColor: 'text-red-400',
    activeBorderColor: 'border-red-500/40',
  },
  high: {
    label: 'High',
    activeTextColor: 'text-orange-400',
    activeBorderColor: 'border-orange-500/40',
  },
  medium: {
    label: 'Medium',
    activeTextColor: 'text-yellow-400',
    activeBorderColor: 'border-yellow-500/40',
  },
  low: {
    label: 'Low',
    activeTextColor: 'text-primary',
    activeBorderColor: 'border-primary/40',
  },
} as const;

export function AlertSummary() {
  const { data: alertCounts, loading, error } = useAlertCounts();

  if (loading) {
    return (
      <div className="flex items-center justify-center py-6">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error || !alertCounts) {
    return (
      <div className="flex items-center justify-center gap-2 py-6 text-muted-foreground">
        <CircleAlert className="w-4 h-4" />
        <span className="text-sm">Unable to load alert counts</span>
      </div>
    );
  }

  const severities = ['critical', 'high', 'medium', 'low'] as const;
  const total = alertCounts.total || 0;

  return (
    <div className="flex flex-wrap items-center justify-center gap-3">
      {severities.map((severity) => {
        const count = alertCounts.by_severity?.[severity] || 0;
        const config = SEVERITY_CONFIG[severity];
        const hasAlerts = count > 0;

        return (
          <Link
            key={severity}
            to="/cases"
            className={`
              relative flex flex-col items-center justify-center
              min-w-[70px] px-3 py-2 rounded-lg
              border transition-all duration-200 hover:scale-105
              ${hasAlerts
                ? `bg-card ${config.activeBorderColor}`
                : 'bg-card/50 border-border/50'
              }
            `}
          >
            <span className={`text-xl font-semibold ${hasAlerts ? config.activeTextColor : 'text-muted-foreground'}`}>
              {count}
            </span>
            <span className="text-[11px] text-muted-foreground">
              {config.label}
            </span>

            {/* Pulse indicator for critical alerts */}
            {severity === 'critical' && count > 0 && (
              <div className="absolute -top-1 -right-1">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
                </span>
              </div>
            )}
          </Link>
        );
      })}

      {/* Total badge */}
      <Link
        to="/cases"
        className={`
          flex flex-col items-center justify-center
          min-w-[70px] px-3 py-2 rounded-lg
          border transition-all duration-200 hover:scale-105
          ${total > 0 ? 'bg-card border-border' : 'bg-card/50 border-border/50'}
        `}
      >
        <span className={`text-xl font-semibold ${total > 0 ? 'text-foreground' : 'text-muted-foreground'}`}>
          {total}
        </span>
        <span className="text-[11px] text-muted-foreground">Total</span>
      </Link>
    </div>
  );
}
