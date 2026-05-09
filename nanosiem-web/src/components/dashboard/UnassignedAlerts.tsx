// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Unassigned Alerts Component
 *
 * Shows open alerts that haven't been assigned to anyone yet.
 * Prioritized by severity for SOC triage workflow.
 */

import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, Bell, AlertTriangle } from 'lucide-react';
import { api, Alert } from '@/lib/api';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const SEVERITY_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: 'crit', color: 'text-red-400', bg: 'bg-red-500/10' },
  high: { label: 'high', color: 'text-orange-400', bg: 'bg-orange-500/10' },
  medium: { label: 'med', color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  low: { label: 'low', color: 'text-primary', bg: 'bg-primary/10' },
  informational: { label: 'info', color: 'text-muted-foreground', bg: 'bg-muted' },
};

function formatCompactTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 60) return `${diffMins}m`;
  if (diffHours < 24) return `${diffHours}h`;
  if (diffDays < 30) return `${diffDays}d`;
  return `${Math.floor(diffDays / 30)}mo`;
}

export function UnassignedAlerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchAlerts = useCallback(async () => {
    try {
      // Fetch open alerts (new status = not acknowledged or closed)
      const result = await api.listAlerts({ status: 'new', limit: 20 });
      // Filter to unassigned and sort by severity then time
      const unassigned = result
        .filter((a) => !a.assigned_to)
        .sort((a, b) => {
          const sevDiff = (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
          if (sevDiff !== 0) return sevDiff;
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        });
      setAlerts(unassigned);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30000); // Refresh every 30s for alerts
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const handleAlertClick = (alert: Alert) => {
    // Navigate to alerts page with this alert selected
    navigate(`/alerts?selected=${alert.id}`);
  };

  return (
    <Card className="bg-card border-0 rounded-2xl shadow-lg h-full">
      <CardHeader className="pb-1 pt-4 px-4">
        <div className="flex items-center justify-between">
          <CardTitle className="text-foreground flex items-center gap-2 text-sm font-medium">
            <Bell className="w-4 h-4 text-amber-400" />
            Unassigned Alerts
          </CardTitle>
          {alerts.length > 0 && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-5">
              {alerts.length}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="px-2 pb-2">
        {isLoading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
          </div>
        ) : alerts.length === 0 ? (
          <div className="text-center py-6">
            <Bell className="w-6 h-6 text-muted-foreground mx-auto mb-1.5" />
            <p className="text-xs text-muted-foreground">No unassigned alerts</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">All alerts have been triaged</p>
          </div>
        ) : (
          <div className="space-y-0.5">
            {alerts.slice(0, 8).map((alert) => {
              const sev = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.medium;
              const time = formatCompactTime(new Date(alert.created_at));
              const eventCount = alert.matched_event_count || alert.matched_events?.length || 0;

              return (
                <button
                  key={alert.id}
                  onClick={() => handleAlertClick(alert)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-accent/50 transition-colors group text-left"
                >
                  {alert.severity === 'critical' && (
                    <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 animate-pulse" />
                  )}
                  <span className={`text-[10px] font-medium ${sev.color} shrink-0 w-7`}>
                    {sev.label}
                  </span>
                  <span className="text-xs text-foreground truncate flex-1 group-hover:text-primary">
                    {alert.rule_name || 'Unknown Rule'}
                  </span>
                  <span className="text-[10px] text-muted-foreground shrink-0">
                    {eventCount} evt
                  </span>
                  <span className="text-[10px] text-muted-foreground w-6 text-right shrink-0">
                    {time}
                  </span>
                </button>
              );
            })}
            {alerts.length > 8 && (
              <Link
                to="/alerts?status=new"
                className="block text-center text-[10px] text-primary hover:text-blue-300 pt-1"
              >
                +{alerts.length - 8} more
              </Link>
            )}
          </div>
        )}
        {alerts.length > 0 && (
          <Link
            to="/alerts?status=new"
            className="block text-center text-[10px] text-primary hover:text-blue-300 mt-2 pt-2 border-t border-border/50"
          >
            View all alerts →
          </Link>
        )}
      </CardContent>
    </Card>
  );
}
