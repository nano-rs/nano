// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Top Firing Rules Component
 *
 * Shows detection rules with the most matches/alerts.
 * Compact single-line rows for high information density.
 */

import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Flame, TrendingUp } from 'lucide-react';
import { useDetections, fromApiDetection } from '@/hooks/use-api';
import { useMemo } from 'react';

const SEVERITY_STYLE: Record<string, { label: string; color: string }> = {
  critical: { label: 'critical', color: 'text-red-400' },
  high: { label: 'high', color: 'text-orange-400' },
  medium: { label: 'medium', color: 'text-yellow-400' },
  low: { label: 'low', color: 'text-primary' },
  informational: { label: 'info', color: 'text-muted-foreground' },
};

function formatCount(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toString();
}

export function TopFiringRules() {
  const { data: apiRules, loading } = useDetections();

  const topRules = useMemo(() => {
    if (!apiRules) return [];

    return apiRules
      .map(fromApiDetection)
      .map(r => ({
        ...r,
        totalMatches: r.matchCount || 0,
      }))
      .filter(r => r.status === 'active' && r.totalMatches > 0)
      .sort((a, b) => b.totalMatches - a.totalMatches)
      .slice(0, 8);
  }, [apiRules]);

  return (
    <Card className="bg-card border-0 rounded-2xl shadow-lg h-full">
      <CardHeader className="pb-1 pt-4 px-4">
        <CardTitle className="text-foreground flex items-center gap-2 text-sm font-medium">
          <Flame className="w-4 h-4 text-orange-400" />
          Top Firing Rules
        </CardTitle>
      </CardHeader>
      <CardContent className="px-2 pb-2">
        {loading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
          </div>
        ) : topRules.length === 0 ? (
          <div className="text-center py-6">
            <TrendingUp className="w-6 h-6 text-muted-foreground mx-auto mb-1.5" />
            <p className="text-xs text-muted-foreground">No rule matches yet</p>
          </div>
        ) : (
          <div className="space-y-0.5">
            {topRules.map((rule, index) => {
              const sev = SEVERITY_STYLE[rule.severity] || SEVERITY_STYLE.medium;
              return (
                <Link
                  key={rule.id}
                  to={`/rules/${rule.id}`}
                  className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-accent/50 transition-colors group"
                >
                  <span className="text-[10px] font-bold text-muted-foreground w-4 shrink-0">
                    {index + 1}
                  </span>
                  <span className="text-xs text-foreground truncate flex-1 group-hover:text-primary">
                    {rule.name}
                  </span>
                  <span className={`text-[10px] font-medium ${sev.color} shrink-0`}>
                    {sev.label}
                  </span>
                  {rule.mode === 'live' && (
                    <span className="text-[10px] text-emerald-400 shrink-0">live</span>
                  )}
                  <span className="text-xs font-semibold text-foreground w-10 text-right shrink-0">
                    {formatCount(rule.totalMatches)}
                  </span>
                </Link>
              );
            })}
          </div>
        )}
        {topRules.length > 0 && (
          <Link
            to="/rules"
            className="block text-center text-[10px] text-primary hover:text-blue-300 mt-2 pt-2 border-t border-border/50"
          >
            View all rules →
          </Link>
        )}
      </CardContent>
    </Card>
  );
}
