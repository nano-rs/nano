// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Mini Stats Component
 *
 * Compact horizontal stat cards with animated counters and glow effects.
 */

import { Loader2, Activity, AlertTriangle, Shield, Zap } from 'lucide-react';
import { AnimatedCounter } from './AnimatedCounter';

interface Stat {
  label: string;
  value: number;
  displayValue: string;
  icon: React.ReactNode;
  color: string;
  glowColor: string;
}

interface MiniStatsProps {
  events24h: number;
  openAlerts: number;
  activeRules: number;
  eventsPerSec?: number;
  loading?: boolean;
}

export function MiniStats({ events24h, openAlerts, activeRules, eventsPerSec, loading }: MiniStatsProps) {
  const formatNumber = (n: number): string => {
    if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
    if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
    return n.toString();
  };

  const stats: Stat[] = [
    {
      label: 'Events 24h',
      value: events24h,
      displayValue: formatNumber(events24h),
      icon: <Activity className="w-5 h-5" />,
      color: 'text-primary',
      glowColor: 'shadow-blue-500/20',
    },
    {
      label: 'Open Alerts',
      value: openAlerts,
      displayValue: openAlerts.toString(),
      icon: <AlertTriangle className="w-5 h-5" />,
      color: openAlerts > 0 ? 'text-amber-400' : 'text-green-400',
      glowColor: openAlerts > 0 ? 'shadow-amber-500/20' : 'shadow-green-500/20',
    },
    {
      label: 'Active Rules',
      value: activeRules,
      displayValue: activeRules.toString(),
      icon: <Shield className="w-5 h-5" />,
      color: 'text-purple-400',
      glowColor: 'shadow-purple-500/20',
    },
    {
      label: 'Ingestion',
      value: eventsPerSec || 0,
      displayValue: eventsPerSec !== undefined
        ? eventsPerSec < 1 ? '<1/s' : `${Math.round(eventsPerSec)}/s`
        : '-',
      icon: <Zap className="w-5 h-5" />,
      color: 'text-cyan-400',
      glowColor: 'shadow-cyan-500/20',
    },
  ];

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="bg-card/80 backdrop-blur-sm rounded-2xl p-5 flex items-center justify-center border border-border"
          >
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {stats.map((stat, index) => (
        <div
          key={stat.label}
          className={`
            relative overflow-hidden
            bg-card/80 backdrop-blur-sm rounded-2xl p-5
            border border-border hover:border-border
            transition-all duration-300 hover:scale-[1.02]
            shadow-lg ${stat.glowColor} hover:shadow-xl
            group
          `}
          style={{
            animationDelay: `${index * 100}ms`,
          }}
        >
          {/* Animated gradient background */}
          <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
            <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent" />
          </div>

          {/* Content */}
          <div className="relative flex items-center gap-4">
            <div className={`${stat.color} p-2 rounded-xl bg-accent/50 group-hover:scale-110 transition-transform duration-300`}>
              {stat.icon}
            </div>
            <div>
              <div className="text-2xl font-bold text-foreground">
                {stat.label === 'Ingestion' ? (
                  <span>{stat.displayValue}</span>
                ) : (
                  <AnimatedCounter
                    value={stat.value}
                    formatFn={formatNumber}
                    duration={1200}
                  />
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">{stat.label}</p>
            </div>
          </div>

          {/* Pulse indicator for alerts */}
          {stat.label === 'Open Alerts' && openAlerts > 0 && (
            <div className="absolute top-3 right-3">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
              </span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
