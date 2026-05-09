// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Consolidated UI color utilities for severity, status, and other badge colors.
 * Use these instead of defining local functions in components.
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type AlertStatus = 'open' | 'new' | 'acknowledged' | 'closed';

/**
 * Color variant for different opacity levels.
 * - 'light' (default): 10% opacity backgrounds, used in most list views
 * - 'dark': 20% opacity backgrounds, used in notebooks and darker contexts
 */
export type ColorVariant = 'light' | 'dark';

const severityColorsLight: Record<SeverityLevel | 'default', string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low: 'bg-primary/10 text-primary border-blue-500/20',
  informational: 'bg-gray-500/10 text-muted-foreground border-gray-500/20',
  default: 'bg-gray-500/10 text-muted-foreground border-gray-500/20',
};

const severityColorsDark: Record<SeverityLevel | 'default', string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-primary/20 text-primary border-blue-500/30',
  informational: 'bg-gray-500/20 text-muted-foreground border-gray-500/30',
  default: 'bg-gray-500/20 text-muted-foreground border-gray-500/30',
};

const statusColorsLight: Record<AlertStatus | 'default', string> = {
  open: 'bg-primary/10 text-primary border-blue-500/20',
  new: 'bg-primary/10 text-primary border-blue-500/20',
  acknowledged: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  closed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  default: 'bg-gray-500/10 text-muted-foreground border-gray-500/20',
};

const statusColorsDark: Record<AlertStatus | 'default', string> = {
  open: 'bg-primary/20 text-primary border-blue-500/30',
  new: 'bg-primary/20 text-primary border-blue-500/30',
  acknowledged: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  closed: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  default: 'bg-gray-500/20 text-muted-foreground border-gray-500/30',
};

/**
 * Get Tailwind CSS classes for severity badge styling.
 * @param severity - The severity level (case-insensitive)
 * @param variant - 'light' for list views (default), 'dark' for notebooks/darker contexts
 */
export function getSeverityColor(severity?: string, variant: ColorVariant = 'light'): string {
  const normalized = (severity?.toLowerCase() ?? 'default') as SeverityLevel | 'default';
  const colors = variant === 'dark' ? severityColorsDark : severityColorsLight;
  return colors[normalized] || colors.default;
}

/**
 * Get Tailwind CSS classes for alert status badge styling.
 * @param status - The alert status (case-insensitive)
 * @param variant - 'light' for list views (default), 'dark' for notebooks/darker contexts
 */
export function getStatusColor(status?: string, variant: ColorVariant = 'light'): string {
  const normalized = (status?.toLowerCase() ?? 'default') as AlertStatus | 'default';
  const colors = variant === 'dark' ? statusColorsDark : statusColorsLight;
  return colors[normalized] || colors.default;
}

/**
 * Get Tailwind CSS classes for detection mode badge styling.
 */
export function getModeColor(mode?: string): string {
  switch (mode?.toLowerCase()) {
    case 'alerting':
      return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20';
    case 'live':
      return 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20';
    case 'staging':
      return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    default:
      return 'bg-gray-500/10 text-muted-foreground border-gray-500/20';
  }
}
