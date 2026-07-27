// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import type { LateralBand, LateralMethodGroup, LateralNodeType } from './types';
import { nplQuotedBody } from '@/lib/npl-quote';

// Band colors lifted verbatim from `design-ref/shadcn/lateral-graph.jsx`.
export const LATERAL_BAND_COLOR: Record<LateralBand, string> = {
  critical: 'oklch(68% 0.18 28)',
  high: 'oklch(76% 0.15 60)',
  medium: 'oklch(78% 0.14 85)',
  low: 'oklch(70% 0.08 220)',
};

// Method colors deliberately avoid the severity hues (red 28, orange 60,
// yellow 85, blue 220) so a red edge never reads as "critical." Severity
// owns the saturated heat ramp; methods use a separate desaturated
// categorical palette: violet (identity/auth), teal (network/transport),
// green (process/execution).
export const LATERAL_METHOD_COLOR: Record<string, string> = {
  'auth-rdp': 'oklch(72% 0.12 300)',
  'auth-smb': 'oklch(72% 0.12 300)',
  'auth-kerberos': 'oklch(72% 0.12 300)',
  'auth-winrm': 'oklch(72% 0.12 300)',
  'network-smb': 'oklch(75% 0.14 175)',
  'network-rdp': 'oklch(75% 0.14 175)',
  'network-winrm': 'oklch(75% 0.14 175)',
  'network-other': 'oklch(75% 0.14 175)',
  'process-psexec': 'oklch(72% 0.11 155)',
  'process-wmic': 'oklch(72% 0.11 155)',
  'process-psrem': 'oklch(72% 0.11 155)',
};

export const LATERAL_METHOD_LABEL: Record<string, string> = {
  'auth-rdp': 'RDP',
  'auth-smb': 'SMB',
  'auth-kerberos': 'Kerberos',
  'auth-winrm': 'WinRM',
  'network-smb': 'SMB·445',
  'network-rdp': 'RDP·3389',
  'network-winrm': 'WinRM·5985',
  'network-other': 'net',
  'process-psexec': 'PsExec',
  'process-wmic': 'wmic',
  'process-psrem': 'PS-rem',
};

export function methodGroup(methodId: string): LateralMethodGroup {
  if (methodId.startsWith('auth-')) return 'auth';
  if (methodId.startsWith('network-')) return 'network';
  return 'process';
}

export function bandColor(band: LateralBand | string | undefined): string {
  return LATERAL_BAND_COLOR[(band as LateralBand) ?? 'low'] ?? LATERAL_BAND_COLOR.low;
}

export function methodColor(methodId: string): string {
  return LATERAL_METHOD_COLOR[methodId] ?? 'oklch(65% 0.05 250)';
}

// Format an event count compactly: 1234 → "1.2K".
export function fmtCount(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

// SVG icon per node type. Stroke-only, 24×24 viewBox, 1.5 stroke-width.
export function NodeIcon({
  type,
  className,
}: {
  type: LateralNodeType;
  className?: string;
}): ReactNode {
  const base = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
    className,
  } as const;
  switch (type) {
    case 'user':
      return (
        <svg {...base}>
          <circle cx="12" cy="8" r="4" />
          <path d="M4 21v-1a7 7 0 0 1 14 0v1" />
        </svg>
      );
    case 'ip':
      return (
        <svg {...base}>
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20" />
        </svg>
      );
    case 'process':
      return (
        <svg {...base}>
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M8 9h8M8 13h6M8 17h4" />
        </svg>
      );
    case 'host':
    default:
      return (
        <svg {...base}>
          <rect x="3" y="4" width="18" height="12" rx="1.5" />
          <path d="M8 20h8M12 16v4" />
        </svg>
      );
  }
}

export const LATERAL_METHODS: {
  id: LateralMethodGroup;
  label: string;
  sub: string;
  color: string;
}[] = [
  { id: 'auth', label: 'Auth', sub: 'RDP · SMB · Kerberos · WinRM', color: 'oklch(72% 0.12 300)' },
  { id: 'network', label: 'Network', sub: '445 · 3389 · 5985 · 22', color: 'oklch(75% 0.14 175)' },
  { id: 'process', label: 'Process', sub: 'psexec · wmic · ps remoting', color: 'oklch(72% 0.11 155)' },
];

// Quote a value for nPL `field="value"` syntax, escaping as needed.
export function quoteValue(value: string): string {
  if (/^[A-Za-z0-9_.-]+$/.test(value)) return value;
  const escaped = nplQuotedBody(value);
  return `"${escaped}"`;
}

// Strip `| lateral …` (and its args) from a query so the user can leave the
// surface and explore the dimension as raw events. Mirrors the cloud-dossier
// regex (NAN-395 invariant 3).
export function stripLateralCommand(query: string): string {
  return query.replace(/\s*\|\s*lateral\b[^|]*/i, '').trim();
}

// Rewrite the `| lateral` arg to seed on a different entity. Drops any
// existing seed=, entity=, methods=, maxhops=, window= so the rebuilt command
// is clean. Mirrors cloud-dossier's `appendCloudArg` rewrite pattern.
export function rewriteLateralSeed(
  _query: string,
  field: 'src_host' | 'user' | 'src_ip',
  value: string
): string {
  const escaped = nplQuotedBody(value);
  const filter = /^[A-Za-z0-9_.-]+$/.test(value) ? `${field}=${value}` : `${field}="${escaped}"`;
  // Prior base filters were often entity-filters that conflict with the new
  // seed, so we drop the whole prior search and let the new seed become the
  // entire query.
  const seedMode = field === 'user' ? 'seed=user' : 'seed=host';
  return `${filter} | lateral ${seedMode}`;
}
