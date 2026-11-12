// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings status bar — bottom strip on the dedicated /settings shell.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsStatusBar`.
 */

import { useSiemHealthLatest } from '@/hooks/use-api';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';
import { SHELL_READ_PERMISSIONS } from '@/lib/shell-permissions';

export function SettingsStatusBar() {
  // NAN-5325: don't request health a role can't read, and don't claim
  // "audit log healthy" when nothing was read.
  const { hasPermission } = useAuth();
  const canReadHealth = hasPermission(SHELL_READ_PERMISSIONS.siemHealth);
  const { data: health } = useSiemHealthLatest({ skip: !canReadHealth });
  const { edition } = useCapabilities();
  const { data: license } = useQuery({
    queryKey: ['license-status'],
    queryFn: () => api.getLicenseStatus(),
    staleTime: 60_000,
    retry: false,
    enabled: edition === 'enterprise',
  });

  // Audit health is wedged into the unified health row; for now treat as healthy
  // unless the platform health endpoint signals a problem.
  const healthy = !health || (health as { status?: string })?.status !== 'unhealthy';
  const showHealth = canReadHealth && !!health;

  // Right-side trail: `nano · settings`. The previous `{section} · {child}`
  // suffix duplicated the SettingsTopbar breadcrumb directly above it
  // (NAN-911 F-13); the topbar is the source of truth for "where am I in
  // settings", and the status-bar trail is just a brand anchor matching the
  // global `nano · {pagename}` pattern used elsewhere.
  const trailText = 'nano · settings';

  return (
    <div
      className="col-start-2 row-start-3 flex items-center px-3.5 border-t border-border font-mono text-[10.5px] text-muted-foreground gap-[18px] tracking-wide h-[22px]"
      style={{ background: 'var(--panel)' }}
    >
      {showHealth && (
        <span className={healthy ? 'text-emerald-500' : 'text-yellow-500'}>
          ● {healthy ? 'audit log healthy' : 'audit log degraded'}
        </span>
      )}
      <span>changes replicated</span>
      {license?.entitlement?.kind === 'trial' && (
        <span className={license.state === 'locked' ? 'text-red-500' : license.state === 'grace_period' ? 'text-yellow-500' : 'text-foreground'}>
          Trial — {license.entitlement.days_remaining} days left
        </span>
      )}
      <span className="flex-1" />
      <span className="text-right">{trailText}</span>
    </div>
  );
}
