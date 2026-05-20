// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings status bar — bottom strip on the dedicated /settings shell.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsStatusBar`.
 */

import { useSiemHealthLatest } from '@/hooks/use-api';

export function SettingsStatusBar() {
  const { data: health } = useSiemHealthLatest();

  // Audit health is wedged into the unified health row; for now treat as healthy
  // unless the platform health endpoint signals a problem.
  const healthy = !health || (health as { status?: string })?.status !== 'unhealthy';

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
      <span className={healthy ? 'text-emerald-500' : 'text-yellow-500'}>
        ● {healthy ? 'audit log healthy' : 'audit log degraded'}
      </span>
      <span>changes replicated</span>
      <span className="flex-1" />
      <span className="text-right">{trailText}</span>
    </div>
  );
}
