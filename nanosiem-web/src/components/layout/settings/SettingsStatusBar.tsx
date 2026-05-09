// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings status bar — bottom strip on the dedicated /settings shell.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsStatusBar`.
 *
 * Right side updates with the active section so the bar visibly changes as
 * the user navigates between settings pages instead of looking frozen.
 */

import { useLocation } from 'react-router-dom';
import { useSiemHealthLatest } from '@/hooks/use-api';
import { resolveActiveSection, SECTION_BY_ID } from './sections';

export function SettingsStatusBar() {
  const { data: health } = useSiemHealthLatest();
  const location = useLocation();

  // Audit health is wedged into the unified health row; for now treat as healthy
  // unless the platform health endpoint signals a problem.
  const healthy = !health || (health as { status?: string })?.status !== 'unhealthy';

  // Build the right-side trail: nano · settings · {section} · {child? }
  const { sectionId } = resolveActiveSection(location.pathname, location.search);
  const section = sectionId ? SECTION_BY_ID[sectionId] : null;
  const trail = ['nano', 'settings'];
  if (section) {
    if (section.parent) {
      trail.push(section.parent.label.toLowerCase());
    }
    trail.push(section.label.toLowerCase());
  }
  const trailText = trail.join(' · ');

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
      <span className="truncate max-w-[60%] text-right" title={trailText}>{trailText}</span>
    </div>
  );
}
