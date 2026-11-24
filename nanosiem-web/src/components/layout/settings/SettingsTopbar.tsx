// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings topbar: breadcrumb + Recent Changes button + PIVT/bell/help.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsTopbar`. The
 * light/dark toggle and theme strip live in the rail footer (NAN-5858).
 */

import { Link, useLocation } from 'react-router-dom';
import { Clock } from 'lucide-react';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { PivtSummon } from '@/enterprise/components/pivt/PivtSummon';
import { useCapabilities } from '@/hooks/use-capabilities';
import type { PivtState } from '@/enterprise/hooks/use-pivt-state';
import { NotificationBell } from '@/components/NotificationBell';
import { HelpMenu } from '@/components/support/HelpMenu';
import { GROUP_LABEL, SECTION_BY_ID, SETTINGS_LANDING_PERMISSIONS, resolveActiveSection } from './sections';
import { useRecentAuditChanges } from '@/hooks/use-api';
import { useAuth } from '@/contexts/AuthContext';
import { SHELL_READ_PERMISSIONS } from '@/lib/shell-permissions';

interface SettingsTopbarProps {
  onOpenAudit: () => void;
  auditOpen: boolean;
  pivt: PivtState;
}

export function SettingsTopbar({ onOpenAudit, auditOpen, pivt }: SettingsTopbarProps) {
  const location = useLocation();
  const { capabilities } = useCapabilities();

  const { sectionId, parentId } = resolveActiveSection(location.pathname, location.search);
  const section = sectionId ? SECTION_BY_ID[sectionId] : null;
  const parent = parentId ? SECTION_BY_ID[parentId] : null;
  const groupLabel = section ? GROUP_LABEL[section.group] : null;

  // Pull a count for the "Recent changes" button. Cheap query — last 24h, 50 entries.
  // NAN-5325: only for roles that can read the audit log.
  const { hasPermission, hasAnyPermission } = useAuth();
  const canReadAudit = hasPermission(SHELL_READ_PERMISSIONS.audit);
  // NAN-5850: a role that cannot open the landing (hunts:view only) gets a plain crumb, not a link to Access Denied.
  const canOpenLanding = hasAnyPermission([...SETTINGS_LANDING_PERMISSIONS]);
  const { data: auditData } = useRecentAuditChanges({ limit: 50 }, { skip: !canReadAudit });
  const auditCount = auditData?.logs?.length ?? 0;

  return (
    <div
      className="col-start-2 row-start-1 flex items-center px-3.5 gap-3.5 border-b border-border h-[42px]"
      style={{ background: 'var(--panel)' }}
    >
      {/* Breadcrumb */}
      <nav className="text-[13px] flex items-center gap-2 whitespace-nowrap min-w-0 overflow-hidden" aria-label="Breadcrumb">
        {canOpenLanding ? (
          <Link to="/settings" className="text-muted-foreground hover:text-foreground transition-colors">Settings</Link>
        ) : (
          <span className="text-muted-foreground">Settings</span>
        )}
        {groupLabel && (
          <>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-muted-foreground">{groupLabel}</span>
          </>
        )}
        {parent && (
          <>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-muted-foreground">{parent.label}</span>
          </>
        )}
        {section && (
          <>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-foreground font-medium truncate">{section.label}</span>
          </>
        )}
      </nav>

      <div className="flex-1" />

      {/* Recent changes trigger */}
      {canReadAudit && (
      <button
        onClick={onOpenAudit}
        className={cn(
          'h-7 px-2.5 rounded-md border text-[11.5px] flex items-center gap-1.5 transition-colors',
          auditOpen
            ? 'border-foreground/20 bg-card text-foreground'
            : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-foreground/20',
        )}
        title="Recent configuration changes"
      >
        <Clock className="w-[12px] h-[12px] text-muted-foreground" />
        <span>Recent changes</span>
        {auditCount > 0 && (
          <span className="font-mono text-[10px] text-muted-foreground/60 tabular-nums">{auditCount}</span>
        )}
      </button>
      )}

      <Separator orientation="vertical" className="h-5 mx-1" />

      {/* NAN-2356: pivt is enterprise; AppLayout gates the same mount. The
          trailing separator goes with it — otherwise open builds render two
          adjacent dividers where the control used to be. */}
      {capabilities.melod && (
        <>
          <PivtSummon state={pivt} />
          <Separator orientation="vertical" className="h-5 mx-0.5" />
        </>
      )}

      <NotificationBell />
      <HelpMenu />

    </div>
  );
}

