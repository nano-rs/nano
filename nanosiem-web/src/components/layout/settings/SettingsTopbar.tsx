// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings topbar — breadcrumb + Recent Changes button + theme/PIVT/bell.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsTopbar`.
 */

import { Link, useLocation } from 'react-router-dom';
import { Clock, Sun, Moon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { useTheme } from 'next-themes';
import { PivtSummon } from '@/enterprise/components/pivt/PivtSummon';
import type { PivtState } from '@/enterprise/hooks/use-pivt-state';
import { NotificationBell } from '@/components/NotificationBell';
import { GROUP_LABEL, SECTION_BY_ID, resolveActiveSection } from './sections';
import { useAuditLog } from '@/hooks/use-api';

interface SettingsTopbarProps {
  onOpenAudit: () => void;
  auditOpen: boolean;
  pivt: PivtState;
}

export function SettingsTopbar({ onOpenAudit, auditOpen, pivt }: SettingsTopbarProps) {
  const location = useLocation();
  const { resolvedTheme, setTheme } = useTheme();
  const theme = resolvedTheme === 'light' ? 'light' : 'dark';

  const { sectionId, parentId } = resolveActiveSection(location.pathname, location.search);
  const section = sectionId ? SECTION_BY_ID[sectionId] : null;
  const parent = parentId ? SECTION_BY_ID[parentId] : null;
  const groupLabel = section ? GROUP_LABEL[section.group] : null;

  // Pull a count for the "Recent changes" button. Cheap query — last 24h, 50 entries.
  const { data: auditData } = useAuditLog({ limit: 50 });
  const auditCount = auditData?.logs?.length ?? 0;

  return (
    <div
      className="col-start-2 row-start-1 flex items-center px-3.5 gap-3.5 border-b border-border h-[42px]"
      style={{ background: 'var(--panel)' }}
    >
      {/* Breadcrumb */}
      <nav className="text-[13px] flex items-center gap-2 whitespace-nowrap min-w-0 overflow-hidden" aria-label="Breadcrumb">
        <Link to="/settings" className="text-muted-foreground hover:text-foreground transition-colors">Settings</Link>
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

      <Separator orientation="vertical" className="h-5 mx-1" />

      <PivtSummon state={pivt} />

      <Separator orientation="vertical" className="h-5 mx-0.5" />

      <NotificationBell />

      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-[26px] w-[26px]"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          >
            {theme === 'dark' ? <Sun className="w-[14px] h-[14px]" /> : <Moon className="w-[14px] h-[14px]" />}
          </Button>
        </TooltipTrigger>
        <TooltipContent side="bottom">
          {theme === 'dark' ? 'Switch to light' : 'Switch to dark'}
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

