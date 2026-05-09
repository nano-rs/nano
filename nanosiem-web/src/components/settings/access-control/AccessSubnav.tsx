// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Underlined-tab subnav for Access Control. Mirrors `design-ref/shadcn/
 * settings-users.jsx` `AccessSubnav` — small icon, label, mono count, brand
 * underline on the active tab.
 *
 * Tabs are filtered against the user's permissions so e.g. Sessions hides
 * for someone without `users:view`.
 */

import { useNavigate, useSearchParams } from 'react-router-dom';
import { Users as UsersIcon, UserCog, KeyRound, Bolt, Clock } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';
import type { AccessTabId } from './AccessHeader';

interface TabDef {
  id: AccessTabId;
  label: string;
  icon: LucideIcon;
  /** ANY of these permissions reveals the tab. */
  permissions: string[];
}

const TABS: TabDef[] = [
  { id: 'users', label: 'Users', icon: UsersIcon, permissions: ['users:view'] },
  { id: 'groups', label: 'Groups', icon: UserCog, permissions: ['groups:view'] },
  { id: 'roles', label: 'Roles', icon: KeyRound, permissions: ['roles:view'] },
  { id: 'api-keys', label: 'API Keys', icon: Bolt, permissions: ['apikeys:view'] },
  { id: 'sessions', label: 'Sessions', icon: Clock, permissions: ['users:view'] },
];

interface AccessSubnavProps {
  activeTab: AccessTabId;
  /** Optional per-tab counts. Tabs without a count render no number. */
  counts?: Partial<Record<AccessTabId, number | string>>;
}

export function AccessSubnav({ activeTab, counts = {} }: AccessSubnavProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { hasAnyPermission } = useAuth();

  const visibleTabs = TABS.filter(t => hasAnyPermission(t.permissions));

  const onJump = (tab: AccessTabId) => {
    const next = new URLSearchParams(searchParams);
    next.set('tab', tab);
    navigate(`/settings/access-control?${next.toString()}`, { replace: true });
  };

  return (
    <div className="flex items-center gap-1 border-b border-border px-5 shrink-0">
      {visibleTabs.map(t => {
        const Icon = t.icon;
        const active = activeTab === t.id;
        const count = counts[t.id];
        return (
          <button
            key={t.id}
            onClick={() => onJump(t.id)}
            className={cn(
              'relative h-9 px-3 flex items-center gap-1.5 text-[12px] transition-colors',
              active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground/80',
            )}
          >
            <Icon className={cn('w-[12px] h-[12px]', active ? 'text-primary' : 'text-muted-foreground')} />
            <span className="font-medium">{t.label}</span>
            {count !== undefined && (
              <span className={cn('font-mono text-[10px] tabular-nums', active ? 'text-muted-foreground' : 'text-muted-foreground/70')}>
                {count}
              </span>
            )}
            {active && <span className="absolute -bottom-px left-0 right-0 h-[2px] bg-primary" />}
          </button>
        );
      })}
    </div>
  );
}
