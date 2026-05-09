// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Access Control eyebrow + title block. Shared across every Access tab.
 * Mirrors `design-ref/shadcn/settings-users.jsx` `AccessHeader`.
 */

import { SECTION_BY_ID, GROUP_LABEL } from '@/components/layout/settings/sections';

export type AccessTabId = 'users' | 'groups' | 'roles' | 'api-keys' | 'sessions';

const TAB_TITLES: Record<AccessTabId, { label: string; desc: string }> = {
  users: { label: 'Users', desc: 'Manage user accounts, status, and group memberships.' },
  groups: { label: 'Groups', desc: 'Group users to share roles, scopes, and SCIM mappings.' },
  roles: { label: 'Roles', desc: 'Permission sets that determine what users can do.' },
  'api-keys': { label: 'API Keys', desc: 'Programmatic access for CI, automation, and integrations.' },
  sessions: { label: 'Sessions', desc: 'Active browser and API sessions across users and clients.' },
};

interface AccessHeaderProps {
  tab: AccessTabId;
}

export function AccessHeader({ tab }: AccessHeaderProps) {
  // Use the registry to derive the eyebrow group label so it tracks the rail.
  const accessSection = SECTION_BY_ID['access'];
  const groupLabel = accessSection ? GROUP_LABEL[accessSection.group] : 'Administration';
  const titleEntry = TAB_TITLES[tab];

  return (
    <div className="px-5 pt-5 pb-2 shrink-0">
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
        {groupLabel}
      </div>
      <div className="text-[18px] font-semibold text-foreground tracking-tight leading-none">
        Access Control · {titleEntry.label}
      </div>
      {titleEntry.desc && (
        <div className="text-[12px] text-muted-foreground mt-1.5 max-w-[720px]">
          {titleEntry.desc}
        </div>
      )}
    </div>
  );
}

