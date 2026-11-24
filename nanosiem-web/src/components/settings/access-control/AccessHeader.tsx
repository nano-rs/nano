// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Access Control eyebrow + title block. Shared across every Access tab.
 * Mirrors `design-ref/shadcn/settings-users.jsx` `AccessHeader`.
 */

import { SECTION_BY_ID, GROUP_LABEL } from '@/components/layout/settings/sections';
import { useCapabilitiesOptional } from '@/hooks/use-capabilities';
import { Term } from '@/components/ui/term';
import type { GlossaryId } from '@/lib/glossary';

export type AccessTabId = 'users' | 'groups' | 'roles' | 'api-keys' | 'sessions';

const TAB_TITLES: Record<AccessTabId, { label: string; desc: string; term?: GlossaryId }> = {
  users: { label: 'Users', desc: 'Add people, turn their accounts on or off, and choose their groups.' },
  groups: { label: 'Groups', term: 'user-group', desc: 'Put users in groups so they share a role and the sources they can see.' },
  roles: { label: 'Roles', term: 'role', desc: 'Each role is a set of permissions that decides what people can do.' },
  'api-keys': { label: 'API Keys', term: 'api-key', desc: 'Keys that let scripts and other tools call nano without a person signing in.' },
  sessions: { label: 'Sessions', term: 'session', desc: 'Everyone signed in right now, in a browser or through the API.' },
};

interface AccessHeaderProps {
  tab: AccessTabId;
}

export function AccessHeader({ tab }: AccessHeaderProps) {
  // Use the registry to derive the eyebrow group label so it tracks the rail.
  const accessSection = SECTION_BY_ID['access'];
  const groupLabel = accessSection ? GROUP_LABEL[accessSection.group] : 'Administration';
  // NAN-5274: SSO group mappings and SCIM provisioning exist only where SSO
  // does (licensed enterprise builds); open builds never claim them.
  const sso = useCapabilitiesOptional()?.capabilities.sso ?? false;
  const titleEntry =
    tab === 'groups' && sso
      ? {
          ...TAB_TITLES.groups,
          desc: 'Put users in groups so they share a role and the sources they can see. SSO and SCIM can manage who is in each group.',
        }
      : TAB_TITLES[tab];

  return (
    <div className="px-5 pt-5 pb-2 shrink-0">
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
        {groupLabel}
      </div>
      <div className="text-[18px] font-semibold text-foreground tracking-tight leading-none">
        Access Control · {titleEntry.term ? <Term id={titleEntry.term}>{titleEntry.label}</Term> : titleEntry.label}
      </div>
      {titleEntry.desc && (
        <div className="text-[12px] text-muted-foreground mt-1.5 max-w-[720px]">
          {titleEntry.desc}
        </div>
      )}
    </div>
  );
}

