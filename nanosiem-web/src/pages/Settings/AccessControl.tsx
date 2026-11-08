// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Access Control — entry route under the Settings shell.
 *
 * `/settings/access-control?tab=<tab>` selects the active tab. Each tab
 * renders a section view (Users / Groups / Roles / API Keys / Sessions) with
 * the shared `AccessHeader` + `AccessSubnav`.
 *
 * Mirrors `design-ref/shadcn/settings-users.jsx` `AccessControlView`. Replaces
 * the legacy chunky `<Tabs>` shell with the redesign-density shadow-free
 * underlined-tab pattern.
 */

import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useAuth } from '@/contexts/AuthContext';
import { useTierContext } from '@/hooks/use-tier';
import { AccessHeader, type AccessTabId } from '@/components/settings/access-control/AccessHeader';
import { AccessSubnav } from '@/components/settings/access-control/AccessSubnav';
import { UsersView } from '@/components/settings/access-control/UsersView';
import { GroupsView } from '@/components/settings/access-control/GroupsView';
import { RolesView } from '@/components/settings/access-control/RolesView';
import { ApiKeysView } from '@/components/settings/access-control/ApiKeysView';
import { SessionsView } from '@/components/settings/access-control/SessionsView';

import { OidcProvidersContent } from '@/enterprise/pages/Settings/OidcProviders';

const TAB_PERMISSION: Record<AccessTabId, string[]> = {
  users: ['users:view'],
  groups: ['groups:view'],
  roles: ['roles:view'],
  'api-keys': ['apikeys:view'],
  sessions: ['users:view'],
};

function useResolveTab(): AccessTabId {
  const [params] = useSearchParams();
  const { hasAnyPermission } = useAuth();
  const { hasSso, isEnforced } = useTierContext();
  const requested = params.get('tab') as AccessTabId | null;

  // Build the visible tab set (mirroring AccessSubnav's filter).
  const visible = useMemo<AccessTabId[]>(() => {
    const all: AccessTabId[] = ['users', 'groups', 'roles', 'api-keys', 'sessions'];
    return all.filter(t => hasAnyPermission(TAB_PERMISSION[t]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasAnyPermission]);

  // Legacy compat: ?tab=sso/audit/feedback (from the old AccessControl tabs)
  // map to nearest equivalent. SSO has its own settings entry now.
  if (requested === 'users' || requested === 'groups' || requested === 'roles' || requested === 'api-keys' || requested === 'sessions') {
    if (visible.includes(requested)) return requested;
  }

  // Fall back to first visible tab.
  return visible[0] || 'users';

  // hasSso/isEnforced retained for future SSO-tab gating once it's a tab again.
  void hasSso; void isEnforced;
}

export function AccessControlPage() {
  useDocumentTitle('Access Control');
  const tab = useResolveTab();

  return (
    <div className="h-full flex flex-col min-h-0">
      <AccessHeader tab={tab} />
      <AccessSubnav activeTab={tab} />
      <AccessControlBody tab={tab} />
    </div>
  );
}

function AccessControlBody({ tab }: { tab: AccessTabId }) {
  if (tab === 'users') return <UsersView />;
  if (tab === 'groups') return <GroupsView />;
  if (tab === 'roles') return <RolesView />;
  if (tab === 'api-keys') return <ApiKeysView />;
  if (tab === 'sessions') return <SessionsView />;
  return null;
}

// Keep OidcProvidersContent reachable as a default export so it can be reused
// by the standalone `/settings/oidc` route until SSO is folded back into the
// Access Control track.
export const _AccessControlOidcRef = OidcProvidersContent;

export default AccessControlPage;
