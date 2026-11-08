// SPDX-License-Identifier: AGPL-3.0-or-later

import { Link } from 'react-router-dom';

import { useAuth } from '@/contexts/AuthContext';

import { INGEST_CREDENTIALS_PATH } from '@/lib/add-data-sources';
import { CLOUD_PULL_PATH, PULL_FEEDS_PATH } from '@/lib/ingestion-paths';
import { cn } from '@/lib/utils';

export { INGEST_CREDENTIALS_PATH };

export type LogSourcesTab = 'sources' | 'credentials' | 'cloud-pull' | 'pull-feeds';

/**
 * Log sources | Credentials | Cloud pull | Pull feeds (main's NAN-2593 /
 * NAN-3596 tabs, plus Pull feeds). NAN-4941: the single home for ingestion on
 * every ClickHouse deployment; a tab shows when the viewer holds any
 * permission its route accepts. Repositories is a rail item, as on main, not
 * a tab, so it is never listed twice.
 */
export function LogSourcesTabs({ active }: { active: LogSourcesTab }) {
  const { hasPermission } = useAuth();
  const tabs: { id: LogSourcesTab; label: string; href: string; any: string[] }[] = [
    { id: 'sources', label: 'Log sources', href: '/ingestion/log-sources', any: ['log_sources:view'] },
    { id: 'credentials', label: 'Credentials', href: INGEST_CREDENTIALS_PATH, any: ['log_sources:view', 'source_configs:view'] },
    { id: 'cloud-pull', label: 'Cloud pull', href: CLOUD_PULL_PATH, any: ['source_configs:view', 'credentials:view'] },
    { id: 'pull-feeds', label: 'Pull feeds', href: PULL_FEEDS_PATH, any: ['log_sources:view', 'credentials:view'] },
  ];
  return (
    <nav className="shrink-0 flex items-end gap-1 px-4 border-b border-border bg-background" aria-label="Log sources">
      {tabs.filter((t) => t.any.some((p) => hasPermission(p))).map((t) => (
        <Link
          key={t.id}
          to={t.href}
          aria-current={active === t.id ? 'page' : undefined}
          className={cn(
            'h-8 px-2.5 inline-flex items-center text-[12px] border-b-2 -mb-px',
            active === t.id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
          )}
        >
          {t.label}
        </Link>
      ))}
    </nav>
  );
}
