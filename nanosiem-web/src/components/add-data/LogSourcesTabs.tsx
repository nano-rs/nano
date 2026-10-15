// SPDX-License-Identifier: AGPL-3.0-or-later

import { useAuth } from '@/contexts/AuthContext';
import { Link } from 'react-router-dom';
import { CLOUD_PULL_PATH } from '@/lib/cloud-pull';
import { cn } from '@/lib/utils';

export const INGEST_CREDENTIALS_PATH = '/ingestion/log-sources/credentials';

/** Hosted-shared tenants: Log Sources | Credentials (NAN-2593) | Cloud pull (NAN-3596). */
export function LogSourcesTabs({ active }: { active: 'sources' | 'onboarding' | 'credentials' | 'cloud-pull' }) {
  const { user } = useAuth();
  const shared = user?.deployment_mode === 'enterprise_shared';
  const tabs = [
    { id: 'sources', label: 'Log sources', href: '/ingestion/log-sources' },
    { id: 'onboarding', label: 'Onboarding', href: '/ingestion/log-sources/onboarding' },
    { id: 'credentials', label: 'Credentials', href: INGEST_CREDENTIALS_PATH },
    { id: 'cloud-pull', label: 'Cloud pull', href: CLOUD_PULL_PATH },
  ] as const;
  return (
    <nav className="shrink-0 flex items-end gap-1 px-4 border-b border-border bg-background" aria-label="Log sources">
      {tabs.filter(t => shared || t.id === 'sources' || t.id === 'onboarding').map((t) => (
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
