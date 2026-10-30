// SPDX-License-Identifier: AGPL-3.0-or-later

import { FolderInput, KeyRound, Network, Rss } from 'lucide-react';
import type { NavItem } from './AppLayout';

/** Whether a nav item belongs on this edition (hosted-shared vs open core / dedicated). */
export function visibleOnEdition(item: Pick<NavItem, 'hideOnShared' | 'sharedOnly'>, sharedTenant: boolean): boolean {
  if (item.hideOnShared && sharedTenant) return false;
  if (item.sharedOnly && !sharedTenant) return false;
  return true;
}

/**
 * Ingestion section - data sources and parsing configuration.
 *
 * Credentials (stored cloud keys) is hidden on hosted-shared tenants
 * (NAN-3620): nothing there consumes them and hosted cloud pull is keyless
 * (Log Sources → Cloud pull). Open core and dedicated keep it.
 */
export const ingestionNavigation: NavItem[] = [
  { name: 'Log Sources', href: '/ingestion/log-sources', icon: Rss, permissions: 'log_sources:view' },
  { name: 'Pipelines', href: '/ingestion/pipelines', icon: Network, permissions: 'log_sources:view', sharedOnly: true },
  { name: 'Repositories', href: '/ingestion/log-sources/repositories', icon: FolderInput, permissions: 'parsers:view' },
  { name: 'Pull feeds', href: '/ingestion/connector-feeds', icon: Rss, permissions: 'log_sources:view', hideOnShared: true },
  { name: 'Source Configs', href: '/ingestion/source-configurations', icon: Network, permissions: 'source_configs:view', hideOnShared: true },
  { name: 'Credentials', href: '/ingestion/credentials', icon: KeyRound, permissions: 'credentials:view', hideOnShared: true },
];
