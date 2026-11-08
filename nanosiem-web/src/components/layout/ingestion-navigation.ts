// SPDX-License-Identifier: AGPL-3.0-or-later

import { FolderInput, Rss, Workflow } from 'lucide-react';
import type { NavItem } from './AppLayout';

/**
 * Ingestion section, matching main's ingestion-navigation.ts: Log Sources ·
 * Pipelines · Repositories. NAN-4941: Log Sources is the single home for
 * sources, ingest tokens, cloud pull and pull feeds (its tabs); Source Configs,
 * Pull Feeds and the cloud Credentials page are retired. Pipelines (Nano Pipe,
 * NAN-4919) sits between the two. Log Sources stays visible to a
 * viewer with only source-config or credential permissions (Cloud pull and
 * Pull feeds accept those).
 */
export const ingestionNavigation: NavItem[] = [
  { name: 'Log Sources', href: '/ingestion/log-sources', icon: Rss, permissions: ['log_sources:view', 'source_configs:view', 'credentials:view'] },
  { name: 'Pipelines', href: '/ingestion/pipelines', icon: Workflow, permissions: 'log_sources:view' },
  { name: 'Repositories', href: '/ingestion/log-sources/repositories', icon: FolderInput, permissions: 'parsers:view' },
];
