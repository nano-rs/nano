// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: pull collectors are enterprise-only (NAN-3861). The hook
// lists nothing and issues no requests, so the Marketplace shows no collector
// cards, counts, or load errors.
import type { HostedCollector } from '@/enterprise/api/hosted-collectors';

export type CollectorFeeds = { data?: unknown[]; isError: boolean; isPending: boolean };
export interface CollectorRow { entry: HostedCollector; feeds: CollectorFeeds }
export interface CollectorState { installed: boolean; enabled: boolean; health: string }

export function collectorSection(_entry: HostedCollector): 'identity' | 'other' {
  return 'other';
}

export function collectorMatches(_entry: HostedCollector, _query: string): boolean {
  return false;
}

export function collectorState(_feeds: CollectorFeeds): CollectorState {
  return { installed: false, enabled: false, health: 'not installed' };
}

export function useHostedCollectors(_options: { pollFeeds: boolean }) {
  return {
    rows: [] as CollectorRow[],
    queryKey: ['hosted-collectors'] as const,
    canView: false,
    isError: false,
    isRefetching: false,
    refetch: () => {},
    canInstall: false,
    canRotate: false,
    canRemove: false,
  };
}
