// SPDX-License-Identifier: AGPL-3.0-or-later

import type { RepositoryRule } from '@/lib/api/rule-repositories';

export type ImportStatusFilter = 'all' | 'imported' | 'not-imported';

export function ruleSourceTypes(rule: Pick<RepositoryRule, 'requires_source_types' | 'suggested_source_types'>): string[] {
  return [...new Set([...(rule.requires_source_types ?? []), ...(rule.suggested_source_types ?? [])].filter(Boolean))];
}

export function sourceTypeCounts<T>(items: T[], sourceTypes: (item: T) => string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    for (const source of new Set(sourceTypes(item))) {
      counts.set(source, (counts.get(source) ?? 0) + 1);
    }
  }
  return counts;
}

export function filterRepositoryItems<T extends { raw: { is_imported?: boolean } }>(
  items: T[],
  options: {
    query: string;
    importStatus: ImportStatusFilter;
    selectedSourceTypes: ReadonlySet<string>;
    sourceTypes: (item: T) => string[];
    searchText: (item: T) => string;
    inCategory: (item: T) => boolean;
  },
): T[] {
  const needle = options.query.trim().toLowerCase();
  return items.filter((item) => {
    if (!options.inCategory(item)) return false;
    if (options.importStatus === 'imported' && !item.raw.is_imported) return false;
    if (options.importStatus === 'not-imported' && item.raw.is_imported) return false;
    if (options.selectedSourceTypes.size && !options.sourceTypes(item).some((source) => options.selectedSourceTypes.has(source))) return false;
    return !needle || options.searchText(item).toLowerCase().includes(needle);
  });
}
