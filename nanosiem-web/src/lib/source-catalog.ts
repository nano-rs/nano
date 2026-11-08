// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The Add source catalog (main's module; NAN-4922): every log parser in the
 * enabled parser repositories, for Step 1's "From repositories" picker.
 * Main keyed the cache on the hosted tenant runtime; a deployment has one here.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { RepositoryParser } from '@/lib/api/parser-repositories';

/** Route keys a new source cannot take (unattributed fallbacks and nano's own lanes). */
export const systemSource = (slug: string) => ['unknown', 'default', 'audit'].includes(slug) || slug.startsWith('otlp_');
export const parserSlug = (parser: Pick<RepositoryParser, 'name' | 'file_path'>) =>
  (parser.name ?? parser.file_path.split('/').pop()?.replace(/\.[^.]+$/, '') ?? '').toLowerCase().replace(/[^a-z0-9_-]+/g, '_');

export type CatalogParser = RepositoryParser & { repository_name: string };

export function useSourceCatalog(enabled = true) {
  return useQuery({
    queryKey: ['source-picker', 'catalog'],
    enabled,
    queryFn: async (): Promise<CatalogParser[]> => {
      const { repositories } = await api.parserRepositories.listRepositories();
      return (await Promise.all(repositories.filter((r) => r.enabled).map(async (repository) =>
        (await api.parserRepositories.listParsers(repository.id))
          .filter((parser) => parser.kind !== 'enrichment' && !systemSource(parserSlug(parser)))
          .map((parser) => ({ ...parser, repository_name: repository.name })),
      ))).flat();
    },
    staleTime: 60_000,
  });
}
