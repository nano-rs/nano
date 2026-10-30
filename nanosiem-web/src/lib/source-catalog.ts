// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { RepositoryParser } from '@/lib/api/parser-repositories';
export const systemSource = (slug: string) => ['unknown', 'default', 'audit'].includes(slug) || slug.startsWith('otlp_');
export const parserSlug = (parser: RepositoryParser) => (parser.name ?? parser.file_path.split('/').pop()?.replace(/\.[^.]+$/, '') ?? '').toLowerCase().replace(/[^a-z0-9_-]+/g, '_');
export function useSourceCatalog(enabled = true) {
  const { tenantRuntime } = useAuth();
  return useQuery({
    queryKey: ['source-picker', 'catalog', tenantRuntime?.key],
    enabled,
    queryFn: async () => {
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
