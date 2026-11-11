// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The Add source catalog (main's module; NAN-4922): every log parser in the
 * enabled parser repositories, for Step 1's "From repositories" picker.
 * Main keyed the cache on the hosted tenant runtime; a deployment has one here.
 */
import { useQuery } from '@tanstack/react-query';
import { parse as parseYaml } from 'yaml';
import { api } from '@/lib/api';
import type { RepositoryParser } from '@/lib/api/parser-repositories';

/** Route keys a new source cannot take (unattributed fallbacks and nano's own lanes). */
export const systemSource = (slug: string) => ['unknown', 'default', 'audit'].includes(slug) || slug.startsWith('otlp_');
export const parserSlug = (parser: Pick<RepositoryParser, 'name' | 'file_path'>) =>
  (parser.name ?? parser.file_path.split('/').pop()?.replace(/\.[^.]+$/, '') ?? '').toLowerCase().replace(/[^a-z0-9_-]+/g, '_');


/** The allow-list the backend applies to match values (`is_safe_source_type`). */
const ROUTE_KEY = /^[A-Za-z0-9_-]+$/;

/**
 * NAN-5264: the route key a repository parser listens on: the first entry of
 * its YAML `match_values` (e.g. `windows_sysmon`), which is what senders and
 * content key on. The parser NAME (`windows_sysmon_ocsf`) is only the fallback
 * for a parser that declares no match value. Defaulting the source key to the
 * name made the new source's `source_type` a value nothing else uses.
 */
export function parserMatchValue(parser: Pick<RepositoryParser, 'name' | 'file_path' | 'raw_content'>): string {
  try {
    const doc: unknown = parseYaml(parser.raw_content ?? '');
    const values = doc && typeof doc === 'object' ? (doc as { match_values?: unknown }).match_values : undefined;
    if (Array.isArray(values)) {
      for (const value of values) {
        const key = typeof value === 'string' ? value.trim() : '';
        if (ROUTE_KEY.test(key)) return key.toLowerCase();
      }
    }
  } catch {
    // Unparseable YAML: the backend import falls back to the name too.
  }
  return parserSlug(parser);
}

export type CatalogParser = RepositoryParser & {
  repository_name: string;
  /** {@link parserMatchValue}: the default source key for this parser. */
  match_value: string;
};

export function useSourceCatalog(enabled = true) {
  return useQuery({
    queryKey: ['source-picker', 'catalog'],
    enabled,
    queryFn: async (): Promise<CatalogParser[]> => {
      const { repositories } = await api.parserRepositories.listRepositories();
      return (await Promise.all(repositories.filter((r) => r.enabled).map(async (repository) =>
        (await api.parserRepositories.listParsers(repository.id))
          .filter((parser) => parser.kind !== 'enrichment')
          .map((parser) => ({ ...parser, repository_name: repository.name, match_value: parserMatchValue(parser) }))
          .filter((parser) => !systemSource(parser.match_value) && !systemSource(parserSlug(parser))),
      ))).flat();
    },
    staleTime: 60_000,
  });
}
