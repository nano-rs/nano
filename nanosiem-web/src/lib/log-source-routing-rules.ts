// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiClientError } from '@/lib/api';
import type { SourceConfiguration, SourceConfigurationWithRules } from '@/lib/api/types';

/** A source-config routing rule that sends events to a log source. */
export interface AssociatedRoutingRule {
  configId: string;
  configName: string;
  ruleId: string;
  matchValue: string;
}

export interface RoutingRuleLookupApi {
  listSourceConfigs(params: { enabled: boolean }): Promise<SourceConfiguration[]>;
  getSourceConfigWithRules(id: string): Promise<SourceConfigurationWithRules>;
}

function isForbidden(err: unknown): boolean {
  return err instanceof ApiClientError && err.status === 403;
}

/**
 * Routing rules that route events to one of a log source's match values, for
 * the warning in the Log Sources delete dialog. The warning is informational:
 * the delete does not depend on it.
 *
 * NAN-5972: a user without `source_configs:view` cannot see these rules, so
 * the lookup is skipped instead of calling the API for a 403 and logging a
 * console error on every delete. A 403 that still happens (a permission
 * removed during the session) reads as "nothing to show", quietly; any other
 * error is still logged.
 */
export async function findAssociatedRoutingRules(
  matchValues: readonly string[] | null | undefined,
  canViewSourceConfigs: boolean,
  client: RoutingRuleLookupApi,
): Promise<AssociatedRoutingRule[]> {
  if (!matchValues?.length || !canViewSourceConfigs) return [];
  const wanted = new Set(matchValues);
  let configs: SourceConfiguration[];
  try {
    configs = await client.listSourceConfigs({ enabled: true });
  } catch (err) {
    if (!isForbidden(err)) console.error('Failed to check associated routing rules:', err);
    return [];
  }
  const perConfig = await Promise.all(
    configs.map(async (config) => {
      try {
        const full = await client.getSourceConfigWithRules(config.id);
        return full.routing_rules
          .filter((rule) => wanted.has(rule.target_source_type))
          .map((rule) => ({
            configId: config.id,
            configName: config.name,
            ruleId: rule.id,
            matchValue: rule.match_value || '(default)',
          }));
      } catch (err) {
        if (!isForbidden(err)) console.error(`Failed to fetch rules for ${config.name}:`, err);
        return [];
      }
    }),
  );
  return perConfig.flat();
}
