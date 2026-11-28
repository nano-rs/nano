// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-6036: which source configurations the Add source wizard can use, and the
 * ingestion method each one implies.
 *
 * A library (repository) source is imported with an `ingestion_method`, and
 * the import endpoint only accepts a source configuration whose type feeds
 * that method (NAN-943; `ingest_transport::dispatch_compatible`). The wizard
 * used to send `routed` for every configuration, so every type but HTTP was
 * refused. The method now comes from the shared config-type table.
 *
 * A custom source is still saved as `routed`: the wizard adds a routing rule
 * on the chosen configuration at Publish that stamps the source key on its
 * events, and the central router hands them to the parser by that key. The
 * backend accepts `routed` with any configuration, so that path is unchanged.
 *
 * The wizard never deploys a source configuration during Transport. Only the
 * custom path's Publish redeploys one, and only a configuration that is
 * already deployed and owns a per-configuration route (see
 * {@link wizardRedeploysConfig}); the grants below match that.
 */

import { isPullConfigType } from '@/lib/cloud-pull';
import { ingestionMethodForConfigType } from '@/lib/log-source-transports';

export interface PairingConfig {
  config_type: string;
  deployed: boolean;
  credential_id?: string | null;
}

export type SourceConfigPairing =
  | { usable: true; ingestionMethod: string }
  | { usable: false; reason: string };

export interface PairingContext {
  /** A library parser from a repository (imported), not a custom source. */
  repositorySource: boolean;
  /** `source_configs:edit`: the wizard adds a routing rule to the configuration. */
  canEditSourceConfigs: boolean;
  /** `source_configs:deploy`: a rule on a deployed configuration, and any redeploy, need it (NAN-5232). */
  canDeploySourceConfigs: boolean;
  /** `credentials:use`: redeploying a configuration that uses a stored credential needs it. */
  canUseCredentials: boolean;
}

export const NO_EDIT_PERMISSION_REASON =
  'You need permission to edit source configurations to send data this way. Pick another way above, or ask an admin.';
export const NO_DEPLOY_PERMISSION_REASON =
  'This source configuration is live, and changing it needs permission to deploy source configurations. Pick another way above, or ask an admin.';
export const NO_CREDENTIAL_PERMISSION_REASON =
  'This source configuration uses a stored credential, and you need permission to use credentials to deploy it. Ask an admin.';
export const UNKNOWN_TYPE_REASON = 'A library source cannot read from this kind of source configuration yet.';
export const OTLP_LIBRARY_REASON =
  'A library source cannot read from an OpenTelemetry source configuration. Pick OTLP above instead.';
export const NOT_RUNNING_REASON =
  'This pull source is not running yet, so a library source would get no data from it. Deploy it under Cloud pull, then pick it here.';

/**
 * Configuration types with no per-configuration route of their own: Vector
 * events reach the router straight from `vector_merge`, and OTLP routes by
 * the parser's own claim on `otlp_logs_prep`. Deploying one only rewrites a
 * route over another stream (`source_type_extract`), which can push the HTTP
 * configuration's route out of the router, so the wizard never deploys them.
 */
const NO_OWN_ROUTE = new Set(['vector', 'otlp']);

/** Whether the custom path's Publish redeploys `config` after adding its routing rule. */
export function wizardRedeploysConfig(config: PairingConfig, repositorySource: boolean): boolean {
  return !repositorySource && config.deployed && !NO_OWN_ROUTE.has(config.config_type);
}

/**
 * Whether a library source on `config` needs that configuration deployed again
 * before data reaches it: a pull configuration stamps the source key on its
 * events only once the import's routing rule is live. The wizard does not do
 * that deploy (it would also push anyone else's unsaved edits live); it tells
 * the user instead.
 */
export function libraryNeedsConfigDeploy(config: PairingConfig | undefined, repositorySource: boolean): boolean {
  return !!config && repositorySource && isPullConfigType(config.config_type);
}

/** Whether the wizard can use `config`, and the ingestion method it implies. */
export function sourceConfigPairing(config: PairingConfig, ctx: PairingContext): SourceConfigPairing {
  if (!ctx.canEditSourceConfigs) return { usable: false, reason: NO_EDIT_PERMISSION_REASON };
  if (config.deployed && !ctx.canDeploySourceConfigs) return { usable: false, reason: NO_DEPLOY_PERMISSION_REASON };
  if (wizardRedeploysConfig(config, ctx.repositorySource) && config.credential_id && !ctx.canUseCredentials) {
    return { usable: false, reason: NO_CREDENTIAL_PERMISSION_REASON };
  }
  if (!ctx.repositorySource) return { usable: true, ingestionMethod: 'routed' };
  const method = ingestionMethodForConfigType(config.config_type);
  if (!method) return { usable: false, reason: UNKNOWN_TYPE_REASON };
  // An `otlp` log source is refused by every later save (the log-source
  // editor does not accept it), and OTLP routing rules are never rendered.
  if (method === 'otlp') return { usable: false, reason: OTLP_LIBRARY_REASON };
  // A library pull source reads its configuration's own route, which exists
  // only once that configuration is deployed. The import's go-live would fail.
  if (isPullConfigType(config.config_type) && !config.deployed) return { usable: false, reason: NOT_RUNNING_REASON };
  return { usable: true, ingestionMethod: method };
}

/**
 * The `source_type` (ingestion method) the wizard saves on the log source.
 * Push transports and custom sources stay `routed`; a library source read
 * through a source configuration keeps the method it was imported with, so a
 * later save from the Review step does not move it to another lane.
 */
export function wizardSourceType(
  transport: 'push' | 'pull',
  config: PairingConfig | undefined,
  ctx: Pick<PairingContext, 'repositorySource'>,
): string {
  if (transport !== 'pull' || !ctx.repositorySource || !config) return 'routed';
  return ingestionMethodForConfigType(config.config_type) ?? 'routed';
}

/**
 * NAN-6036: once a source exists whose transport is fixed (a library import,
 * or a stored non-routed method such as a pull source), the wizard keeps the
 * Transport choice as it is: switching would leave the saved source on the old
 * route or send a method the new choice cannot carry. A custom `routed` draft
 * can still switch.
 */
export function transportChoiceLocked(args: {
  sourceExists: boolean;
  repositorySource: boolean;
  persistedSourceType: string | null;
}): boolean {
  if (!args.sourceExists) return false;
  if (args.repositorySource) return true;
  return !!args.persistedSourceType && args.persistedSourceType !== 'routed';
}

/**
 * NAN-6036: whether the custom path's Publish adds the `source_type` identity
 * routing rule for `feedId` to `config`. Not for a library source (its import
 * already added it), not when the configuration already has that rule (a
 * repeat on a pull configuration is coerced to a catch-all `default` rule that
 * takes every unmatched event), and not on Vector / OTLP, which have no route
 * of their own for the rule to act on.
 */
export function wizardAddsRoutingRule(
  config: PairingConfig,
  repositorySource: boolean,
  feedId: string,
  existingRules: ReadonlyArray<{ match_field?: string; match_value?: string }>,
): boolean {
  if (repositorySource || NO_OWN_ROUTE.has(config.config_type)) return false;
  return !existingRules.some((r) => r.match_field === 'source_type' && r.match_value === feedId);
}
