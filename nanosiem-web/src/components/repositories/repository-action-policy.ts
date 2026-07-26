// SPDX-License-Identifier: AGPL-3.0-or-later

export type HasPermission = (permission: string) => boolean;

export interface ActionAccess {
  allowed: boolean;
  missing: string[];
  reason: string | null;
}

export interface RuleImportIntent {
  outcome: 'create' | 'update' | 'skip';
  mode?: 'staging' | 'live' | 'alerting';
  ruleFormat?: 'sigma' | 'nanosiem';
  rawContent?: string;
  /**
   * Update promotion depends on the current detection's lifecycle fields,
   * which repository list responses do not expose. Callers may set this when
   * they have a definitive preflight result.
   */
  requiresPromote?: boolean;
}

export interface ParserImportIntent {
  kind?: string;
  ingestionMethod?: string;
  dispatchSourceConfigId?: string | null;
}

const SOURCE_INVENTORY_CAPABILITIES = [
  'search:execute',
  'log_sources:create',
  'detections:view',
  'source_scopes:view',
] as const;

function accessForAll(
  hasPermission: HasPermission,
  requiredCapabilities: readonly string[],
): ActionAccess {
  const required = [...new Set(requiredCapabilities)];
  const missing = required.filter((permission) => !hasPermission(permission));
  return {
    allowed: missing.length === 0,
    missing,
    reason:
      missing.length === 0
        ? null
        : `${missing.length === 1 ? 'Missing capability' : 'Missing capabilities'}: ${missing.join(', ')}`,
  };
}

function frontmatterValue(rawContent: string | undefined, key: string): string | undefined {
  const content = rawContent?.trim();
  if (!content?.startsWith('---')) return undefined;
  const end = content.indexOf('\n---', 3);
  if (end < 0) return undefined;
  const frontmatter = content.slice(3, end);
  const match = frontmatter.match(
    new RegExp(`^\\s*${key}\\s*:\\s*["']?([^\\s"'#]+)`, 'im'),
  );
  return match?.[1]?.toLowerCase();
}

function ruleCreateRequiresPromote(intent: RuleImportIntent): boolean {
  if (intent.ruleFormat !== 'nanosiem') {
    return intent.mode === 'live' || intent.mode === 'alerting';
  }

  const mode = intent.mode ?? frontmatterValue(intent.rawContent, 'mode') ?? 'staging';
  const detectionMode = frontmatterValue(intent.rawContent, 'detection_mode') ?? 'scheduled';
  return mode === 'live' || mode === 'alerting' || detectionMode === 'realtime';
}

export function ruleImportAccess(
  hasPermission: HasPermission,
  intents: readonly RuleImportIntent[],
): ActionAccess {
  const required = ['rule_repositories:import'];

  for (const intent of intents) {
    if (intent.outcome === 'create') {
      required.push('detections:create');
      if (ruleCreateRequiresPromote(intent)) {
        required.push('detections:promote');
      }
    } else if (intent.outcome === 'update') {
      required.push('detections:edit');
      if (intent.requiresPromote) {
        required.push('detections:promote');
      }
    }
  }

  return accessForAll(hasPermission, required);
}

export function rulePreviewAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['rule_repositories:view']);
}

export function ruleDiffAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['rule_repositories:view', 'detections:view']);
}

export function ruleDismissAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['detections:edit']);
}

export function detectionViewAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['detections:view']);
}

export function sourceInventoryAccess(hasPermission: HasPermission): ActionAccess {
  const allowed = SOURCE_INVENTORY_CAPABILITIES.some(hasPermission);
  return {
    allowed,
    missing: allowed ? [] : [...SOURCE_INVENTORY_CAPABILITIES],
    reason: allowed
      ? null
      : `Requires one of: ${SOURCE_INVENTORY_CAPABILITIES.join(', ')}`,
  };
}

function configTypeForIngestionMethod(ingestionMethod: string | undefined): string {
  return (ingestionMethod ?? 'routed') === 'routed'
    ? 'http'
    : (ingestionMethod ?? 'routed');
}

export function parserImportAccess(
  hasPermission: HasPermission,
  intents: readonly ParserImportIntent[],
  /**
   * All source-config types visible to the caller. Null means the inventory
   * cannot be read, so auto-resolution must be treated as possible.
   */
  sourceConfigTypes: readonly string[] | null,
): ActionAccess {
  const required = ['parser_repositories:import'];

  for (const intent of intents) {
    required.push('log_sources:create');
    if (intent.kind === 'enrichment') continue;

    const mayResolveDispatchConfig =
      !!intent.dispatchSourceConfigId ||
      sourceConfigTypes === null ||
      sourceConfigTypes.includes(configTypeForIngestionMethod(intent.ingestionMethod));
    if (mayResolveDispatchConfig) {
      required.push('source_configs:edit');
    }
  }

  return accessForAll(hasPermission, required);
}

export function parserPreviewAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['parser_repositories:view']);
}

export function parserDiffAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['parser_repositories:view', 'log_sources:view']);
}

export function parserDismissAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['parsers:edit']);
}

export function parserApplyAccess(
  hasPermission: HasPermission,
  deployAfterApply = false,
): ActionAccess {
  const required = ['parsers:edit', 'log_sources:edit'];
  if (deployAfterApply) required.push('log_sources:deploy');
  return accessForAll(hasPermission, required);
}

export function logSourceViewAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['log_sources:view']);
}

export function logSourceDeployAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['log_sources:deploy']);
}

export function sourceConfigInventoryAccess(hasPermission: HasPermission): ActionAccess {
  return accessForAll(hasPermission, ['source_configs:view']);
}

export function repositoryQueryEnabled(access: ActionAccess, active = true): boolean {
  return active && access.allowed;
}
