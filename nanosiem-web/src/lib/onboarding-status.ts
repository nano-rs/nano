// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3241: on an enterprise-shared (lean) tenant the onboarding status probe
 * reports `has_log_sources` / `has_parsers` as false because the tenant's
 * source registry lives behind `/api/log-sources`, not the deployment-global
 * tables the dedicated probe reads. Overlay what the registry says so the
 * Getting Started checklist reflects deployed sources and their parsers.
 */

import type { OnboardingStatus } from '@/lib/api/onboarding';
import type { LogSource } from '@/lib/api/types';

type RegistrySource = Pick<LogSource, 'deployed' | 'parser_vrl'>;

export function overlayLogSourceStatus(
  status: OnboardingStatus | null | undefined,
  sources: readonly RegistrySource[] | null | undefined,
): OnboardingStatus | null | undefined {
  if (!status || !sources || sources.length === 0) return status;
  const hasParser = sources.some(
    (s) => s.deployed || (typeof s.parser_vrl === 'string' && s.parser_vrl.trim() !== ''),
  );
  return {
    ...status,
    has_log_sources: true,
    has_parsers: status.has_parsers || hasParser,
  };
}
