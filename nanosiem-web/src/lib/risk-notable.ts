// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3225 — recognise a risk notable and the entity it is about.
 *
 * Two generations exist: the retired scheduler's `kind = 'risk_notable'`
 * alerts (NAN-1792) and, since NAN-1805, ordinary detection alerts raised by
 * a `dataset=risk` rule (the seeded default notable rule or a custom one),
 * whose matched events are risk-dataset rows (`entity`, `entity_type`,
 * `score_24h`, `score_7d`, …). Both carry the entity on the first payload row.
 */

import type { Alert } from '@/lib/api/types';

/** Fixed id of the seeded default risk-notable rule (`DEFAULT_RISK_NOTABLE_RULE_ID`). */
export const DEFAULT_RISK_NOTABLE_RULE_ID = 'b8f3d2a1-6c4e-4f7a-9d2b-3e5a7c901f44';

export interface RiskNotableEntity {
  entity: string;
  entity_type: string;
}

const IPV4 = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;

/** The risk reader's value-based typing (`aggregate_sql` multiIf). */
export function inferRiskEntityType(entity: string): string {
  if (IPV4.test(entity)) return 'ip';
  if (entity.includes('@')) return 'email';
  if (entity.includes('.')) return 'hostname';
  return 'user';
}

export function riskNotableEntity(
  alert: Pick<Alert, 'kind' | 'rule_id' | 'matched_events'> | null | undefined,
): RiskNotableEntity | null {
  if (!alert) return null;
  const first = Array.isArray(alert.matched_events) ? alert.matched_events[0] : undefined;
  const row = first && typeof first === 'object' ? (first as Record<string, unknown>) : undefined;
  const entity = typeof row?.entity === 'string' ? row.entity.trim() : '';
  if (!entity) return null;
  const isNotable =
    alert.kind === 'risk_notable' ||
    alert.rule_id === DEFAULT_RISK_NOTABLE_RULE_ID ||
    (row != null && ('score_7d' in row || 'score_24h' in row));
  if (!isNotable) return null;
  const entityType =
    typeof row?.entity_type === 'string' && row.entity_type ? row.entity_type : inferRiskEntityType(entity);
  return { entity, entity_type: entityType };
}
