// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3661: delivery health for a log source. A log source's lane is fed by
 * cloud pull sources and connector feeds; when one of them fails, the analyst
 * clicks into the log source and needs to see which delivery broke, why, and
 * what to change. This module turns a stored `last_error` into:
 *
 * - its machine code (shown in mono next to the hint, so support can match it), and
 * - an actionable hint naming the fix.
 *
 * Codes come from three writers:
 * - the pull broker probe (`deploy/pull-broker/cloud-broker/{aws,gcp,azure}.js`
 *   in the platform), stored as `<code>: <broker message>`;
 * - the pull reconciler (`pull-source-reconcile.ts`): `source_not_enrolled`,
 *   `no_parser_lane`, `probe_*`;
 * - the API's create-time deny lists (`target_*_denied`, `gcp_project_denied`).
 *
 * Hints never contain a secret. The AWS ExternalId and nano principal are not
 * secrets (the setup panel shows both to every tenant admin); a caller may pass
 * them in so the hint names the exact value to paste.
 */

import type { PullSourceState } from '@/lib/api/pull-sources';
import { pullStateLabel } from '@/lib/cloud-pull';

export interface PullHintContext {
  /** `GET /api/pull-sources/setup/aws` → `external_id`. */
  externalId?: string | null;
  /** `GET /api/pull-sources/setup/aws` → `nano_principal_arn`. */
  nanoPrincipalArn?: string | null;
  /** The tenant's nano GCP service account (`GET /api/pull-sources/setup/gcp`). */
  gcpServiceAccount?: string | null;
}

/** Which setup panel on the Cloud pull page fixes the error. */
export type PullHintSetup = 'aws' | 'gcp' | 'azure' | 'log_source' | null;

export interface PullErrorHint {
  /** The stored code (`assume_role_denied`), else null for free text. */
  code: string | null;
  /** What to change; null when no known code matched. */
  hint: string | null;
  /** Platform-side or transient: nano retries without the tenant doing anything. */
  retriesAutomatically: boolean;
  setup: PullHintSetup;
}

/** snake_case with at least one `_`, then `": "` or the end (an ARN such as `arn:aws:…` is not a code). Mirrors `pull_error_code` in inputs.rs. */
const CODE = /^([a-z][a-z0-9]*_[a-z0-9_]{1,62})(?:: |$)/;

/** The leading `<code>:` of a stored error, if any. */
export function pullErrorCode(lastError: string | null | undefined): string | null {
  if (!lastError) return null;
  const m = CODE.exec(lastError.trim());
  return m ? m[1] : null;
}

type HintFn = (ctx: PullHintContext) => string;
interface HintRule {
  match: RegExp;
  hint: HintFn;
  setup: PullHintSetup;
  retries?: boolean;
}

const externalId = (ctx: PullHintContext) =>
  ctx.externalId ? ctx.externalId : 'the ExternalId shown in the AWS setup panel';
const principal = (ctx: PullHintContext) =>
  ctx.nanoPrincipalArn ? ctx.nanoPrincipalArn : "nano's pull role shown in the AWS setup panel";
const gcpMember = (ctx: PullHintContext) =>
  ctx.gcpServiceAccount ? `serviceAccount:${ctx.gcpServiceAccount}` : 'the nano service account shown in the GCP setup panel';

const TRANSIENT = 'Platform-side or transient; nano retries automatically. Nothing to change.';

/**
 * Ordered: the first match wins. Code rules match the stored `<code>:` prefix
 * anywhere in the text (older rows carry the code mid-string); text rules
 * catch upstream wording such as `PERMISSION_DENIED` or KMS denials.
 */
const RULES: HintRule[] = [
  // --- reconciler (any provider) ---
  { match: /\bsource_not_enrolled\b/, setup: 'log_source',
    hint: () => 'This log source is not enabled for the tenant. Enable it (and its parser) on this page; nano then deploys the pull automatically.' },
  { match: /\bno_parser_lane\b/, setup: 'log_source',
    hint: () => 'No parser serves this lane in the tenant bundle. Publish or enable this log source\'s parser; the pull is deployed once it is serving.' },
  { match: /\bprobe_(unreachable|rate_limited|unsupported|response_invalid|failed)\b/, setup: null, retries: true, hint: () => TRANSIENT },
  // Render ledger (pull-source-reconcile.ts). `pull_render_failed` / `pull_render_blocked` are the
  // NAN-3604 follow-up codes for a failed or held Worker render; the copy never promises a retry there.
  { match: /\bpull_render_(failed|refused)\b/, setup: null,
    hint: () => 'Verified, but nano could not roll out the pull configuration. nano has recorded the failure; nothing to change on your side.' },
  { match: /\bpull_render_blocked\b/, setup: null,
    hint: () => 'Verified, but the rollout is held behind a configuration rollout that has not settled. nano has recorded the failure; nothing to change on your side.' },
  { match: /\bpull_render_waiting\b/, setup: null, retries: true,
    hint: () => 'Verified. nano is rolling the pull configuration out; events start once it lands. Nothing to change.' },

  // --- AWS (cloud-broker/aws.js) ---
  { match: /\btarget_account_denied\b/, setup: 'aws',
    hint: () => "This AWS account can't be used for cloud pull. Use a role and queue in the account that owns your logs." },
  { match: /\brole_does_not_enforce_external_id\b/, setup: 'aws',
    hint: (ctx) => `The role trusts nano without an ExternalId condition. Add "sts:ExternalId": "${externalId(ctx)}" to the role trust policy's StringEquals condition.` },
  { match: /\bexternal_id_check_inconclusive\b/, setup: null, retries: true,
    hint: () => 'nano could not confirm that the role enforces the ExternalId. It retries automatically.' },
  { match: /\b(assume_role_denied|AccessDenied[^\n]*AssumeRole|not authorized to perform: sts:AssumeRole)\b/, setup: 'aws',
    hint: (ctx) => `AWS denied AssumeRole. In the role trust policy, allow ${principal(ctx)} and set sts:ExternalId to ${externalId(ctx)}. A changed or mistyped ExternalId is the usual cause.` },
  { match: /\bassume_role_rejected\b/, setup: 'aws',
    hint: () => 'AWS rejected the AssumeRole request. Check that the role ARN exists and that its trust policy allows sts:AssumeRole, sts:SetSourceIdentity and sts:TagSession for nano.' },
  { match: /\bsts_region_disabled\b/, setup: 'aws',
    hint: () => 'STS is disabled for this region in your account. Activate the region under IAM → Account settings → Security Token Service.' },
  { match: /\b(kms|KMS)\b[^\n]*(denied|Denied|AccessDenied|not authorized)|\bKMS\.\w+Exception\b/, setup: 'aws',
    hint: () => 'The role cannot decrypt with the KMS key on the queue or bucket. Allow kms:Decrypt for the role in the key policy (via SQS and S3).' },
  { match: /\b(dlq|DLQ|dead[- ]letter)\b/, setup: 'aws',
    hint: () => 'Messages are moving to the dead-letter queue. Check that the role can delete messages (sqs:DeleteMessage) and that the redrive maxReceiveCount is not lower than nano\'s retries.' },
  { match: /\bqueue_access_denied\b/, setup: 'aws',
    hint: () => 'The role cannot read the queue. Grant sqs:ReceiveMessage, sqs:DeleteMessage, sqs:ChangeMessageVisibility and sqs:GetQueueAttributes on the queue, and check that the queue policy does not deny the role.' },
  { match: /\bqueue_not_found\b/, setup: 'aws',
    hint: () => 'The queue does not exist in that account and region. Check the queue ARN, or recreate the source with the right one.' },
  { match: /\bqueue_rejected\b/, setup: 'aws',
    hint: () => 'SQS rejected the request. Check the queue ARN and the queue access policy.' },
  { match: /\b(queue_account_mismatch|account_mismatch)\b/, setup: 'aws',
    hint: () => 'The queue is in a different AWS account than the role. Use a role and queue in the same account.' },
  { match: /\bregion_mismatch\b/, setup: 'aws',
    hint: () => 'The queue is in a different region than the one selected. Recreate the source with the queue\'s region.' },
  { match: /\bqueue_arn_mismatch\b/, setup: 'aws',
    hint: () => 'The queue SQS reported does not match the queue ARN on this source. Check the ARN for a typo.' },
  { match: /\bbucket_not_allowed\b/, setup: 'aws',
    hint: () => 'The bucket name is not allowed for this source. Check the bucket in the S3 notification and on the source.' },
  { match: /\b(sts|sqs)_(unavailable|unreachable|response_invalid)\b|\bupstream_response_too_large\b/, setup: null, retries: true,
    hint: () => TRANSIENT },

  // --- GCP (cloud-broker/gcp.js, gcp-deny.js) ---
  { match: /\bgcp_project_denied\b/, setup: 'gcp',
    hint: () => "This GCP project can't be used for cloud pull. Use a subscription in a project you own." },
  { match: /\bgcp_subscription_not_found\b/, setup: 'gcp',
    hint: () => 'The subscription does not exist. Check projects/<project>/subscriptions/<name> on the source.' },
  { match: /\b(gcp_subscription_denied|PERMISSION_DENIED)\b/, setup: 'gcp',
    hint: (ctx) => `nano cannot read the subscription. Grant roles/pubsub.subscriber on the subscription (not the project) to ${gcpMember(ctx)}.` },
  { match: /\bSERVICE_DISABLED\b|\bAPI has not been used\b|\bis disabled\b[^\n]*pubsub/i, setup: 'gcp',
    hint: () => 'The Pub/Sub API is disabled in the project. Enable pubsub.googleapis.com, then retry.' },
  { match: /\bgcp_service_account_missing\b/, setup: null, retries: true,
    hint: () => "nano is still provisioning this tenant's GCP service account. It retries automatically." },
  { match: /\bgcp_denied\b/, setup: 'gcp',
    hint: (ctx) => `Google refused the request. Check that ${gcpMember(ctx)} holds roles/pubsub.subscriber on the subscription.` },
  { match: /\bgcp_rejected\b/, setup: 'gcp',
    hint: () => 'Google rejected the request. Check the subscription path on the source.' },
  { match: /\bgcp_(unavailable|unreachable|response_invalid)\b/, setup: null, retries: true, hint: () => TRANSIENT },

  // --- Azure (cloud-broker/azure.js) ---
  { match: /\bazure_token_mismatch\b/, setup: 'azure',
    hint: () => 'The token Entra issued does not match this directory or app. Check the directory and client IDs.' },
  { match: /\bsubscription_tenant_mismatch\b/, setup: 'azure',
    hint: () => 'The subscription belongs to a different directory than the one given.' },
  { match: /\btarget_(tenant|subscription)_denied\b/, setup: 'azure',
    hint: () => "This Azure tenant or subscription can't be used for cloud pull." },
  { match: /\bazure_denied\b/, setup: 'azure',
    hint: () => 'Entra refused the sign-in. Check the federated credential (issuer, subject, audience) on the app registration.' },
  { match: /\bazure_rejected\b/, setup: 'azure',
    hint: () => 'Entra rejected the app configuration. Check the app registration and its federated credential.' },
  { match: /\bcheckpoint_access_denied\b/, setup: 'azure',
    hint: () => 'Grant Storage Blob Data Contributor on the checkpoint container to the app.' },
  { match: /\bcheckpoint_container_not_found\b/, setup: 'azure',
    hint: () => 'The checkpoint container does not exist in that storage account.' },
  { match: /\bevent_hub_[a-z_]+\b/, setup: 'azure',
    hint: () => 'Check the event hub name and the Azure Event Hubs Data Receiver role on it.' },
  { match: /\b(azure|event_hubs|storage|management)_(unavailable|unreachable|response_invalid)\b/, setup: null, retries: true,
    hint: () => TRANSIENT },
];

/** The code and actionable hint for a stored pull-source error. */
export function pullErrorHint(lastError: string | null | undefined, ctx: PullHintContext = {}): PullErrorHint {
  const code = pullErrorCode(lastError);
  if (!lastError) return { code: null, hint: null, retriesAutomatically: false, setup: null };
  for (const rule of RULES) {
    if (rule.match.test(lastError)) {
      return { code, hint: rule.hint(ctx), retriesAutomatically: rule.retries ?? false, setup: rule.setup };
    }
  }
  return { code, hint: null, retriesAutomatically: false, setup: null };
}

/** True when the hint wants the AWS setup values (ExternalId, nano principal) filled in. */
export function hintNeedsAwsSetup(lastError: string | null | undefined): boolean {
  return !!lastError && /\b(assume_role_denied|role_does_not_enforce_external_id|AssumeRole)\b/.test(lastError);
}

/** True when the hint wants the tenant's GCP service account filled in. */
export function hintNeedsGcpSetup(lastError: string | null | undefined): boolean {
  return !!lastError && /\b(gcp_subscription_denied|gcp_denied|PERMISSION_DENIED)\b/.test(lastError);
}

// --- delivery attention (list indicator + detail panel) ---

export type DeliveryAttentionLevel = 'failed' | 'blocked' | 'paused';

export interface DeliveryAttention {
  level: DeliveryAttentionLevel;
  /** "pull" | "connector". */
  kind: 'pull' | 'connector';
  id: string;
  name: string;
  /** A short reason for a tooltip: the stored code or generic text. */
  reason: string;
}

/** A pull source that needs attention, else null. Healthy and progressing rows return null. */
export function pullAttention(source: {
  id: string; name: string; state: string; last_error?: string | null;
}): DeliveryAttention | null {
  const label = pullStateLabel(source.state as PullSourceState, source.last_error);
  // The code only, like the API summary: free text can carry ARNs and stays in the row's error cell.
  const code = pullErrorCode(source.last_error);
  if (source.state === 'failed') return { level: 'failed', kind: 'pull', id: source.id, name: source.name, reason: code ?? 'verification failed' };
  if (label === 'blocked') return { level: 'blocked', kind: 'pull', id: source.id, name: source.name, reason: code ?? 'blocked' };
  if (source.state === 'paused') return { level: 'paused', kind: 'pull', id: source.id, name: source.name, reason: 'paused' };
  return null;
}

/** A connector feed that needs attention (failed run, timeout, disabled), else null. */
export function connectorAttention(feed: {
  id: string; name: string; status: string; enabled: boolean; last_error?: string | null;
}): DeliveryAttention | null {
  if (!feed.enabled || feed.status === 'disabled') return { level: 'paused', kind: 'connector', id: feed.id, name: feed.name, reason: 'disabled' };
  if (feed.status === 'failed' || feed.status === 'timeout') {
    return { level: 'failed', kind: 'connector', id: feed.id, name: feed.name, reason: feed.status === 'timeout' ? 'last run timed out' : (feed.last_error ?? 'last run failed') };
  }
  return null;
}

const LEVEL_RANK: Record<string, number> = { failed: 3, blocked: 2, paused: 1 };

type AttentionLike = Pick<DeliveryAttention, 'name' | 'reason'> & { kind: string; level: string };

/** The worst level among `items` (client-derived or the API's `attention`), or null. */
export function worstAttention(items: readonly { level: string }[]): DeliveryAttentionLevel | null {
  let worst: DeliveryAttentionLevel | null = null;
  for (const item of items) {
    const rank = LEVEL_RANK[item.level] ?? 0;
    if (rank > 0 && (!worst || rank > LEVEL_RANK[worst])) worst = item.level as DeliveryAttentionLevel;
  }
  return worst;
}

/** One tooltip line per item: `pull · CloudTrail prod: failed (assume_role_denied)`. */
export function attentionSummary(items: readonly AttentionLike[]): string[] {
  return items.map((i) => `${i.kind} · ${i.name}: ${i.level}${i.reason && i.reason !== i.level ? ` (${i.reason})` : ''}`);
}
