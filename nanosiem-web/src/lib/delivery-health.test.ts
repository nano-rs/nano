// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-3661: pull error codes → actionable hints; delivery attention levels. */
import { describe, expect, it } from 'vitest';
import {
  attentionSummary,
  connectorAttention,
  hintNeedsAwsSetup,
  hintNeedsGcpSetup,
  pullAttention,
  pullErrorCode,
  pullErrorHint,
  worstAttention,
} from './delivery-health';

describe('pullErrorCode', () => {
  it('reads the leading code of a stored error', () => {
    expect(pullErrorCode('assume_role_denied: AWS denied AssumeRole')).toBe('assume_role_denied');
    expect(pullErrorCode('gcp_project_denied')).toBe('gcp_project_denied');
    expect(pullErrorCode('AccessDenied: no')).toBeNull();
    expect(pullErrorCode('connection reset by peer')).toBeNull();
    expect(pullErrorCode('arn:aws:iam::123456789012:role/x')).toBeNull();
    expect(pullErrorCode('timeout')).toBeNull();
    expect(pullErrorCode(null)).toBeNull();
  });
});

describe('pullErrorHint', () => {
  const cases: [string, RegExp, string | null][] = [
    // AWS
    ['assume_role_denied: the broker could not assume the role', /trust policy.*ExternalId/, 'aws'],
    ['role_does_not_enforce_external_id: the role trusts nano without an ExternalId', /sts:ExternalId/, 'aws'],
    ['target_account_denied', /AWS account can't be used/, 'aws'],
    ['queue_access_denied: the role cannot read the queue', /sqs:ReceiveMessage/, 'aws'],
    ['queue_not_found: x', /queue does not exist/, 'aws'],
    ['queue_account_mismatch: x', /different AWS account/, 'aws'],
    ['region_mismatch: x', /different region/, 'aws'],
    ['sts_region_disabled: x', /Security Token Service/, 'aws'],
    ['queue_rejected: KMS.AccessDeniedException', /kms:Decrypt/, 'aws'],
    ['messages moved to the DLQ after 3 receives', /dead-letter queue/, 'aws'],
    // GCP
    ['gcp_project_denied: x', /GCP project can't be used/, 'gcp'],
    ['gcp_subscription_denied: subscription_get', /roles\/pubsub\.subscriber on the subscription/, 'gcp'],
    ['403 PERMISSION_DENIED on projects/p/subscriptions/s', /roles\/pubsub\.subscriber/, 'gcp'],
    ['gcp_subscription_not_found: x', /subscription does not exist/, 'gcp'],
    ['SERVICE_DISABLED: Cloud Pub/Sub API has not been used', /Enable pubsub\.googleapis\.com/, 'gcp'],
    // Azure (unchanged copy from the Cloud pull page)
    ['checkpoint_access_denied: x', /Storage Blob Data Contributor/, 'azure'],
    // reconciler
    ['source_not_enrolled: aws_cloudtrail is not an enabled log source', /not enabled/, 'log_source'],
    ['no_parser_lane: aws_cloudtrail has no parser', /No parser serves this lane/, 'log_source'],
  ];
  it.each(cases)('%s', (lastError, hint, setup) => {
    const result = pullErrorHint(lastError);
    expect(result.hint).toMatch(hint);
    expect(result.setup).toBe(setup);
    expect(result.retriesAutomatically).toBe(false);
  });

  it('distinguishes a render in flight from a failed or blocked render', () => {
    const waiting = pullErrorHint('pull_render_waiting: verified; nano is rolling the pull configuration out and retries automatically');
    expect(waiting).toMatchObject({ code: 'pull_render_waiting', retriesAutomatically: true, setup: null });
    for (const code of ['pull_render_failed', 'pull_render_refused', 'pull_render_blocked']) {
      const result = pullErrorHint(`${code}: deployer_refusal/provision`);
      expect(result.code).toBe(code);
      expect(result.retriesAutomatically, code).toBe(false);
      expect(result.hint, code).toMatch(/nano has recorded the failure/);
      expect(result.hint, code).not.toMatch(/alerted/);
      expect(result.hint, code).not.toMatch(/retr/i);
    }
  });

  it('marks platform-side and transient codes as retrying automatically', () => {
    for (const err of ['probe_unreachable: the pull broker could not be reached', 'sqs_unavailable: x', 'gcp_unreachable: x', 'gcp_service_account_missing: x', 'external_id_check_inconclusive: x']) {
      const result = pullErrorHint(err);
      expect(result.retriesAutomatically, err).toBe(true);
      expect(result.setup, err).toBeNull();
    }
  });

  it('fills in the ExternalId, nano principal and service account when given', () => {
    const aws = pullErrorHint('assume_role_denied: x', { externalId: 'ext-123', nanoPrincipalArn: 'arn:aws:iam::210987654321:role/nano-pull-broker' });
    expect(aws.hint).toContain('ext-123');
    expect(aws.hint).toContain('arn:aws:iam::210987654321:role/nano-pull-broker');
    expect(aws.code).toBe('assume_role_denied');
    const gcp = pullErrorHint('gcp_subscription_denied: x', { gcpServiceAccount: 'nano-t-abc@pull.iam.gserviceaccount.com' });
    expect(gcp.hint).toContain('serviceAccount:nano-t-abc@pull.iam.gserviceaccount.com');
  });

  it('falls back to the setup panel wording without setup values', () => {
    expect(pullErrorHint('assume_role_denied: x').hint).toContain('ExternalId shown in the AWS setup panel');
  });

  it('returns no hint for unknown text, but keeps a code when there is one', () => {
    expect(pullErrorHint('something odd happened')).toEqual({ code: null, hint: null, retriesAutomatically: false, setup: null });
    expect(pullErrorHint('brand_new_code: x').code).toBe('brand_new_code');
    expect(pullErrorHint(null).hint).toBeNull();
  });

  it('knows which errors want setup values', () => {
    expect(hintNeedsAwsSetup('assume_role_denied: x')).toBe(true);
    expect(hintNeedsAwsSetup('queue_not_found: x')).toBe(false);
    expect(hintNeedsGcpSetup('gcp_subscription_denied: x')).toBe(true);
    expect(hintNeedsGcpSetup('gcp_project_denied: x')).toBe(false);
  });
});

describe('delivery attention', () => {
  const pull = (state: string, last_error: string | null = null) => ({ id: 'p1', name: 'trail', state, last_error });
  it('flags failed, blocked and paused pulls only', () => {
    expect(pullAttention(pull('failed', 'assume_role_denied: x'))).toMatchObject({ level: 'failed', reason: 'assume_role_denied' });
    expect(pullAttention(pull('pending_bundle', 'no_parser_lane: x'))).toMatchObject({ level: 'blocked', reason: 'no_parser_lane' });
    expect(pullAttention(pull('paused'))).toMatchObject({ level: 'paused' });
    expect(pullAttention(pull('pending_verification'))).toBeNull();
    expect(pullAttention(pull('active'))).toBeNull();
  });

  it('flags failed, timed-out and disabled connector feeds', () => {
    const feed = (status: string, enabled = true) => ({ id: 'f1', name: 'gws', status, enabled, last_error: null });
    expect(connectorAttention(feed('failed'))).toMatchObject({ level: 'failed' });
    expect(connectorAttention(feed('timeout'))).toMatchObject({ level: 'failed', reason: 'last run timed out' });
    expect(connectorAttention(feed('disabled', false))).toMatchObject({ level: 'paused', reason: 'disabled' });
    expect(connectorAttention(feed('success'))).toBeNull();
    expect(connectorAttention(feed('pending'))).toBeNull();
  });

  it('ranks failed over blocked over paused and summarises each item', () => {
    const items = [
      { kind: 'pull', name: 'a', level: 'paused', reason: 'paused' },
      { kind: 'connector', name: 'b', level: 'failed', reason: 'last run failed' },
      { kind: 'pull', name: 'c', level: 'blocked', reason: 'no_parser_lane' },
    ];
    expect(worstAttention(items)).toBe('failed');
    expect(worstAttention(items.slice(0, 1))).toBe('paused');
    expect(worstAttention([])).toBeNull();
    expect(attentionSummary(items)).toEqual([
      'pull · a: paused',
      'connector · b: failed (last run failed)',
      'pull · c: blocked (no_parser_lane)',
    ]);
  });
});
