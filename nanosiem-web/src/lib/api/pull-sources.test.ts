// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-3596: cloud pull API client + the add-form validation that builds its POST body. */
import { describe, expect, it, vi } from 'vitest';
import { PullSourcesApi } from './pull-sources';
import {
  azureCreateError,
  azureNamespaceHost,
  azureProbeHint,
  gcpSubscriptionProblem,
  normalizeAzureNamespace,
  pullTarget,
  safeQuickCreateUrl,
  validateAwsPullForm,
  validateAzurePullForm,
  validateGcpPullForm,
  type AwsPullForm,
  type AzurePullForm,
  type GcpPullForm,
} from '@/lib/cloud-pull';

function client() {
  const request = vi.fn(async () => ({}));
  return { request, api: new PullSourcesApi(request as unknown as <T>(e: string, o?: RequestInit) => Promise<T>) };
}

describe('PullSourcesApi', () => {
  it('calls the /api/pull-sources contract', async () => {
    const { request, api } = client();
    await api.getAwsSetup();
    await api.list();
    await api.get('ps 1');
    await api.pause('ps1');
    await api.resume('ps1');
    await api.retry('ps1');
    await api.remove('ps1');
    expect(request.mock.calls).toEqual([
      ['/api/pull-sources/setup/aws'],
      ['/api/pull-sources'],
      ['/api/pull-sources/ps%201'],
      ['/api/pull-sources/ps1/pause', { method: 'POST' }],
      ['/api/pull-sources/ps1/resume', { method: 'POST' }],
      ['/api/pull-sources/ps1/retry', { method: 'POST' }],
      ['/api/pull-sources/ps1', { method: 'DELETE' }],
    ]);
  });

  it('POSTs the create body as JSON', async () => {
    const { request, api } = client();
    const body = {
      name: 'trail', provider: 'aws_sqs' as const, source_slug: 'aws_cloudtrail',
      aws: { region: 'us-east-1', role_arn: 'arn:aws:iam::210987654321:role/r', queue_arn: 'arn:aws:sqs:us-east-1:210987654321:q' },
    };
    await api.create(body);
    expect(request).toHaveBeenCalledWith('/api/pull-sources', { method: 'POST', body: JSON.stringify(body) });
  });

  it('PATCHes a credential rotation with only the credential block (NAN-3729)', async () => {
    const { request, api } = client();
    await api.update('ps 1', { aws: { role_arn: 'arn:aws:iam::210987654321:role/r2' } });
    expect(request).toHaveBeenCalledWith('/api/pull-sources/ps%201', {
      method: 'PATCH', body: JSON.stringify({ aws: { role_arn: 'arn:aws:iam::210987654321:role/r2' } }),
    });
  });
});

const valid: AwsPullForm = {
  name: 'prod trail', sourceSlug: 'aws_cloudtrail', region: 'us-east-1',
  roleArn: 'arn:aws:iam::210987654321:role/nano/pull-role', queueArn: 'arn:aws:sqs:us-east-1:210987654321:trail.fifo',
  bucket: '', prefix: '',
};

describe('validateAwsPullForm', () => {
  it('builds an aws_sqs body without bucket or prefix keys', () => {
    const { errors, request } = validateAwsPullForm(valid);
    expect(errors).toEqual({});
    expect(request).toStrictEqual({
      name: 'prod trail', provider: 'aws_sqs', source_slug: 'aws_cloudtrail',
      aws: { region: 'us-east-1', role_arn: valid.roleArn, queue_arn: valid.queueArn },
    });
  });

  it('derives aws_s3_sqs from a bucket and keeps the prefix', () => {
    const { request } = validateAwsPullForm({ ...valid, bucket: 'org-trail', prefix: 'AWSLogs/' });
    expect(request?.provider).toBe('aws_s3_sqs');
    expect(request?.aws).toStrictEqual({ region: 'us-east-1', role_arn: valid.roleArn, queue_arn: valid.queueArn, bucket: 'org-trail', prefix: 'AWSLogs/' });
  });

  it('rejects mismatched accounts and regions', () => {
    expect(validateAwsPullForm({ ...valid, queueArn: 'arn:aws:sqs:us-east-1:234567890123:q' }).errors.queueArn)
      .toMatch(/234567890123 must match the role account 210987654321/);
    expect(validateAwsPullForm({ ...valid, region: 'eu-west-1' }).errors.queueArn).toMatch(/in us-east-1, not eu-west-1/);
  });

  it('mirrors the server ARN, region, slug, bucket and prefix rules', () => {
    const e = (patch: Partial<AwsPullForm>) => validateAwsPullForm({ ...valid, ...patch }).errors;
    expect(e({ roleArn: 'arn:aws-us-gov:iam::210987654321:role/r' }).roleArn).toBeTruthy();
    expect(e({ roleArn: 'arn:aws:iam::11111111111:role/r' }).roleArn).toBeTruthy();
    expect(e({ roleArn: 'arn:aws:iam::210987654321:user/r' }).roleArn).toBeTruthy();
    expect(e({ queueArn: 'arn:aws:sqs:us-east-1:210987654321:bad name' }).queueArn).toBeTruthy();
    expect(e({ queueArn: 'arn:aws:sqs:us-gov-west-1:210987654321:q', region: 'us-gov-west-1' }).region).toBeTruthy();
    expect(e({ sourceSlug: 'unknown' }).sourceSlug).toBeTruthy();
    expect(e({ sourceSlug: 'AWS' }).sourceSlug).toBeTruthy();
    expect(e({ name: ' padded' }).name).toBeTruthy();
    expect(e({ name: 'has $var' }).name).toBeTruthy();
    expect(e({ bucket: 'Bad_Bucket' }).bucket).toBeTruthy();
    expect(e({ bucket: '192.168.1.1' }).bucket).toBeTruthy();
    expect(e({ bucket: 'b-s3alias' }).bucket).toBeTruthy();
    expect(e({ bucket: 'ok-bucket', prefix: '/abs' }).prefix).toBeTruthy();
    expect(e({ bucket: 'ok-bucket', prefix: 'a/../b' }).prefix).toBeTruthy();
    expect(e({ prefix: 'AWSLogs/' }).prefix).toMatch(/needs a bucket/);
  });
});

describe('PullSourcesApi GCP (NAN-3598)', () => {
  it('asks the GCP setup with and without an encoded subscription', async () => {
    const { request, api } = client();
    await api.getGcpSetup();
    await api.getGcpSetup('projects/acme-logs/subscriptions/nano+audit~1');
    await api.getGcpSetup('');
    expect(request.mock.calls).toEqual([
      ['/api/pull-sources/setup/gcp'],
      ['/api/pull-sources/setup/gcp?subscription=projects%2Facme-logs%2Fsubscriptions%2Fnano%2Baudit~1'],
      ['/api/pull-sources/setup/gcp'],
    ]);
  });

  it('POSTs a gcp_pubsub create body as JSON', async () => {
    const { request, api } = client();
    const body = {
      name: 'audit', provider: 'gcp_pubsub' as const, source_slug: 'gcp_audit',
      gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit' }, tuning: { ack_deadline_secs: 60 },
    };
    await api.create(body);
    expect(request).toHaveBeenCalledWith('/api/pull-sources', { method: 'POST', body: JSON.stringify(body) });
  });
});

describe('gcpSubscriptionProblem', () => {
  it('accepts valid resource names', () => {
    for (const ok of [
      'projects/acme-logs/subscriptions/nano-audit',
      'projects/a12345/subscriptions/abc',
      'projects/my-project-123456789012345678/subscriptions/Sub.with_all~chars+50%-x',
      `projects/acme-logs/subscriptions/a${'b'.repeat(254)}`,
    ]) expect(gcpSubscriptionProblem(ok)).toBeNull();
  });

  it('rejects bad shapes, projects and names', () => {
    const shape = 'Use projects/<project>/subscriptions/<name>';
    expect(gcpSubscriptionProblem('nano-audit')).toBe(shape);
    expect(gcpSubscriptionProblem('projects/acme-logs/topics/nano-audit')).toBe(shape);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/nano-audit/extra')).toBe(shape);
    expect(gcpSubscriptionProblem('/projects/acme-logs/subscriptions/nano-audit')).toBe(shape);
    expect(gcpSubscriptionProblem('projects/Acme-Logs/subscriptions/nano-audit')).toMatch(/^Project ID/);
    expect(gcpSubscriptionProblem('projects/acme/subscriptions/nano-audit')).toMatch(/^Project ID/);
    expect(gcpSubscriptionProblem('projects/acme-logs-/subscriptions/nano-audit')).toMatch(/^Project ID/);
    expect(gcpSubscriptionProblem('projects/1acme-logs/subscriptions/nano-audit')).toMatch(/^Project ID/);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/google-audit')).toMatch(/'goog'/);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/goog')).toMatch(/'goog'/);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/ab')).toMatch(/^Subscription name/);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/1abc')).toMatch(/^Subscription name/);
    expect(gcpSubscriptionProblem('projects/acme-logs/subscriptions/has space')).toMatch(/^Subscription name/);
    expect(gcpSubscriptionProblem(`projects/acme-logs/subscriptions/a${'b'.repeat(255)}`)).toMatch(/^Subscription name/);
  });
});

const validGcp: GcpPullForm = {
  name: 'audit', sourceSlug: 'gcp_audit', subscription: ' projects/acme-logs/subscriptions/nano-audit ', ackDeadline: '',
};

describe('validateGcpPullForm', () => {
  it('builds a gcp_pubsub body without tuning by default', () => {
    const { errors, request } = validateGcpPullForm(validGcp);
    expect(errors).toEqual({});
    expect(request).toStrictEqual({
      name: 'audit', provider: 'gcp_pubsub', source_slug: 'gcp_audit',
      gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit' },
    });
  });

  it('adds tuning.ack_deadline_secs within 10-600 and rejects the rest', () => {
    expect(validateGcpPullForm({ ...validGcp, ackDeadline: '10' }).request?.tuning).toStrictEqual({ ack_deadline_secs: 10 });
    expect(validateGcpPullForm({ ...validGcp, ackDeadline: '600' }).request?.tuning).toStrictEqual({ ack_deadline_secs: 600 });
    for (const bad of ['9', '601', '1.5', '-10', 'abc']) {
      expect(validateGcpPullForm({ ...validGcp, ackDeadline: bad }).errors.ackDeadline).toBe('Whole seconds, 10-600');
    }
  });

  it('shares the name and lane rules and requires a subscription', () => {
    const e = (patch: Partial<GcpPullForm>) => validateGcpPullForm({ ...validGcp, ...patch }).errors;
    expect(e({ name: '' }).name).toBe('Required');
    expect(e({ sourceSlug: 'unknown' }).sourceSlug).toBeTruthy();
    expect(e({ subscription: '' }).subscription).toBe('Required');
    expect(e({ subscription: 'nano-audit' }).subscription).toBe('Use projects/<project>/subscriptions/<name>');
  });
});

describe('pullTarget', () => {
  it('reads <namespace>/<hub> for an Azure row', () => {
    expect(pullTarget({
      azure: {
        namespace: 'acme-logs', event_hub: 'signins', consumer_group: 'nano',
        directory_id: 'd', client_id: 'c',
      },
    })).toBe('acme-logs/signins');
  });

  it('reads the queue or the subscription', () => {
    expect(pullTarget({ aws: { region: 'r', account_id: 'a', role_arn: 'x', queue_arn: 'arn:q' }, gcp: null })).toBe('arn:q');
    expect(pullTarget({ aws: null, gcp: { subscription: 'projects/p/subscriptions/s', service_account: 'sa' } })).toBe('projects/p/subscriptions/s');
    expect(pullTarget({})).toBe('');
  });
});

describe('safeQuickCreateUrl', () => {
  it('accepts only https AWS console links', () => {
    expect(safeQuickCreateUrl('https://us-east-1.console.aws.amazon.com/cloudformation/home#/stacks/quickcreate')).toMatch(/^https:/);
    expect(safeQuickCreateUrl('https://console.aws.amazon.com/cloudformation')).toMatch(/^https:/);
    expect(safeQuickCreateUrl('javascript:alert(1)')).toBeNull();
    expect(safeQuickCreateUrl('https://console.aws.amazon.com.evil.test/')).toBeNull();
    expect(safeQuickCreateUrl('http://console.aws.amazon.com/')).toBeNull();
    expect(safeQuickCreateUrl(undefined)).toBeNull();
  });
});

// --- NAN-3604: Azure Event Hubs ---

const G1 = '11111111-2222-4333-8444-555555555555';
const G2 = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const G3 = '0f0f0f0f-1e1e-4d2d-9c3c-4b4b4b4b4b4b';

describe('PullSourcesApi (Azure)', () => {
  it('asks the Azure setup and POSTs an azure_event_hubs body as JSON', async () => {
    const { request, api } = client();
    await api.getAzureSetup();
    expect(request).toHaveBeenLastCalledWith('/api/pull-sources/setup/azure');
    const body = {
      name: 'signins', provider: 'azure_event_hubs' as const, source_slug: 'azure_signin',
      azure: {
        directory_id: G1, client_id: G2, subscription_id: G3, namespace: 'acme-logs', event_hub: 'signins',
        consumer_group: 'nano', checkpoint_account: 'acmecheckpoints', checkpoint_container: 'nano-checkpoints',
      },
    };
    await api.create(body);
    expect(request).toHaveBeenLastCalledWith('/api/pull-sources', { method: 'POST', body: JSON.stringify(body) });
  });
});

const validAzure: AzurePullForm = {
  name: 'entra sign-ins', sourceSlug: 'azure_signin', directoryId: ` ${G1.toUpperCase()} `, clientId: G2,
  subscriptionId: G3, namespace: 'Acme-Logs.servicebus.windows.net', eventHub: 'insights-logs-signinlogs',
  consumerGroup: '', checkpointAccount: 'acmecheckpoints', checkpointContainer: 'nano-checkpoints',
};

describe('validateAzurePullForm', () => {
  it('builds the exact azure_event_hubs body: lowercased GUIDs, short namespace, no consumer group when empty', () => {
    const { errors, request } = validateAzurePullForm(validAzure);
    expect(errors).toEqual({});
    expect(request).toStrictEqual({
      name: 'entra sign-ins', provider: 'azure_event_hubs', source_slug: 'azure_signin',
      azure: {
        directory_id: G1, client_id: G2, subscription_id: G3, namespace: 'acme-logs',
        event_hub: 'insights-logs-signinlogs', checkpoint_account: 'acmecheckpoints', checkpoint_container: 'nano-checkpoints',
      },
    });
    // Never a secret-shaped field.
    expect(JSON.stringify(request)).not.toMatch(/secret|sas|connection|key|endpoint|password/i);
  });

  it('sends a named or $Default consumer group', () => {
    expect(validateAzurePullForm({ ...validAzure, consumerGroup: 'nano' }).request?.azure.consumer_group).toBe('nano');
    expect(validateAzurePullForm({ ...validAzure, consumerGroup: '$Default' }).request?.azure.consumer_group).toBe('$Default');
  });

  it('mirrors the server grammar', () => {
    const e = (patch: Partial<AzurePullForm>) => validateAzurePullForm({ ...validAzure, ...patch }).errors;
    expect(e({ directoryId: '' }).directoryId).toBe('Required');
    expect(e({ directoryId: 'contoso.onmicrosoft.com' }).directoryId).toMatch(/^Expected a GUID/);
    expect(e({ clientId: '00000000-0000-0000-0000-000000000000' }).clientId).toBe('Must not be the nil GUID');
    expect(e({ subscriptionId: '1234' }).subscriptionId).toMatch(/^Expected a GUID/);
    for (const bad of ['abc', '1acme-logs', 'acme-logs-', 'acme_logs', `a${'b'.repeat(50)}`, 'acme.logs']) {
      expect(e({ namespace: bad }).namespace).toMatch(/^6-50 lowercase/);
    }
    for (const ok of ['abcdef', 'acme-logs-01', `a${'b'.repeat(49)}`, 'sb://acme-logs.servicebus.windows.net/']) {
      expect(e({ namespace: ok }).namespace).toBeUndefined();
    }
    expect(e({ eventHub: '' }).eventHub).toBe('Required');
    expect(e({ eventHub: '-hub' }).eventHub).toMatch(/^Up to 256/);
    expect(e({ eventHub: 'hub/x' }).eventHub).toMatch(/^Up to 256/);
    expect(e({ eventHub: 'a'.repeat(257) }).eventHub).toMatch(/^Up to 256/);
    expect(e({ eventHub: 'Hub.with_all-chars9' }).eventHub).toBeUndefined();
    expect(e({ consumerGroup: '$default' }).consumerGroup).toMatch(/^\$Default, or/);
    expect(e({ consumerGroup: 'g'.repeat(51) }).consumerGroup).toMatch(/^\$Default, or/);
    for (const bad of ['ab', 'Acmecheckpoints', 'acme-checkpoints', 'a'.repeat(25)]) {
      expect(e({ checkpointAccount: bad }).checkpointAccount).toBe('3-24 lowercase letters and digits');
    }
    for (const bad of ['ab', 'Nano', '-nano', 'nano-', 'na--no', 'nano_ck', 'a'.repeat(64)]) {
      expect(e({ checkpointContainer: bad }).checkpointContainer).toMatch(/^3-63 lowercase/);
    }
    for (const ok of ['abc', 'nano-check-01', 'a'.repeat(63)]) {
      expect(e({ checkpointContainer: ok }).checkpointContainer).toBeUndefined();
    }
    expect(e({ name: '' }).name).toBe('Required');
    expect(e({ sourceSlug: 'unknown' }).sourceSlug).toBeTruthy();
  });

  it('derives the namespace host', () => {
    expect(normalizeAzureNamespace(' SB://Acme-Logs.servicebus.windows.net/ ')).toBe('acme-logs');
    expect(azureNamespaceHost('acme-logs')).toBe('acme-logs.servicebus.windows.net');
    expect(azureNamespaceHost('ab')).toBeNull();
  });
});

describe('azureCreateError', () => {
  it('maps deny refusals to generic text that never names the owner', () => {
    const tenant = azureCreateError({ message: 'invalid pull source azure.directory_id: target_tenant_denied', status: 400 });
    expect(tenant?.field).toBe('directoryId');
    expect(tenant?.message).toMatch(/^This Azure tenant can't be used/);
    const sub = azureCreateError({ message: 'x', code: 'target_subscription_denied', status: 400 });
    expect(sub?.field).toBe('subscriptionId');
    expect(sub?.message).toMatch(/^This Azure subscription can't be used/);
    for (const m of [tenant!.message, sub!.message]) expect(m).not.toMatch(/nano|deny|denied|blocked|internal/i);
  });

  it('puts a field refusal on its field and passes other messages through', () => {
    expect(azureCreateError({ message: 'invalid pull source azure.namespace: 6-50 lowercase letters, digits or hyphens; letter first' }))
      .toEqual({ field: 'namespace', message: '6-50 lowercase letters, digits or hyphens; letter first' });
    expect(azureCreateError({ message: 'invalid pull source azure.checkpoint_container: invalid container name' })?.field)
      .toBe('checkpointContainer');
    expect(azureCreateError({ message: 'a source with this name exists', status: 409 }))
      .toEqual({ message: 'a source with this name exists' });
    expect(azureCreateError({ message: 'provider_not_supported: azure_event_hubs' })?.message).toMatch(/not available/);
    expect(azureCreateError(null)).toBeNull();
  });
});

describe('azureProbeHint', () => {
  it('names the next step for each broker probe code', () => {
    const cases: [string, RegExp][] = [
      ['azure_denied: AADSTS700213 no matching federated identity record', /federated credential/],
      ['azure_rejected: AADSTS7000215', /app configuration/],
      ['azure_token_mismatch: tid', /directory and client IDs/],
      ['subscription_tenant_mismatch', /different directory/],
      ['checkpoint_access_denied: 403', /Storage Blob Data Contributor/],
      ['checkpoint_container_not_found: 404', /does not exist/],
      ['event_hub_not_found', /Data Receiver/],
      ['target_tenant_denied', /can't be used/],
    ];
    for (const [err, hint] of cases) expect(azureProbeHint(err)).toMatch(hint);
    expect(azureProbeHint('connection reset')).toBeNull();
    expect(azureProbeHint(null)).toBeNull();
  });
});
