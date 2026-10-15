// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull sources (NAN-3288 / NAN-3596 / NAN-3598 / NAN-3604): the tenant's
 * AWS S3 + SQS queues that nano reads with an assumed role, GCP Pub/Sub
 * subscriptions it reads as a per-tenant service account, and Azure Event Hubs
 * it reads as the tenant's own Entra app through a federated identity
 * credential (no client secret). Contract:
 * `/api/pull-sources` (NAN-3592). Every wire type for the surface lives here.
 *
 * The tenant never sends an ExternalId, service account, endpoint or key: nano
 * derives them and shows them on the setup calls; a create carries only the
 * fields in `CreatePullSourceRequest`.
 */

export type PullSourceProvider = 'aws_s3_sqs' | 'aws_sqs' | 'gcp_pubsub' | 'azure_event_hubs';
export type PullSourceState = 'pending_verification' | 'pending_bundle' | 'active' | 'paused' | 'failed';

export interface PullSourceAwsTarget {
  region: string;
  account_id: string;
  role_arn: string;
  queue_arn: string;
  bucket?: string | null;
  prefix?: string | null;
}

export interface PullSource {
  id: string;
  name: string;
  provider: PullSourceProvider;
  source_slug: string;
  state: PullSourceState;
  last_error?: string | null;
  verified_at?: string | null;
  revision: number;
  created_at: string;
  updated_at: string;
  aws?: PullSourceAwsTarget | null;
  gcp?: PullSourceGcpTarget | null;
  azure?: PullSourceAzureTarget | null;
}

/** An Azure Event Hubs row (NAN-3604). The FQDN is always `<namespace>.servicebus.windows.net`. */
export interface PullSourceAzureTarget {
  namespace: string;
  event_hub: string;
  consumer_group: string;
  directory_id: string;
  client_id: string;
  subscription_id?: string | null;
  checkpoint_account?: string | null;
  checkpoint_container?: string | null;
}

export interface PullSourceGcpTarget {
  /** `projects/<project>/subscriptions/<name>`. */
  subscription: string;
  /** The tenant's nano service account the binding names. */
  service_account?: string | null;
}

/** `GET /api/pull-sources/setup/aws`: what the tenant pastes into AWS. */
export interface PullSourceAwsSetup {
  /** nano's IAM role (`arn:aws:iam::<nano>:role/nano-pull-broker`); never a user or access key. */
  nano_principal_arn: string;
  external_id: string;
  external_id_version: number;
  /** `nano-<tenant>`: the sts:SourceIdentity on every nano session. */
  source_identity?: string;
  trust_policy: Record<string, unknown>;
  permission_policy_template: Record<string, unknown>;
  /** CloudFormation template; the API returns it as a JSON object. */
  cloudformation_template: Record<string, unknown> | string;
  supported_regions?: string[];
  quick_create_url?: string | null;
}

/** `GET /api/pull-sources/setup/gcp`: the IAM binding the tenant adds on its subscription. */
export interface PullSourceGcpSetup {
  /** The tenant's nano service account email. */
  service_account: string;
  /** `serviceAccount:<email>`. */
  member: string;
  /** Always `roles/pubsub.subscriber`. */
  role: string;
  /** Always `subscription`: the role is granted on the subscription, never the project. */
  binding_level: 'subscription' | string;
  /** `projects/<PROJECT_ID>/subscriptions/<SUBSCRIPTION_ID>`. */
  subscription_format: string;
  /** The validated `?subscription=` value, or null. */
  subscription: string | null;
  /** With `?subscription=`, the placeholders are filled in. */
  gcloud_command: string;
  verify_command: string;
  ack_deadline_secs: { min: number; max: number };
  /** NAN-3658: the lane a create without `source_slug` feeds (`gcp_audit`); absent on older servers. */
  default_source_slug?: string;
}

/** A role the tenant's app needs (`GET /api/pull-sources/setup/azure`). */
export interface PullSourceAzurePermission {
  /** Built-in role name, e.g. `Azure Event Hubs Data Receiver`. */
  role: string;
  /** `event_hub` | `checkpoint_container`: the narrowest scope to grant it on. */
  scope: string;
  /** ARM scope with `<UPPER_CASE>` placeholders. */
  scope_template: string;
}

/** Copyable `az` commands; `<UPPER_CASE>` tokens are placeholders. */
export interface PullSourceAzureCommands {
  /** Skip when reusing an app registration. */
  app_registration?: string;
  service_principal?: string;
  federated_credential: string;
  role_event_hub: string;
  checkpoint_container?: string;
  role_checkpoint: string;
  consumer_group: string;
  /** Prose with an example command: routing logs into the hub via diagnostic settings. */
  diagnostic_settings_hint: string;
}

/**
 * `GET /api/pull-sources/setup/azure` (NAN-3604): the federated identity
 * credential the tenant adds to its own app registration, and the two role
 * assignments. nano never asks for or receives a client secret.
 */
export interface PullSourceAzureSetup {
  /** nano's pull-broker issuer (`https://pull-broker.nano.rs`). */
  issuer: string;
  /** `nano-pull:azure:<tenant>`: constant across this tenant's sources. */
  subject: string;
  /** Always `api://AzureADTokenExchange`. */
  audience: string;
  /** Suggested credential name (`nano-pull`). */
  federated_credential_name: string;
  app_permissions: PullSourceAzurePermission[];
  commands: PullSourceAzureCommands;
  /** Endpoints the pull container reaches, for customer firewalls. */
  endpoints?: { event_hubs: string; checkpoint_blob: string };
  /** `$Default`. */
  default_consumer_group?: string;
  /** Returned by the API; deliberately never rendered. */
  deny?: { tenants: string[]; subscriptions: string[] };
}

export interface CreateAwsPullSourceRequest {
  name: string;
  provider: Extract<PullSourceProvider, 'aws_s3_sqs' | 'aws_sqs'>;
  source_slug: string;
  aws: {
    region: string;
    role_arn: string;
    queue_arn: string;
    bucket?: string;
    prefix?: string;
  };
}

export interface CreateGcpPullSourceRequest {
  name: string;
  provider: 'gcp_pubsub';
  source_slug: string;
  gcp: { subscription: string };
  tuning?: { ack_deadline_secs: number };
}

export interface CreateAzurePullSourceRequest {
  name: string;
  provider: 'azure_event_hubs';
  source_slug: string;
  azure: {
    directory_id: string;
    client_id: string;
    subscription_id: string;
    /** Short name; nano derives `<namespace>.servicebus.windows.net`. */
    namespace: string;
    event_hub: string;
    /** Omitted = `$Default`. */
    consumer_group?: string;
    checkpoint_account: string;
    checkpoint_container: string;
  };
}

export type CreatePullSourceRequest =
  | CreateAwsPullSourceRequest
  | CreateGcpPullSourceRequest
  | CreateAzurePullSourceRequest;

/**
 * NAN-3729: `PATCH /api/pull-sources/{id}`: rotate the credential an existing
 * source uses, in place. Exactly the row's own block: the AWS role, or the
 * Entra app / directory. The queue, subscription, hub, consumer group and
 * checkpoint (the source's cursor) never change, and GCP has no customer
 * credential (nano's per-tenant service account is fixed). The source
 * re-enters verification and turns active again once the new credential
 * passes the broker probe.
 */
export type UpdatePullSourceRequest =
  | { aws: { role_arn: string } }
  | { azure: { directory_id?: string; client_id?: string } };

/** Error codes the surface handles quietly instead of as failures. */
export const PULL_SOURCES_NOT_ENABLED = 'pull_sources_not_enabled';
export const PULL_SETUP_UNAVAILABLE = 'pull_setup_unavailable';

export class PullSourcesApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  getAwsSetup(): Promise<PullSourceAwsSetup> {
    return this.request('/api/pull-sources/setup/aws');
  }

  /** With a subscription, the gcloud and verify commands come back filled in. */
  getGcpSetup(subscription?: string): Promise<PullSourceGcpSetup> {
    const query = subscription ? `?subscription=${encodeURIComponent(subscription)}` : '';
    return this.request(`/api/pull-sources/setup/gcp${query}`);
  }

  getAzureSetup(): Promise<PullSourceAzureSetup> {
    return this.request('/api/pull-sources/setup/azure');
  }

  list(): Promise<PullSource[]> {
    return this.request('/api/pull-sources');
  }

  get(id: string): Promise<PullSource> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}`);
  }

  create(body: CreatePullSourceRequest): Promise<PullSource> {
    return this.request('/api/pull-sources', { method: 'POST', body: JSON.stringify(body) });
  }

  pause(id: string): Promise<PullSource> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}/pause`, { method: 'POST' });
  }

  resume(id: string): Promise<PullSource> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}/resume`, { method: 'POST' });
  }

  /** NAN-3618: send a `failed` source back through verification (any other state is 409). */
  retry(id: string): Promise<PullSource> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}/retry`, { method: 'POST' });
  }

  /** NAN-3729: rotate the source's credential in place; it re-verifies (an unchanged one is a no-op). */
  update(id: string, body: UpdatePullSourceRequest): Promise<PullSource> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
  }

  remove(id: string): Promise<void> {
    return this.request(`/api/pull-sources/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }
}
