// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull (NAN-3596 / NAN-3598 / NAN-3604): client-side checks for the AWS,
 * GCP and Azure add forms. They mirror the server validators in `nanosiem-core/src/shared_pull_sources.rs`
 * so a typo is caught before the POST; the server stays the gate.
 */

import type {
  CreateAwsPullSourceRequest,
  CreateAzurePullSourceRequest,
  CreateGcpPullSourceRequest,
  PullSource,
  PullSourceProvider,
  PullSourceState,
  UpdatePullSourceRequest,
} from '@/lib/api/pull-sources';

export const CLOUD_PULL_PATH = '/ingestion/log-sources/cloud-pull';

/** Commercial partition only (`AWS_COMMERCIAL_REGIONS`). */
export const AWS_COMMERCIAL_REGIONS = [
  'af-south-1', 'ap-east-1', 'ap-east-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
  'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4',
  'ap-southeast-5', 'ap-southeast-6', 'ap-southeast-7', 'ca-central-1', 'ca-west-1', 'eu-central-1',
  'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2', 'eu-west-3',
  'il-central-1', 'me-central-1', 'me-south-1', 'mx-central-1', 'sa-east-1', 'us-east-1', 'us-east-2',
  'us-west-1', 'us-west-2',
] as const;

export const STATE_LABEL: Record<PullSourceState, string> = {
  pending_verification: 'verifying',
  pending_bundle: 'deploying',
  active: 'active',
  paused: 'paused',
  failed: 'failed',
};

/**
 * NAN-3618: a pending row that carries a reconciler error is stuck, not
 * progressing. "deploying" next to `source_not_enrolled…` reads as a
 * contradiction, so a pending state with a last_error is labelled "blocked"
 * (the error column gives the reason). Clean pending rows keep their label.
 */
export function pullStateLabel(state: PullSourceState, lastError?: string | null): string {
  if ((state === 'pending_bundle' || state === 'pending_verification') && lastError) return 'blocked';
  return STATE_LABEL[state] ?? state;
}

/** Row actions the API accepts per state (shared_pull_sources.rs transition SQL). */
export type PullRowAction = 'pause' | 'resume' | 'retry' | 'delete';
export function pullRowActions(state: PullSourceState): PullRowAction[] {
  switch (state) {
    case 'failed': return ['retry', 'delete'];
    case 'paused': return ['resume', 'delete'];
    case 'active':
    case 'pending_verification':
    case 'pending_bundle': return ['pause', 'delete'];
    default: return ['delete'];
  }
}

export const PROVIDER_LABEL: Record<PullSourceProvider, string> = {
  aws_s3_sqs: 'S3 via SQS',
  aws_sqs: 'SQS',
  gcp_pubsub: 'GCP Pub/Sub',
  azure_event_hubs: 'Azure Event Hubs',
};

const ROLE_ARN = /^arn:aws:iam::(\d{12}):role\/([A-Za-z0-9+=,.@_/-]+)$/;
const QUEUE_ARN = /^arn:aws:sqs:([a-z0-9-]+):(\d{12}):([A-Za-z0-9_-]+(?:\.fifo)?)$/;
const SLUG = /^[a-z0-9][a-z0-9_-]{0,99}$/;
const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const PREFIX = /^[A-Za-z0-9!_.*()/=,@+:-]*$/;

export function parseRoleArn(arn: string): { account: string } | null {
  const m = ROLE_ARN.exec(arn);
  if (!m || arn.length > 2048) return null;
  const path = m[2];
  const name = path.split('/').pop() ?? '';
  if (path.length > 512 || !name || name.length > 64 || path.includes('//')) return null;
  return { account: m[1] };
}

export function parseQueueArn(arn: string): { region: string; account: string; name: string } | null {
  const m = QUEUE_ARN.exec(arn);
  if (!m || arn.length > 256 || m[3].length > 80) return null;
  return { region: m[1], account: m[2], name: m[3] };
}

/** What a row reads: the SQS queue ARN, the Pub/Sub subscription, or `<namespace>/<hub>`. */
export function pullTarget(source: Pick<PullSource, 'aws' | 'gcp' | 'azure'>): string {
  if (source.aws) return source.aws.queue_arn;
  if (source.gcp) return source.gcp.subscription;
  if (source.azure) return `${source.azure.namespace}/${source.azure.event_hub}`;
  return '';
}

export function isAwsRegion(region: string): boolean {
  return (AWS_COMMERCIAL_REGIONS as readonly string[]).includes(region);
}

function bucketProblem(bucket: string): string | null {
  if (!BUCKET.test(bucket)) return 'Lowercase letters, digits, dots and hyphens; 3-63 characters';
  if (/\.\.|\.-|-\./.test(bucket)) return 'Invalid dot placement';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(bucket)) return 'Must not be formatted as an IP address';
  if (/^(xn--|sthree-|amzn-s3-demo-)/.test(bucket) || /(-s3alias|--ol-s3|--x-s3|--table-s3)$/.test(bucket)) {
    return 'Reserved bucket prefix or suffix';
  }
  return null;
}

function prefixProblem(prefix: string): string | null {
  if (prefix.length > 1024) return 'At most 1024 characters';
  if (prefix.startsWith('/')) return "Must not start with '/'";
  if (!PREFIX.test(prefix)) return 'Contains a disallowed character';
  if (prefix.split('/').some((seg) => seg === '.' || seg === '..')) return "Must not contain '.' or '..' segments";
  return null;
}

function nameProblem(name: string): string | null {
  if (!name.trim()) return 'Required';
  if (name.trim() !== name) return 'Must not start or end with whitespace';
  if ([...name].length > 100) return 'At most 100 characters';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f$"\\`]/.test(name)) return 'Contains a disallowed character';
  return null;
}

function slugProblem(slug: string): string | null {
  if (!slug) return 'Required';
  if (!SLUG.test(slug) || slug === 'unknown') return 'Lowercase letters, digits, _ and -';
  return null;
}

export interface AwsPullForm {
  name: string;
  sourceSlug: string;
  region: string;
  roleArn: string;
  queueArn: string;
  bucket: string;
  prefix: string;
}

export type AwsPullField = keyof AwsPullForm;

export const EMPTY_AWS_PULL_FORM: AwsPullForm = {
  name: '', sourceSlug: '', region: '', roleArn: '', queueArn: '', bucket: '', prefix: '',
};

/**
 * Validate the form. Returns per-field messages, and the exact POST body when
 * there are none. Provider is derived: a bucket means S3 notifications via SQS.
 */
export function validateAwsPullForm(form: AwsPullForm): {
  errors: Partial<Record<AwsPullField, string>>;
  request: CreateAwsPullSourceRequest | null;
} {
  const errors: Partial<Record<AwsPullField, string>> = {};
  const name = form.name;
  const slug = form.sourceSlug.trim();
  const region = form.region.trim();
  const roleArn = form.roleArn.trim();
  const queueArn = form.queueArn.trim();
  const bucket = form.bucket.trim();
  const prefix = form.prefix.trim();

  const nameError = nameProblem(name);
  if (nameError) errors.name = nameError;
  const slugError = slugProblem(slug);
  if (slugError) errors.sourceSlug = slugError;

  if (!region) errors.region = 'Required';
  else if (!isAwsRegion(region)) errors.region = 'Not a supported commercial AWS region';

  const role = roleArn ? parseRoleArn(roleArn) : null;
  if (!roleArn) errors.roleArn = 'Required';
  else if (!role) errors.roleArn = 'Expected arn:aws:iam::<12-digit account>:role/<name>';

  const queue = queueArn ? parseQueueArn(queueArn) : null;
  if (!queueArn) errors.queueArn = 'Required';
  else if (!queue) errors.queueArn = 'Expected arn:aws:sqs:<region>:<12-digit account>:<queue>';
  else if (!isAwsRegion(queue.region)) errors.queueArn = 'Queue is not in a supported commercial AWS region';
  else if (role && role.account !== queue.account) {
    errors.queueArn = `Queue account ${queue.account} must match the role account ${role.account}`;
  } else if (region && isAwsRegion(region) && queue.region !== region) {
    errors.queueArn = `Queue is in ${queue.region}, not ${region}`;
  }

  if (bucket) {
    const problem = bucketProblem(bucket);
    if (problem) errors.bucket = problem;
  }
  if (prefix) {
    if (!bucket) errors.prefix = 'A prefix needs a bucket';
    else {
      const problem = prefixProblem(prefix);
      if (problem) errors.prefix = problem;
    }
  }

  if (Object.keys(errors).length > 0) return { errors, request: null };
  const aws: CreateAwsPullSourceRequest['aws'] = { region, role_arn: roleArn, queue_arn: queueArn };
  if (bucket) aws.bucket = bucket;
  if (bucket && prefix) aws.prefix = prefix;
  return {
    errors,
    request: { name, provider: bucket ? 'aws_s3_sqs' : 'aws_sqs', source_slug: slug, aws },
  };
}

// --- GCP Pub/Sub (NAN-3598). Mirrors `parse_gcp_subscription` / `validate_gcp_project`. ---

export const GCP_SUBSCRIPTION_FORMAT = 'projects/<project>/subscriptions/<name>';
export const GCP_ACK_DEADLINE = { min: 10, max: 600 } as const;

const GCP_PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const GCP_SUBSCRIPTION_NAME = /^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$/;

/** Null when `projects/<project>/subscriptions/<name>` is valid; else the message to show. */
export function gcpSubscriptionProblem(path: string): string | null {
  const parts = path.split('/');
  if (parts.length !== 4 || parts[0] !== 'projects' || parts[2] !== 'subscriptions') {
    return `Use ${GCP_SUBSCRIPTION_FORMAT}`;
  }
  const [, project, , name] = parts;
  if (!GCP_PROJECT.test(project)) {
    return 'Project ID: 6-30 lowercase letters, digits and hyphens, starting with a letter';
  }
  if (name.startsWith('goog')) return "Subscription names must not start with 'goog'";
  if (!GCP_SUBSCRIPTION_NAME.test(name)) {
    return 'Subscription name: 3-255 characters, starting with a letter; letters, digits and . _ ~ + % -';
  }
  return null;
}

export interface GcpPullForm {
  name: string;
  sourceSlug: string;
  subscription: string;
  /** Empty = the server default. */
  ackDeadline: string;
}

export type GcpPullField = keyof GcpPullForm;

export const EMPTY_GCP_PULL_FORM: GcpPullForm = { name: '', sourceSlug: '', subscription: '', ackDeadline: '' };

/** NAN-3658: the stock GCP Audit Log (OCSF) lane a Pub/Sub source feeds by default. */
export const GCP_DEFAULT_SOURCE_SLUG = 'gcp_audit';

/**
 * NAN-3658: the lane the GCP form preselects: `gcp_audit` only when that
 * parser is deployed on the tenant (in `lanes`). Otherwise none, so the
 * operator must choose explicitly (the server refuses an undeployed lane).
 */
export function defaultGcpSourceSlug(lanes: readonly string[] | null, preferred = GCP_DEFAULT_SOURCE_SLUG): string {
  return lanes?.includes(preferred) ? preferred : '';
}

/**
 * NAN-3657 / NAN-3658: the parser a pull source feeds, for the Cloud pull
 * table. `deployed` is null while the tenant's lanes are unknown.
 */
export interface PullParser {
  name?: string;
  deployed: boolean | null;
}

export function validateGcpPullForm(
  form: GcpPullForm,
  ack: { min: number; max: number } = GCP_ACK_DEADLINE,
): {
  errors: Partial<Record<GcpPullField, string>>;
  request: CreateGcpPullSourceRequest | null;
} {
  const errors: Partial<Record<GcpPullField, string>> = {};
  const slug = form.sourceSlug.trim();
  const subscription = form.subscription.trim();
  const ackText = form.ackDeadline.trim();

  const nameError = nameProblem(form.name);
  if (nameError) errors.name = nameError;
  const slugError = slugProblem(slug);
  if (slugError) errors.sourceSlug = slugError;

  if (!subscription) errors.subscription = 'Required';
  else {
    const problem = gcpSubscriptionProblem(subscription);
    if (problem) errors.subscription = problem;
  }

  let ackDeadline: number | null = null;
  if (ackText) {
    ackDeadline = /^\d+$/.test(ackText) ? Number(ackText) : NaN;
    if (!Number.isInteger(ackDeadline) || ackDeadline < ack.min || ackDeadline > ack.max) {
      errors.ackDeadline = `Whole seconds, ${ack.min}-${ack.max}`;
    }
  }

  if (Object.keys(errors).length > 0) return { errors, request: null };
  const request: CreateGcpPullSourceRequest = {
    name: form.name, provider: 'gcp_pubsub', source_slug: slug, gcp: { subscription },
  };
  if (ackDeadline !== null) request.tuning = { ack_deadline_secs: ackDeadline };
  return { errors, request };
}

// --- Azure Event Hubs (NAN-3604). Mirrors the server grammar in shared_pull_sources.rs. ---

export const AZURE_EH_SUFFIX = '.servicebus.windows.net';
export const AZURE_DEFAULT_CONSUMER_GROUP = '$Default';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const AZURE_NAMESPACE = /^[a-z][a-z0-9-]{4,48}[a-z0-9]$/;
const AZURE_ENTITY = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const STORAGE_ACCOUNT = /^[a-z0-9]{3,24}$/;
const BLOB_CONTAINER = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}$/;

function uuidProblem(value: string): string | null {
  if (!value) return 'Required';
  if (!UUID.test(value)) return 'Expected a GUID, e.g. 00000000-0000-0000-0000-000000000000';
  if (value === NIL_UUID) return 'Must not be the nil GUID';
  return null;
}

/**
 * The namespace short name the user meant: trimmed, lowercased, with a pasted
 * `.servicebus.windows.net` FQDN or `sb://` scheme reduced to the short name.
 */
export function normalizeAzureNamespace(value: string): string {
  let ns = value.trim().toLowerCase();
  if (ns.startsWith('sb://')) ns = ns.slice(5);
  if (ns.endsWith('/')) ns = ns.slice(0, -1);
  if (ns.endsWith(AZURE_EH_SUFFIX)) ns = ns.slice(0, -AZURE_EH_SUFFIX.length);
  return ns;
}

export function azureNamespaceProblem(ns: string): string | null {
  if (!ns) return 'Required';
  if (!AZURE_NAMESPACE.test(ns)) return '6-50 lowercase letters, digits or hyphens; letter first, letter or digit last';
  return null;
}

/** `<ns>.servicebus.windows.net` for a valid short name, else null. */
export function azureNamespaceHost(value: string): string | null {
  const ns = normalizeAzureNamespace(value);
  return azureNamespaceProblem(ns) ? null : `${ns}${AZURE_EH_SUFFIX}`;
}

/** `https://<account>.blob.core.windows.net/<container>` once the account name is valid, else null. */
export function azureBlobUrl(account: string, container: string): string | null {
  const a = account.trim();
  return STORAGE_ACCOUNT.test(a) ? `https://${a}.blob.core.windows.net/${container.trim() || '<container>'}` : null;
}

function eventHubProblem(name: string): string | null {
  if (!name) return 'Required';
  if (name.length > 256 || !AZURE_ENTITY.test(name)) {
    return 'Up to 256 letters, digits, . _ -; starting and ending with a letter or digit';
  }
  return null;
}

function consumerGroupProblem(name: string): string | null {
  if (name === AZURE_DEFAULT_CONSUMER_GROUP) return null;
  if (name.length > 50 || !AZURE_ENTITY.test(name)) {
    return `$Default, or up to 50 letters, digits, . _ -; starting and ending with a letter or digit`;
  }
  return null;
}

function storageAccountProblem(name: string): string | null {
  if (!name) return 'Required';
  if (!STORAGE_ACCOUNT.test(name)) return '3-24 lowercase letters and digits';
  return null;
}

function containerProblem(name: string): string | null {
  if (!name) return 'Required';
  if (!BLOB_CONTAINER.test(name)) {
    return '3-63 lowercase letters, digits and single hyphens; starting and ending with a letter or digit';
  }
  return null;
}

export interface AzurePullForm {
  name: string;
  sourceSlug: string;
  directoryId: string;
  clientId: string;
  subscriptionId: string;
  namespace: string;
  eventHub: string;
  /** Empty = `$Default`. */
  consumerGroup: string;
  checkpointAccount: string;
  checkpointContainer: string;
}

export type AzurePullField = keyof AzurePullForm;

export const EMPTY_AZURE_PULL_FORM: AzurePullForm = {
  name: '', sourceSlug: '', directoryId: '', clientId: '', subscriptionId: '', namespace: '', eventHub: '',
  consumerGroup: '', checkpointAccount: '', checkpointContainer: '',
};

export function validateAzurePullForm(form: AzurePullForm): {
  errors: Partial<Record<AzurePullField, string>>;
  request: CreateAzurePullSourceRequest | null;
} {
  const errors: Partial<Record<AzurePullField, string>> = {};
  const slug = form.sourceSlug.trim();
  const directoryId = form.directoryId.trim().toLowerCase();
  const clientId = form.clientId.trim().toLowerCase();
  const subscriptionId = form.subscriptionId.trim().toLowerCase();
  const namespace = normalizeAzureNamespace(form.namespace);
  const eventHub = form.eventHub.trim();
  const consumerGroup = form.consumerGroup.trim();
  const checkpointAccount = form.checkpointAccount.trim();
  const checkpointContainer = form.checkpointContainer.trim();

  const check = (field: AzurePullField, problem: string | null) => { if (problem) errors[field] = problem; };
  check('name', nameProblem(form.name));
  check('sourceSlug', slugProblem(slug));
  check('directoryId', uuidProblem(directoryId));
  check('clientId', uuidProblem(clientId));
  check('subscriptionId', uuidProblem(subscriptionId));
  check('namespace', azureNamespaceProblem(namespace));
  check('eventHub', eventHubProblem(eventHub));
  if (consumerGroup) check('consumerGroup', consumerGroupProblem(consumerGroup));
  check('checkpointAccount', storageAccountProblem(checkpointAccount));
  check('checkpointContainer', containerProblem(checkpointContainer));

  if (Object.keys(errors).length > 0) return { errors, request: null };
  const azure: CreateAzurePullSourceRequest['azure'] = {
    directory_id: directoryId,
    client_id: clientId,
    subscription_id: subscriptionId,
    namespace,
    event_hub: eventHub,
    checkpoint_account: checkpointAccount,
    checkpoint_container: checkpointContainer,
  };
  if (consumerGroup) azure.consumer_group = consumerGroup;
  return { errors, request: { name: form.name, provider: 'azure_event_hubs', source_slug: slug, azure } };
}

/** Server field (`azure.<x>` in a 400 message) → form field. */
const AZURE_SERVER_FIELD: Record<string, AzurePullField> = {
  'azure.directory_id': 'directoryId',
  'azure.client_id': 'clientId',
  'azure.subscription_id': 'subscriptionId',
  'azure.namespace': 'namespace',
  'azure.event_hub': 'eventHub',
  'azure.consumer_group': 'consumerGroup',
  'azure.checkpoint_account': 'checkpointAccount',
  'azure.checkpoint_container': 'checkpointContainer',
  name: 'name',
  source_slug: 'sourceSlug',
};

/**
 * A refused Azure create, as something to show. Deny-list refusals read the
 * same for any tenant or subscription: the text never says whose it is.
 */
export function azureCreateError(error: { message?: string; code?: string; status?: number } | null | undefined): {
  field?: AzurePullField;
  message: string;
} | null {
  if (!error) return null;
  const text = `${error.code ?? ''} ${error.message ?? ''}`;
  if (/\btarget_tenant_denied\b/.test(text)) {
    return { field: 'directoryId', message: "This Azure tenant can't be used for cloud pull. Use the directory that owns your Event Hubs namespace." };
  }
  if (/\btarget_subscription_denied\b/.test(text)) {
    return { field: 'subscriptionId', message: "This Azure subscription can't be used for cloud pull. Use the subscription that holds your Event Hubs namespace." };
  }
  if (/\bprovider_not_supported\b/.test(text)) {
    return { message: 'Azure Event Hubs pull is not available on this deployment yet.' };
  }
  if (/\bpull_source_limit_reached\b/.test(text)) {
    return { message: 'This tenant has reached its cloud pull source limit. Delete a source to add another.' };
  }
  const m = /invalid pull source ([a-z_.]+): (.+)$/.exec(error.message ?? '');
  if (m && AZURE_SERVER_FIELD[m[1]]) return { field: AZURE_SERVER_FIELD[m[1]], message: m[2] };
  return { message: error.message || 'Could not add the source' };
}

/**
 * Probe failure codes (NAN-3604 broker) → what the tenant should fix. The row's
 * `last_error` is shown as is; this adds the next step when it names a code.
 */
const AZURE_PROBE_HINTS: [RegExp, string][] = [
  [/\bazure_token_mismatch\b/, 'The token Entra issued does not match this directory or app. Check the directory and client IDs.'],
  [/\bsubscription_tenant_mismatch\b/, 'The subscription belongs to a different directory than the one given.'],
  [/\btarget_(tenant|subscription)_denied\b/, "This Azure tenant or subscription can't be used for cloud pull."],
  [/\bazure_denied\b/, 'Entra refused the sign-in. Check the federated credential (issuer, subject, audience) on the app registration.'],
  [/\bazure_rejected\b/, 'Entra rejected the app configuration. Check the app registration and its federated credential.'],
  [/\bcheckpoint_access_denied\b/, 'Grant Storage Blob Data Contributor on the checkpoint container to the app.'],
  [/\bcheckpoint_container_not_found\b/, 'The checkpoint container does not exist in that storage account.'],
  [/\bevent_hub_[a-z_]+\b/, 'Check the event hub name and the Azure Event Hubs Data Receiver role on it.'],
];

export function azureProbeHint(lastError: string | null | undefined): string | null {
  if (!lastError) return null;
  for (const [re, hint] of AZURE_PROBE_HINTS) if (re.test(lastError)) return hint;
  return null;
}

/** Only an AWS console quick-create link is rendered as "Launch stack". */
export function safeQuickCreateUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    const host = u.hostname;
    return u.protocol === 'https:' && (host === 'console.aws.amazon.com' || host.endsWith('.console.aws.amazon.com'))
      ? u.toString()
      : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// NAN-3729: in-place credential rotation
// ---------------------------------------------------------------------------

/** Providers whose credential the tenant can rotate in place (GCP's identity is nano's per-tenant service account). */
export function pullCredentialEditable(source: Pick<PullSource, 'provider'>): boolean {
  return source.provider === 'aws_s3_sqs' || source.provider === 'aws_sqs' || source.provider === 'azure_event_hubs';
}

/** The states an edited source walks through before it pulls again (labels as STATE_LABEL). */
export const PULL_REVERIFY_STEPS: readonly PullSourceState[] = ['pending_verification', 'pending_bundle', 'active'];

export type PullCredentialField = 'roleArn' | 'directoryId' | 'clientId';
export type PullCredentialForm = Record<PullCredentialField, string>;

export function pullCredentialFormOf(source: PullSource): PullCredentialForm {
  return {
    roleArn: source.aws?.role_arn ?? '',
    directoryId: source.azure?.directory_id ?? '',
    clientId: source.azure?.client_id ?? '',
  };
}

/**
 * NAN-3729: the PATCH body for a credential edit, or field errors. `changed`
 * is false when the form still holds the current credential (the API treats
 * that as a no-op, so the UI does not send it).
 */
export function validatePullCredentialForm(source: PullSource, form: PullCredentialForm): {
  errors: Partial<Record<PullCredentialField, string>>;
  request: UpdatePullSourceRequest | null;
  changed: boolean;
} {
  const errors: Partial<Record<PullCredentialField, string>> = {};
  if (source.aws) {
    const roleArn = form.roleArn.trim();
    const role = roleArn ? parseRoleArn(roleArn) : null;
    if (!roleArn) errors.roleArn = 'Required';
    else if (!role) errors.roleArn = 'Expected arn:aws:iam::<12-digit account>:role/<name>';
    else if (role.account !== source.aws.account_id) errors.roleArn = `The role must be in the queue's account (${source.aws.account_id})`;
    const changed = roleArn !== source.aws.role_arn;
    return { errors, changed, request: Object.keys(errors).length === 0 && changed ? { aws: { role_arn: roleArn } } : null };
  }
  if (source.azure) {
    const directoryId = form.directoryId.trim().toLowerCase();
    const clientId = form.clientId.trim().toLowerCase();
    const directoryProblem = uuidProblem(directoryId);
    const clientProblem = uuidProblem(clientId);
    if (directoryProblem) errors.directoryId = directoryProblem;
    if (clientProblem) errors.clientId = clientProblem;
    const azure: { directory_id?: string; client_id?: string } = {};
    if (directoryId !== source.azure.directory_id.toLowerCase()) azure.directory_id = directoryId;
    if (clientId !== source.azure.client_id.toLowerCase()) azure.client_id = clientId;
    const changed = Object.keys(azure).length > 0;
    return { errors, changed, request: Object.keys(errors).length === 0 && changed ? { azure } : null };
  }
  return { errors, changed: false, request: null };
}
