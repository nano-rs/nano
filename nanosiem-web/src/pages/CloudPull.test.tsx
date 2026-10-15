// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3596 / NAN-3598 / NAN-3604: Log Sources → Cloud pull (AWS + GCP + Azure setup, add forms, sources table). */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PullSource } from '@/lib/api/pull-sources';
import { CloudPull } from './CloudPull';

const mocks = vi.hoisted(() => {
  class ApiClientError extends Error {
    constructor(message: string, public code: string, public details?: unknown, public status?: number) {
      super(message);
      this.name = 'ApiClientError';
    }
  }
  return {
    ApiClientError,
    toast: vi.fn(),
    list: vi.fn(),
    setup: vi.fn(),
    gcpSetup: vi.fn(),
    azureSetup: vi.fn(),
    create: vi.fn(),
    pause: vi.fn(),
    resume: vi.fn(),
    retry: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    endpoint: vi.fn(),
    logSources: vi.fn(),
    // null = every permission granted; a Set limits hasPermission to its members.
    perms: { granted: null as Set<string> | null },
    inputSummary: vi.fn(),
  };
});

vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => true }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'u', active_tenant: { id: 't' } },
    tenantRuntime: { key: 't:u' },
    hasPermission: (p: string) => mocks.perms.granted?.has(p) ?? true,
    hasAllPermissions: () => true,
  }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: mocks.ApiClientError,
  api: {
    pullSources: {
      list: mocks.list, getAwsSetup: mocks.setup, getGcpSetup: mocks.gcpSetup, getAzureSetup: mocks.azureSetup, create: mocks.create,
      pause: mocks.pause, resume: mocks.resume, retry: mocks.retry, update: mocks.update, remove: mocks.remove,
    },
    getIngestEndpoint: mocks.endpoint,
    listLogSources: mocks.logSources,
    pipelines: { inputSummary: mocks.inputSummary },
  },
}));

const SETUP = {
  nano_principal_arn: 'arn:aws:iam::000000000000:role/nano-pull-broker',
  // Real format (core derive_aws_external_id / broker pinned vector): `nano1-` + 32 lowercase base32 chars.
  external_id: 'nano1-wysiubznfu2o34kle4oiqc3sgosiedom',
  external_id_version: 1,
  trust_policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole' }] },
  permission_policy_template: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['sqs:ReceiveMessage'] }] },
  source_identity: 'nano-00000000-0000-4000-8000-000000000001',
  cloudformation_template: { AWSTemplateFormatVersion: '2010-09-09', Resources: {} },
  supported_regions: ['us-east-1'],
  quick_create_url: 'https://us-east-1.console.aws.amazon.com/cloudformation/home#/stacks/quickcreate',
};

const SA = 'nano-t-0123456789abcdef012345@nano-pull-prod.iam.gserviceaccount.com';
const GCP_SETUP = {
  service_account: SA,
  member: `serviceAccount:${SA}`,
  role: 'roles/pubsub.subscriber',
  binding_level: 'subscription',
  subscription_format: 'projects/<PROJECT_ID>/subscriptions/<SUBSCRIPTION_ID>',
  subscription: null,
  gcloud_command: `gcloud pubsub subscriptions add-iam-policy-binding <SUBSCRIPTION_ID> --project <PROJECT_ID> --member=serviceAccount:${SA} --role=roles/pubsub.subscriber`,
  verify_command: 'gcloud pubsub subscriptions get-iam-policy <SUBSCRIPTION_ID> --project <PROJECT_ID> --format=json',
  ack_deadline_secs: { min: 10, max: 600 },
};
const filledGcpSetup = (sub: string) => {
  const [, project, , name] = sub.split('/');
  const fill = (cmd: string) => cmd.replace('<SUBSCRIPTION_ID>', name).replace('<PROJECT_ID>', project);
  return { ...GCP_SETUP, subscription: sub, gcloud_command: fill(GCP_SETUP.gcloud_command), verify_command: fill(GCP_SETUP.verify_command) };
};

const AZURE_SUBJECT = 'nano-pull:azure:00000000-0000-4000-8000-000000000001';
const EH_SCOPE = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.EventHub/namespaces/<NAMESPACE>/eventhubs/<EVENT_HUB>';
const CK_SCOPE = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<STORAGE_RESOURCE_GROUP>/providers/Microsoft.Storage/storageAccounts/<CHECKPOINT_ACCOUNT>/blobServices/default/containers/<CHECKPOINT_CONTAINER>';
// Shape of the enterprise crate `AzurePullSetup` (NAN-3604 core lane).
const AZURE_SETUP = {
  issuer: 'https://pull-broker.nano.rs',
  subject: AZURE_SUBJECT,
  audience: 'api://AzureADTokenExchange',
  federated_credential_name: 'nano-pull',
  app_permissions: [
    { role: 'Azure Event Hubs Data Receiver', scope: 'event_hub', scope_template: EH_SCOPE },
    { role: 'Storage Blob Data Contributor', scope: 'checkpoint_container', scope_template: CK_SCOPE },
  ],
  commands: {
    app_registration: 'az ad app create --display-name nano-pull --sign-in-audience AzureADMyOrg --query appId --output tsv',
    service_principal: 'az ad sp create --id <APP_CLIENT_ID>',
    federated_credential: `az ad app federated-credential create --id <APP_CLIENT_ID> --parameters '{"name":"nano-pull","issuer":"https://pull-broker.nano.rs","subject":"${AZURE_SUBJECT}","audiences":["api://AzureADTokenExchange"]}'`,
    role_event_hub: `az role assignment create --assignee <APP_CLIENT_ID> --role "Azure Event Hubs Data Receiver" --scope ${EH_SCOPE}`,
    checkpoint_container: 'az storage container create --account-name <CHECKPOINT_ACCOUNT> --name <CHECKPOINT_CONTAINER> --auth-mode login',
    role_checkpoint: `az role assignment create --assignee <APP_CLIENT_ID> --role "Storage Blob Data Contributor" --scope ${CK_SCOPE}`,
    consumer_group: 'az eventhubs eventhub consumer-group create --resource-group <RESOURCE_GROUP> --namespace-name <NAMESPACE> --eventhub-name <EVENT_HUB> --name nano',
    diagnostic_settings_hint: 'Send logs to the Event Hub with a diagnostic setting. Azure Monitor delivers each message as a {"records": [...]} envelope; nano unpacks it.',
  },
  deny: { tenants: ['e6800ccd-d972-42ce-b555-dbf0a25ed9a7'], subscriptions: ['9938c5c9-196d-4cbc-a45e-ab8030503f7c'] },
  endpoints: { event_hubs: '<NAMESPACE>.servicebus.windows.net:5671', checkpoint_blob: '<CHECKPOINT_ACCOUNT>.blob.core.windows.net:443' },
  default_consumer_group: '$Default',
};
const G1 = '11111111-2222-4333-8444-555555555555';
const G2 = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const G3 = '0f0f0f0f-1e1e-4d2d-9c3c-4b4b4b4b4b4b';

function source(id: string, state: PullSource['state'], extra: Partial<PullSource> = {}): PullSource {
  return {
    id, name: `src-${id}`, provider: 'aws_sqs', source_slug: 'aws_cloudtrail', state, revision: 1,
    created_at: '2026-10-11T12:00:00Z', updated_at: '2026-10-11T12:00:00Z',
    aws: { region: 'us-east-1', account_id: '210987654321', role_arn: 'arn:aws:iam::210987654321:role/r', queue_arn: `arn:aws:sqs:us-east-1:210987654321:${id}` },
    ...extra,
  };
}

const writeText = vi.fn(async () => {});
beforeAll(() => {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  Element.prototype.scrollIntoView ??= () => {};
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.perms.granted = null;
  mocks.list.mockResolvedValue([]);
  mocks.setup.mockResolvedValue(SETUP);
  mocks.azureSetup.mockResolvedValue(AZURE_SETUP);
  mocks.gcpSetup.mockImplementation(async (sub?: string) => (sub ? filledGcpSetup(sub) : GCP_SETUP));
  // Lanes unavailable → the form falls back to a slug text field.
  mocks.endpoint.mockRejectedValue(new Error('offline'));
  mocks.logSources.mockResolvedValue([]);
  mocks.inputSummary.mockResolvedValue({ sources: [] });
  mocks.create.mockImplementation(async (body: { name: string }) => source('new', 'pending_verification', { name: body.name }));
  mocks.pause.mockResolvedValue(source('a', 'paused'));
  mocks.resume.mockResolvedValue(source('p', 'active'));
  mocks.retry.mockResolvedValue(source('f', 'pending_verification'));
  mocks.remove.mockResolvedValue(undefined);
});
afterEach(() => cleanup());

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CloudPull />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const type = (label: string | RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

async function openForm() {
  renderPage();
  await screen.findByTestId('cloud-pull-setup');
  fireEvent.click(screen.getByRole('button', { name: /add source/i }));
  await screen.findByTestId('cloud-pull-form');
  await waitFor(() => expect(mocks.endpoint).toHaveBeenCalled());
}

describe('CloudPull setup', () => {
  it('shows the principal and ExternalId in mono with copy, the policies, and the stack links', async () => {
    renderPage();
    const setup = await screen.findByTestId('cloud-pull-setup');
    const principal = within(setup).getByText(SETUP.nano_principal_arn);
    expect(principal.className).toMatch(/font-mono/);
    // NAN-3597: the principal is nano's IAM role; no user / access-key wording.
    expect(within(setup).getByText('Nano principal (IAM role)')).toBeTruthy();
    expect(within(setup).getByRole('button', { name: 'Copy nano role ARN' })).toBeTruthy();
    expect(setup.textContent ?? '').not.toMatch(/IAM user|access key|:user\//i);
    expect(within(setup).getByText(SETUP.external_id).className).toMatch(/font-mono/);
    expect(SETUP.external_id).toMatch(/^nano1-[a-z2-7]{32}$/);
    expect(screen.getByTestId('cloud-pull-trust-policy').textContent).toContain('"sts:AssumeRole"');
    expect(screen.getByTestId('cloud-pull-permission-policy').textContent).toContain('sqs:ReceiveMessage');
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Copy ExternalId' })); });
    expect(writeText).toHaveBeenCalledWith(SETUP.external_id);
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Copy trust policy' })); });
    expect(writeText).toHaveBeenLastCalledWith(JSON.stringify(SETUP.trust_policy, null, 2));
    // The API returns the CloudFormation template as a JSON object: it downloads as pretty JSON.
    const blobs: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => { blobs.push(blob); return 'blob:cfn'; });
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    fireEvent.click(screen.getByRole('button', { name: /download cloudformation template/i }));
    expect(blobs).toHaveLength(1);
    expect(blobs[0].type).toBe('application/json');
    expect(JSON.parse(await blobs[0].text())).toEqual(SETUP.cloudformation_template);
    click.mockRestore();
    const launch = screen.getByRole('link', { name: /launch stack/i });
    expect(launch.getAttribute('href')).toBe(SETUP.quick_create_url);
    expect(launch.getAttribute('rel')).toContain('noopener');
    expect(screen.getByText(/dead-letter queue/i)).toBeTruthy();
    expect(screen.getByText(/RawMessageDelivery/)).toBeTruthy();
  });

  it('hides Launch stack for a non-console URL', async () => {
    mocks.setup.mockResolvedValue({ ...SETUP, quick_create_url: 'https://evil.test/' });
    renderPage();
    await screen.findByTestId('cloud-pull-setup');
    expect(screen.queryByRole('link', { name: /launch stack/i })).toBeNull();
  });

  it('renders a quiet not-enabled state, not an error', async () => {
    mocks.list.mockRejectedValue(new mocks.ApiClientError('not enabled', 'pull_sources_not_enabled', undefined, 409));
    renderPage();
    expect(await screen.findByTestId('cloud-pull-not-enabled')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByRole('button', { name: /add source/i })).toBeNull();
    expect(mocks.setup).not.toHaveBeenCalled();
    expect(mocks.toast).not.toHaveBeenCalled();
  });

  it('keeps the list when setup is unavailable (503)', async () => {
    mocks.list.mockResolvedValue([source('a', 'active')]);
    mocks.setup.mockRejectedValue(new mocks.ApiClientError('unavailable', 'pull_setup_unavailable', undefined, 503));
    renderPage();
    await screen.findByTestId('pull-row-a');
    fireEvent.click(screen.getByRole('button', { name: /aws setup/i }));
    expect(await screen.findByText(/setup details are unavailable right now/i)).toBeTruthy();
  });
});

describe('CloudPull add form', () => {
  it('shows field errors, including a queue in another account, and does not POST', async () => {
    await openForm();
    type('Name', 'trail');
    type('Lane', 'aws_cloudtrail');
    type('Role ARN', 'arn:aws:iam::210987654321:role/nano-pull');
    type('Queue ARN', 'arn:aws:sqs:us-east-1:234567890123:trail');
    type('Bucket (optional)', 'Bad_Bucket');
    fireEvent.click(within(screen.getByTestId('cloud-pull-form')).getByRole('button', { name: 'Add source' }));
    expect(await screen.findByText('Queue account 234567890123 must match the role account 210987654321')).toBeTruthy();
    expect(screen.getByText(/lowercase letters, digits, dots and hyphens/i)).toBeTruthy();
    type('Role ARN', 'arn:aws:iam::210987654321:user/x');
    expect(await screen.findByText(/expected arn:aws:iam::/i)).toBeTruthy();
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('fills the region from the queue and POSTs exactly the allowed fields', async () => {
    await openForm();
    expect(within(screen.getByTestId('cloud-pull-form')).queryByLabelText(/external|endpoint|key/i)).toBeNull();
    type('Name', 'prod trail');
    type('Lane', 'aws_cloudtrail');
    type('Role ARN', 'arn:aws:iam::210987654321:role/nano-pull');
    type('Queue ARN', 'arn:aws:sqs:eu-west-1:210987654321:trail');
    expect(screen.getByLabelText('Region').textContent).toContain('eu-west-1');
    type('Bucket (optional)', 'org-trail');
    type('Prefix (optional)', 'AWSLogs/');
    expect(screen.getByTestId('cloud-pull-provider').textContent).toBe('provider aws_s3_sqs');
    fireEvent.click(within(screen.getByTestId('cloud-pull-form')).getByRole('button', { name: 'Add source' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1));
    expect(mocks.create.mock.calls[0][0]).toStrictEqual({
      name: 'prod trail', provider: 'aws_s3_sqs', source_slug: 'aws_cloudtrail',
      aws: {
        region: 'eu-west-1', role_arn: 'arn:aws:iam::210987654321:role/nano-pull',
        queue_arn: 'arn:aws:sqs:eu-west-1:210987654321:trail', bucket: 'org-trail', prefix: 'AWSLogs/',
      },
    });
    await waitFor(() => expect(screen.queryByTestId('cloud-pull-form')).toBeNull());
  });

  it('shows the server message inline when create is refused', async () => {
    mocks.create.mockRejectedValue(new mocks.ApiClientError('a source with this name exists', 'conflict', undefined, 409));
    await openForm();
    type('Name', 'dup');
    type('Lane', 'aws_cloudtrail');
    type('Role ARN', 'arn:aws:iam::210987654321:role/nano-pull');
    type('Queue ARN', 'arn:aws:sqs:us-east-1:210987654321:trail');
    fireEvent.click(within(screen.getByTestId('cloud-pull-form')).getByRole('button', { name: 'Add source' }));
    expect((await screen.findByTestId('cloud-pull-server-error')).textContent).toBe('a source with this name exists');
  });

  it('offers enrolled lanes as a select when the endpoint lists them', async () => {
    mocks.endpoint.mockResolvedValue({
      sources: [{ label: 'route template: aws_cloudtrail', route_state: 'active', protocol: 'hec', source_slug: 'aws_cloudtrail' }],
    });
    await openForm();
    await waitFor(() => expect(screen.getByLabelText('Lane').getAttribute('role')).toBe('combobox'));
  });
});

describe('CloudPull sources table', () => {
  it('labels every state and shows the last error and verified time', async () => {
    mocks.list.mockResolvedValue([
      source('v', 'pending_verification'),
      source('d', 'pending_bundle'),
      source('a', 'active', { verified_at: '2026-10-11T12:00:00Z' }),
      source('p', 'paused'),
      source('f', 'failed', { last_error: 'AccessDenied: sts:AssumeRole' }),
    ]);
    renderPage();
    await screen.findByTestId('pull-row-a');
    const label = (id: string) => within(screen.getByTestId(`pull-row-${id}`)).getByTestId('pull-state').textContent;
    expect([label('v'), label('d'), label('a'), label('p'), label('f')]).toEqual(['verifying', 'deploying', 'active', 'paused', 'failed']);
    expect(within(screen.getByTestId('pull-row-f')).getByTestId('pull-last-error').firstChild?.textContent).toBe('AccessDenied: sts:AssumeRole');
    // NAN-3661: AWS errors get an actionable hint too, not only Azure.
    expect(within(screen.getByTestId('pull-row-f')).getByTestId('pull-error-hint').textContent).toMatch(/trust policy.*ExternalId/);
    expect(within(screen.getByTestId('pull-row-a')).getByTitle('Oct 11, 2026, 12:00:00 UTC')).toBeTruthy();
    expect(within(screen.getByTestId('pull-row-v')).getByText('never')).toBeTruthy();
    // Setup collapses once sources exist.
    expect(screen.queryByTestId('cloud-pull-setup')).toBeNull();
  });

  it('pauses, resumes and deletes (delete behind a confirm)', async () => {
    mocks.list.mockResolvedValue([source('a', 'active'), source('p', 'paused')]);
    renderPage();
    await screen.findByTestId('pull-row-a');
    fireEvent.click(screen.getByRole('button', { name: 'Pause src-a' }));
    await waitFor(() => expect(mocks.pause).toHaveBeenCalledWith('a'));
    fireEvent.click(screen.getByRole('button', { name: 'Resume src-p' }));
    await waitFor(() => expect(mocks.resume).toHaveBeenCalledWith('p'));
    fireEvent.click(screen.getByRole('button', { name: 'Delete src-a' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(mocks.remove).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(mocks.remove).toHaveBeenCalledWith('a'));
  });

  it('offers Retry verification on failed rows only, calls retry and refreshes the list (NAN-3618)', async () => {
    mocks.list
      .mockResolvedValueOnce([
        source('v', 'pending_verification'),
        source('d', 'pending_bundle'),
        source('a', 'active'),
        source('p', 'paused'),
        source('f', 'failed', { last_error: 'AccessDenied: sts:AssumeRole' }),
      ])
      .mockResolvedValue([source('f', 'pending_verification')]);
    renderPage();
    await screen.findByTestId('pull-row-f');
    for (const id of ['v', 'd', 'a', 'p']) {
      expect(within(screen.getByTestId(`pull-row-${id}`)).queryByRole('button', { name: /Retry verification/ })).toBeNull();
    }
    const failed = screen.getByTestId('pull-row-f');
    // A failed row cannot be paused (the API answers 409); retry replaces it.
    expect(within(failed).queryByRole('button', { name: 'Pause src-f' })).toBeNull();
    expect(within(failed).getByTestId('pull-last-error').firstChild?.textContent).toBe('AccessDenied: sts:AssumeRole');
    expect(mocks.list).toHaveBeenCalledTimes(1);
    fireEvent.click(within(failed).getByRole('button', { name: 'Retry verification for src-f' }));
    await waitFor(() => expect(mocks.retry).toHaveBeenCalledWith('f'));
    expect(mocks.pause).not.toHaveBeenCalled();
    // The list query is invalidated and refetched: the row leaves `failed`.
    await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(within(screen.getByTestId('pull-row-f')).getByTestId('pull-state').textContent).toBe('verifying'));
    expect(screen.queryByRole('button', { name: /Retry verification/ })).toBeNull();
  });

  // NAN-3618: only the actions the API accepts for each state (transition SQL:
  // pause ← active|pending_verification|pending_bundle, resume ← paused, retry ← failed).
  it.each([
    ['active', ['Pause', 'Rotate credential', 'Delete']],
    ['pending_verification', ['Pause', 'Rotate credential', 'Delete']],
    ['pending_bundle', ['Pause', 'Rotate credential', 'Delete']],
    ['paused', ['Resume', 'Rotate credential', 'Delete']],
    ['failed', ['Retry verification', 'Rotate credential', 'Delete']],
  ] as const)('action matrix: %s → %j', async (state, expected) => {
    mocks.list.mockResolvedValue([source('x', state)]);
    renderPage();
    const row = await screen.findByTestId('pull-row-x');
    const labels = within(row).queryAllByRole('button').map((b) => b.textContent?.trim());
    expect(labels).toEqual([...expected]);
  });

  // NAN-3629: pause / resume / retry follow the server's log_sources:edit, not deploy.
  it.each([
    ['edit only', ['log_sources:view', 'log_sources:edit'],
      ['Pause', 'Rotate credential', 'Resume', 'Rotate credential', 'Retry verification', 'Rotate credential']],
    ['deploy only', ['log_sources:view', 'log_sources:deploy'], []],
  ] as const)('row actions with %s', async (_label, granted, expected) => {
    mocks.perms.granted = new Set(granted);
    mocks.list.mockResolvedValue([source('a', 'active'), source('p', 'paused'), source('f', 'failed')]);
    renderPage();
    await screen.findByTestId('pull-row-a');
    const labels = ['a', 'p', 'f'].flatMap((id) =>
      within(screen.getByTestId(`pull-row-${id}`)).queryAllByRole('button').map((b) => b.textContent?.trim()));
    expect(labels).toEqual([...expected]);
  });

  it('labels a pending row with a last_error "blocked", clean pending rows keep their label (NAN-3618)', async () => {
    mocks.list.mockResolvedValue([
      source('b', 'pending_bundle', { last_error: 'source_not_enrolled: aws_cloudtrail' }),
      source('v', 'pending_verification', { last_error: 'AccessDenied: sts:AssumeRole' }),
      source('d', 'pending_bundle'),
      source('w', 'pending_verification'),
      source('f', 'failed', { last_error: 'AccessDenied: sts:AssumeRole' }),
    ]);
    renderPage();
    await screen.findByTestId('pull-row-b');
    const label = (id: string) => within(screen.getByTestId(`pull-row-${id}`)).getByTestId('pull-state').textContent;
    expect([label('b'), label('v'), label('d'), label('w'), label('f')]).toEqual(['blocked', 'blocked', 'deploying', 'verifying', 'failed']);
    // The error stays visible as the reason.
    expect(within(screen.getByTestId('pull-row-b')).getByTestId('pull-last-error').firstChild?.textContent).toBe('source_not_enrolled: aws_cloudtrail');
    expect(within(screen.getByTestId('pull-row-b')).getByTestId('pull-error-hint').textContent).toMatch(/not enabled/);
  });

  it('links each lane back to the pipeline that runs it (NAN-3621)', async () => {
    mocks.list.mockResolvedValue([source('a', 'active'), source('o', 'active', { source_slug: 'unmapped_lane' })]);
    mocks.inputSummary.mockResolvedValue({ sources: [
      { log_source_id: 'lsrc_trail', source_slugs: ['aws_cloudtrail'], push: 0, pull: 1, connectors: 0, mixed_processes: false },
    ] });
    renderPage();
    const lane = within(await screen.findByTestId('pull-row-a')).getByTestId('pull-lane');
    const link = await within(lane).findByRole('link', { name: 'aws_cloudtrail' });
    expect(link.getAttribute('href')).toBe('/ingestion/pipelines/lsrc_trail');
    const other = within(screen.getByTestId('pull-row-o')).getByTestId('pull-lane');
    expect(within(other).queryByRole('link')).toBeNull();
    expect(other.textContent).toBe('unmapped_lane');
  });

  it('keeps plain lane labels when the inputs summary is unavailable', async () => {
    mocks.list.mockResolvedValue([source('a', 'active')]);
    mocks.inputSummary.mockRejectedValue(Object.assign(new Error('Not found'), { status: 404 }));
    renderPage();
    const lane = within(await screen.findByTestId('pull-row-a')).getByTestId('pull-lane');
    await waitFor(() => expect(mocks.inputSummary).toHaveBeenCalled());
    expect(within(lane).queryByRole('link')).toBeNull();
  });
});

async function selectGcp() {
  renderPage();
  await screen.findByTestId('cloud-pull-setup');
  fireEvent.click(screen.getByRole('radio', { name: 'GCP Pub/Sub' }));
  return screen.findByTestId('cloud-pull-gcp-setup');
}

describe('CloudPull GCP (NAN-3598)', () => {
  it('toggles to the GCP setup: service account, role on the subscription, commands with copy', async () => {
    const setup = await selectGcp();
    expect(screen.getByRole('radio', { name: 'GCP Pub/Sub' }).getAttribute('aria-checked')).toBe('true');
    expect(screen.queryByTestId('cloud-pull-setup')).toBeNull();
    expect(screen.getByTestId('cloud-pull-provider-label').textContent).toBe('GCP Pub/Sub');
    expect(mocks.gcpSetup).toHaveBeenCalledWith(undefined);
    expect(within(setup).getByText(SA).className).toMatch(/font-mono/);
    for (const el of within(setup).getAllByText('roles/pubsub.subscriber')) expect(el.className).toMatch(/font-mono/);
    expect(within(setup).getByText('on the subscription, not the project')).toBeTruthy();
    expect(within(setup).getByText(GCP_SETUP.subscription_format)).toBeTruthy();
    expect(screen.getByTestId('cloud-pull-gcp-command').textContent).toBe(GCP_SETUP.gcloud_command);
    expect(screen.getByTestId('cloud-pull-gcp-command').className).toMatch(/font-mono/);
    expect(screen.getByTestId('cloud-pull-gcp-verify').textContent).toBe(GCP_SETUP.verify_command);
    for (const name of ['Copy service account', 'Copy role', 'Copy subscription format', 'Copy grant', 'Copy verify']) {
      expect(within(setup).getByRole('button', { name })).toBeTruthy();
    }
    await act(async () => { fireEvent.click(within(setup).getByRole('button', { name: 'Copy service account' })); });
    expect(writeText).toHaveBeenLastCalledWith(SA);
    await act(async () => { fireEvent.click(within(setup).getByRole('button', { name: 'Copy grant' })); });
    expect(writeText).toHaveBeenLastCalledWith(GCP_SETUP.gcloud_command);
    expect(setup.textContent ?? '').not.toMatch(/key file|json key|private key/i);
    // AWS comes back unchanged.
    fireEvent.click(screen.getByRole('radio', { name: 'AWS S3 + SQS' }));
    expect(await screen.findByTestId('cloud-pull-setup')).toBeTruthy();
    expect(screen.getByRole('button', { name: /aws setup/i })).toBeTruthy();
  });

  it('fills the commands for a valid subscription and shows a client error for a bad one', async () => {
    await selectGcp();
    const input = screen.getByLabelText(/fill the commands for a subscription/i);
    fireEvent.change(input, { target: { value: 'projects/acme-logs/subscriptions/nano/extra' } });
    expect(await screen.findByText('Use projects/<project>/subscriptions/<name>')).toBeTruthy();
    fireEvent.change(input, { target: { value: 'projects/acme-logs/subscriptions/nano-audit' } });
    await waitFor(() => expect(mocks.gcpSetup).toHaveBeenCalledWith('projects/acme-logs/subscriptions/nano-audit'));
    await waitFor(() => expect(screen.getByTestId('cloud-pull-gcp-command').textContent)
      .toContain('add-iam-policy-binding nano-audit --project acme-logs'));
    expect(mocks.gcpSetup).not.toHaveBeenCalledWith('projects/acme-logs/subscriptions/nano/extra');
  });

  it('shows the server refusal of a subscription inline and keeps the placeholder commands', async () => {
    mocks.gcpSetup.mockImplementation(async (sub?: string) => {
      if (sub) throw new mocks.ApiClientError('invalid pull source gcp.subscription: project is nano-owned', 'invalid', undefined, 400);
      return GCP_SETUP;
    });
    await selectGcp();
    fireEvent.change(screen.getByLabelText(/fill the commands for a subscription/i), { target: { value: 'projects/nano-pull-prod/subscriptions/x-audit' } });
    expect(await screen.findByText(/project is nano-owned/)).toBeTruthy();
    expect(screen.getByTestId('cloud-pull-gcp-command').textContent).toBe(GCP_SETUP.gcloud_command);
  });

  it('handles 503 setup unavailable and 409 not enabled like AWS', async () => {
    mocks.list.mockResolvedValue([source('a', 'active')]);
    mocks.gcpSetup.mockRejectedValue(new mocks.ApiClientError('unavailable', 'pull_setup_unavailable', undefined, 503));
    renderPage();
    await screen.findByTestId('pull-row-a');
    fireEvent.click(screen.getByRole('radio', { name: 'GCP Pub/Sub' }));
    fireEvent.click(screen.getByRole('button', { name: /gcp setup/i }));
    expect(await screen.findByText(/setup details are unavailable right now/i)).toBeTruthy();
    expect(screen.getByTestId('pull-row-a')).toBeTruthy();
    cleanup();
    mocks.list.mockResolvedValue([]);
    mocks.gcpSetup.mockRejectedValue(new mocks.ApiClientError('not enabled', 'pull_sources_not_enabled', undefined, 409));
    renderPage();
    await screen.findByTestId('cloud-pull-setup');
    fireEvent.click(screen.getByRole('radio', { name: 'GCP Pub/Sub' }));
    expect(await screen.findByTestId('cloud-pull-not-enabled')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /add source/i })).toBeNull();
    // The toggle stays, so the user is never stuck on a refused provider.
    fireEvent.click(screen.getByRole('radio', { name: 'AWS S3 + SQS' }));
    expect(await screen.findByTestId('cloud-pull-setup')).toBeTruthy();
  });

  it('validates the subscription inline and POSTs the exact gcp_pubsub body', async () => {
    await selectGcp();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-gcp-form');
    expect(within(form).queryByLabelText(/key|role arn|queue/i)).toBeNull();
    type('Name', 'org audit');
    type('Lane', 'gcp_audit');
    type('Subscription', 'projects/Acme-Logs/subscriptions/nano-audit');
    type(/ack deadline/i, '5');
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    expect(await screen.findByText(/^Project ID: 6-30 lowercase/)).toBeTruthy();
    expect(screen.getByText('Whole seconds, 10-600')).toBeTruthy();
    type('Subscription', 'nano-audit');
    expect(await screen.findByText('Use projects/<project>/subscriptions/<name>')).toBeTruthy();
    expect(mocks.create).not.toHaveBeenCalled();
    type('Subscription', 'projects/acme-logs/subscriptions/nano-audit');
    type(/ack deadline/i, '120');
    expect(within(form).getByTestId('cloud-pull-provider').textContent).toBe('provider gcp_pubsub');
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1));
    expect(mocks.create.mock.calls[0][0]).toStrictEqual({
      name: 'org audit', provider: 'gcp_pubsub', source_slug: 'gcp_audit',
      gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit' },
      tuning: { ack_deadline_secs: 120 },
    });
    await waitFor(() => expect(screen.queryByTestId('cloud-pull-gcp-form')).toBeNull());
  });

  it('prefills the form subscription from the setup panel', async () => {
    await selectGcp();
    fireEvent.change(screen.getByLabelText(/fill the commands for a subscription/i), { target: { value: 'projects/acme-logs/subscriptions/nano-audit' } });
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    await screen.findByTestId('cloud-pull-gcp-form');
    expect((screen.getByLabelText('Subscription') as HTMLInputElement).value).toBe('projects/acme-logs/subscriptions/nano-audit');
  });

  it('shows GCP rows with the subscription and a provider label beside AWS rows', async () => {
    mocks.list.mockResolvedValue([
      source('a', 'active'),
      source('g', 'failed', {
        provider: 'gcp_pubsub', source_slug: 'gcp_audit', aws: null,
        gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit', service_account: SA },
        last_error: 'PERMISSION_DENIED: pubsub.subscriptions.get',
      }),
    ]);
    renderPage();
    const row = await screen.findByTestId('pull-row-g');
    const target = within(row).getByTestId('pull-target');
    expect(target.textContent).toBe('projects/acme-logs/subscriptions/nano-audit');
    expect(target.className).toMatch(/font-mono/);
    expect(target.getAttribute('title')).toContain(SA);
    expect(within(row).getByText('GCP Pub/Sub')).toBeTruthy();
    expect(within(screen.getByTestId('pull-row-a')).getByTestId('pull-target').textContent).toBe('arn:aws:sqs:us-east-1:210987654321:a');
    fireEvent.click(screen.getByRole('button', { name: 'Delete src-g' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain('projects/acme-logs/subscriptions/nano-audit');
    expect(dialog.textContent).toContain('IAM binding on your subscription is not changed');
  });
});

const routeTemplate = (slug: string) => ({ label: `route template: ${slug}`, route_state: 'active', protocol: 'hec', source_slug: slug });

describe('CloudPull parser lane (NAN-3657 / NAN-3658)', () => {
  it('preselects gcp_audit in the GCP form when that parser is deployed, and POSTs it', async () => {
    mocks.endpoint.mockResolvedValue({ sources: [routeTemplate('aws_cloudtrail'), routeTemplate('gcp_audit')] });
    await selectGcp();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-gcp-form');
    await waitFor(() => expect(within(form).getByLabelText('Lane').textContent).toContain('gcp_audit'));
    expect(within(form).queryByTestId('cloud-pull-gcp-no-default')).toBeNull();
    type('Name', 'org audit');
    type('Subscription', 'projects/acme-logs/subscriptions/nano-audit');
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1));
    expect(mocks.create.mock.calls[0][0]).toStrictEqual({
      name: 'org audit', provider: 'gcp_pubsub', source_slug: 'gcp_audit',
      gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit' },
    });
  });

  it('requires an explicit parser when gcp_audit is not deployed', async () => {
    mocks.endpoint.mockResolvedValue({ sources: [routeTemplate('aws_cloudtrail')] });
    await selectGcp();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-gcp-form');
    expect((await within(form).findByTestId('cloud-pull-gcp-no-default')).textContent).toContain('gcp_audit');
    expect(within(form).getByLabelText('Lane').textContent).not.toContain('gcp_audit');
    type('Name', 'org audit');
    type('Subscription', 'projects/acme-logs/subscriptions/nano-audit');
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    expect(await within(form).findByText('Required')).toBeTruthy();
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('shows the parser each source feeds, slug in mono, and flags one that is not deployed', async () => {
    mocks.endpoint.mockResolvedValue({ sources: [routeTemplate('aws_cloudtrail')] });
    mocks.logSources.mockResolvedValue([
      { id: 'lsrc_trail', name: 'AWS CloudTrail', match_values: ['aws_cloudtrail'], lifecycle_status: 'published', deployed: true },
    ]);
    mocks.list.mockResolvedValue([
      source('a', 'active'),
      source('g', 'failed', {
        provider: 'gcp_pubsub', source_slug: 'gcp_audit', aws: null,
        gcp: { subscription: 'projects/acme-logs/subscriptions/nano-audit', service_account: SA },
        last_error: 'parser lane gcp_audit is not deployed',
      }),
    ]);
    renderPage();
    const header = within(await screen.findByTestId('cloud-pull-table')).getAllByRole('columnheader').map((h) => h.textContent);
    expect(header).toContain('Parser');
    const a = await screen.findByTestId('pull-row-a');
    expect((await within(a).findByTestId('pull-parser-name')).textContent).toBe('AWS CloudTrail');
    const lane = within(a).getByTestId('pull-lane');
    expect(lane.textContent).toBe('aws_cloudtrail');
    expect(lane.className).toMatch(/font-mono/);
    expect(within(a).queryByTestId('pull-parser-missing')).toBeNull();
    const g = screen.getByTestId('pull-row-g');
    expect(within(g).getByTestId('pull-lane').textContent).toBe('gcp_audit');
    const missing = await within(g).findByTestId('pull-parser-missing');
    expect(missing.textContent).toContain('not deployed');
    expect(missing.getAttribute('title')).toContain('No gcp_audit parser is deployed');
  });

  it('does not flag a parser while the tenant lanes are unknown', async () => {
    mocks.list.mockResolvedValue([source('g', 'active', { source_slug: 'gcp_audit' })]);
    renderPage();
    const g = await screen.findByTestId('pull-row-g');
    await waitFor(() => expect(mocks.endpoint).toHaveBeenCalled());
    expect(within(g).getByTestId('pull-lane').textContent).toBe('gcp_audit');
    expect(within(g).queryByTestId('pull-parser-missing')).toBeNull();
  });
});

async function selectAzure() {
  renderPage();
  await screen.findByTestId('cloud-pull-setup');
  fireEvent.click(screen.getByRole('radio', { name: 'Azure Event Hubs' }));
  return screen.findByTestId('cloud-pull-azure-setup');
}

async function fillAzure(form: HTMLElement, patch: Record<string, string> = {}) {
  const values: Record<string, string> = {
    Name: 'entra sign-ins', Lane: 'azure_signin', 'Directory (tenant) ID': G1, 'Application (client) ID': G2,
    'Subscription ID': G3, 'Event Hubs namespace': 'acme-logs', 'Event hub': 'insights-logs-signinlogs',
    'Consumer group (optional)': 'nano', 'Checkpoint storage account': 'acmecheckpoints', 'Checkpoint container': 'nano-checkpoints',
    ...patch,
  };
  for (const [label, value] of Object.entries(values)) {
    fireEvent.change(within(form).getByLabelText(label), { target: { value } });
  }
}

describe('CloudPull Azure (NAN-3604)', () => {
  it('shows the keyless federation steps with issuer / subject / audience in mono and copy buttons', async () => {
    const setup = await selectAzure();
    expect(screen.getByRole('radio', { name: 'Azure Event Hubs' }).getAttribute('aria-checked')).toBe('true');
    expect(screen.getByTestId('cloud-pull-provider-label').textContent).toBe('Azure Event Hubs');
    expect(screen.getByRole('button', { name: /azure setup/i })).toBeTruthy();
    expect(mocks.azureSetup).toHaveBeenCalledTimes(1);
    for (const value of [AZURE_SETUP.issuer, AZURE_SUBJECT, AZURE_SETUP.audience]) {
      expect(within(setup).getByText(value).className).toMatch(/font-mono/);
    }
    for (const name of ['Copy issuer', 'Copy subject', 'Copy audience', 'Copy credential name']) {
      expect(within(setup).getByRole('button', { name })).toBeTruthy();
    }
    await act(async () => { fireEvent.click(within(setup).getByRole('button', { name: 'Copy subject' })); });
    expect(writeText).toHaveBeenLastCalledWith(AZURE_SUBJECT);
    // Five steps, each with its az command.
    for (let n = 1; n <= 5; n++) expect(within(setup).getByTestId(`azure-step-${n}`)).toBeTruthy();
    const commands = AZURE_SETUP.commands as Record<string, string>;
    for (const id of ['app_registration', 'service_principal', 'federated_credential', 'role_event_hub', 'checkpoint_container', 'role_checkpoint', 'consumer_group']) {
      const block = within(setup).getByTestId(`azure-command-${id}`);
      expect(block.textContent).toBe(commands[id]);
      expect(block.className).toMatch(/font-mono/);
    }
    expect(within(setup).getByTestId('azure-command-federated_credential').closest('[data-testid="azure-step-1"]')).toBeTruthy();
    expect(within(setup).getByTestId('azure-command-role_checkpoint').closest('[data-testid="azure-step-3"]')).toBeTruthy();
    expect(within(setup).getByTestId('azure-diagnostic-hint').textContent).toBe(AZURE_SETUP.commands.diagnostic_settings_hint);
    await act(async () => { fireEvent.click(within(setup).getByRole('button', { name: 'Copy event hub role' })); });
    expect(writeText).toHaveBeenLastCalledWith(AZURE_SETUP.commands.role_event_hub);
    expect(within(setup).getByTestId('azure-endpoints').textContent).toContain('<NAMESPACE>.servicebus.windows.net:5671');
    // The deny list is in the response but never on the page.
    expect(setup.textContent).not.toContain(AZURE_SETUP.deny.tenants[0]);
    expect(setup.textContent).not.toContain(AZURE_SETUP.deny.subscriptions[0]);
    const step2 = within(setup).getByTestId('azure-step-2');
    expect(within(step2).getByText('Azure Event Hubs Data Receiver').className).toMatch(/font-mono/);
    const step3 = within(setup).getByTestId('azure-step-3');
    expect(within(step3).getByText('Storage Blob Data Contributor')).toBeTruthy();
    expect(step3.textContent).toMatch(/keep their read position/);
    expect(within(setup).getByTestId('azure-step-5').textContent).toMatch(/SignInLogs.*AuditLogs/);
    // No secret is asked for, and the page says so.
    expect(setup.textContent).toMatch(/No client secret, certificate or SAS key is asked for/);
  });

  it('validates every field inline, shows the derived host, and does not POST', async () => {
    await selectAzure();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-azure-form');
    expect(within(form).queryByLabelText(/secret|connection string|sas|key/i)).toBeNull();
    await fillAzure(form, {
      'Directory (tenant) ID': 'contoso.onmicrosoft.com', 'Event Hubs namespace': 'Acme_Logs',
      'Checkpoint storage account': 'Acme-Checkpoints', 'Checkpoint container': 'nano--ck',
    });
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    expect(await within(form).findByText(/^Expected a GUID/)).toBeTruthy();
    expect(within(form).getByText(/^6-50 lowercase/)).toBeTruthy();
    expect(within(form).getByText('3-24 lowercase letters and digits')).toBeTruthy();
    expect(within(form).getByText(/^3-63 lowercase/)).toBeTruthy();
    expect(within(form).getByLabelText('Directory (tenant) ID').getAttribute('aria-invalid')).toBe('true');
    expect(mocks.create).not.toHaveBeenCalled();
    fireEvent.change(within(form).getByLabelText('Event Hubs namespace'), { target: { value: 'acme-logs.servicebus.windows.net' } });
    expect(within(form).getByTestId('cloud-pull-azure-host').textContent).toBe('acme-logs.servicebus.windows.net');
    expect(within(form).getByTestId('cloud-pull-azure-host').className).toMatch(/font-mono/);
  });

  it('POSTs the exact azure_event_hubs body', async () => {
    await selectAzure();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-azure-form');
    await fillAzure(form, { 'Directory (tenant) ID': G1.toUpperCase(), 'Event Hubs namespace': 'Acme-Logs' });
    expect(within(form).getByTestId('cloud-pull-provider').textContent).toBe('provider azure_event_hubs');
    expect(within(form).getByTestId('cloud-pull-azure-blob').textContent).toBe('https://acmecheckpoints.blob.core.windows.net/nano-checkpoints');
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1));
    expect(mocks.create.mock.calls[0][0]).toStrictEqual({
      name: 'entra sign-ins', provider: 'azure_event_hubs', source_slug: 'azure_signin',
      azure: {
        directory_id: G1, client_id: G2, subscription_id: G3, namespace: 'acme-logs', event_hub: 'insights-logs-signinlogs',
        consumer_group: 'nano', checkpoint_account: 'acmecheckpoints', checkpoint_container: 'nano-checkpoints',
      },
    });
    await waitFor(() => expect(screen.queryByTestId('cloud-pull-azure-form')).toBeNull());
    expect(mocks.toast.mock.calls.at(-1)?.[0].title).toBe('Pull source added');
  });

  it('maps a denied tenant / subscription to generic text on the field', async () => {
    mocks.create.mockRejectedValueOnce(new mocks.ApiClientError('invalid pull source azure.directory_id: target_tenant_denied', 'BAD_REQUEST', undefined, 400));
    await selectAzure();
    fireEvent.click(screen.getByRole('button', { name: /add source/i }));
    const form = await screen.findByTestId('cloud-pull-azure-form');
    await fillAzure(form);
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    const msg = await within(form).findByText(/^This Azure tenant can't be used for cloud pull/);
    expect(msg.id).toBe('cloud-pull-azure-directoryId-error');
    expect(form.textContent).not.toMatch(/target_tenant_denied|nano's|nano-owned/);
    // Editing clears the stale refusal.
    fireEvent.change(within(form).getByLabelText('Directory (tenant) ID'), { target: { value: G3 } });
    await waitFor(() => expect(within(form).queryByText(/can't be used/)).toBeNull());
    mocks.create.mockRejectedValueOnce(new mocks.ApiClientError('invalid pull source azure.subscription_id: target_subscription_denied', 'BAD_REQUEST', undefined, 400));
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    expect((await within(form).findByText(/^This Azure subscription can't be used/)).id).toBe('cloud-pull-azure-subscriptionId-error');
    mocks.create.mockRejectedValueOnce(new mocks.ApiClientError('a source with this name exists', 'conflict', undefined, 409));
    fireEvent.change(within(form).getByLabelText('Subscription ID'), { target: { value: G1 } });
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    expect((await screen.findByTestId('cloud-pull-server-error')).textContent).toBe('a source with this name exists');
  });

  it('shows Azure rows with namespace / hub / consumer group and a next step for probe failures', async () => {
    const azure = (hub: string) => ({
      namespace: 'acme-logs', event_hub: hub, consumer_group: 'nano', directory_id: G1, client_id: G2,
      subscription_id: G3, checkpoint_account: 'acmecheckpoints', checkpoint_container: 'nano-checkpoints',
    });
    mocks.list.mockResolvedValue([
      source('z1', 'pending_verification', { provider: 'azure_event_hubs', source_slug: 'azure_signin', aws: null, azure: azure('signins') }),
      source('z2', 'failed', {
        provider: 'azure_event_hubs', source_slug: 'azure_activity', aws: null, azure: azure('activity'),
        last_error: 'checkpoint_access_denied: the app cannot list acmecheckpoints/nano-checkpoints',
      }),
      source('z3', 'active', { provider: 'azure_event_hubs', source_slug: 'azure_activity', aws: null, azure: azure('audit'), verified_at: '2026-10-11T12:00:00Z' }),
    ]);
    renderPage();
    const failed = await screen.findByTestId('pull-row-z2');
    const target = within(failed).getByTestId('pull-target');
    expect(target.textContent).toBe('acme-logs/activity · nano');
    expect(target.className).toMatch(/font-mono/);
    expect(target.getAttribute('title')).toContain('acme-logs.servicebus.windows.net/activity');
    expect(target.getAttribute('title')).toContain(`app ${G2}`);
    expect(within(failed).getByText('Azure Event Hubs')).toBeTruthy();
    expect(within(failed).getByTestId('pull-last-error').textContent).toContain('checkpoint_access_denied');
    expect(within(failed).getByTestId('pull-error-hint').textContent).toMatch(/Storage Blob Data Contributor/);
    expect(within(screen.getByTestId('pull-row-z1')).getByTestId('pull-state').textContent).toBe('verifying');
    expect(within(screen.getByTestId('pull-row-z3')).getByTestId('pull-state').textContent).toBe('active');
    fireEvent.click(screen.getByRole('button', { name: 'Delete src-z2' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain('acme-logs/activity');
    expect(dialog.textContent).toContain('federated credential and role assignments are not changed');
  });
});

describe('CloudPull credential rotation (NAN-3729)', () => {
  const azure = { namespace: 'acme-logs', event_hub: 'signins', consumer_group: 'nano', directory_id: G1, client_id: G2,
    subscription_id: G3, checkpoint_account: 'acmecheckpoints', checkpoint_container: 'nano-checkpoints' };

  it('rotates an AWS role in place: says it re-verifies, shows the steps, PATCHes only the role', async () => {
    mocks.list
      .mockResolvedValueOnce([source('a', 'active', { verified_at: '2026-10-11T12:00:00Z' })])
      .mockResolvedValue([source('a', 'pending_verification', { revision: 2 })]);
    mocks.update.mockResolvedValue(source('a', 'pending_verification', { revision: 2 }));
    renderPage();
    const row = await screen.findByTestId('pull-row-a');
    fireEvent.click(within(row).getByRole('button', { name: 'Rotate credential for src-a' }));
    const dialog = await screen.findByTestId('cloud-pull-credential-dialog');
    // Prefilled with the current role; nothing changed yet, so save is disabled.
    expect((within(dialog).getByLabelText('Role ARN') as HTMLInputElement).value).toBe('arn:aws:iam::210987654321:role/r');
    expect((within(dialog).getByRole('button', { name: 'Save and re-verify' }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).getByTestId('cloud-pull-reverify-note').textContent).toMatch(/re-verifies this source with the new role/);
    expect(within(dialog).getByTestId('cloud-pull-reverify-steps').textContent).toBe('active→verifying→deploying→active');
    // A role in another account is refused client-side.
    fireEvent.change(within(dialog).getByLabelText('Role ARN'), { target: { value: 'arn:aws:iam::234567890123:role/r2' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save and re-verify' }));
    expect(await within(dialog).findByText(/queue's account \(210987654321\)/)).toBeTruthy();
    expect(mocks.update).not.toHaveBeenCalled();
    fireEvent.change(within(dialog).getByLabelText('Role ARN'), { target: { value: 'arn:aws:iam::210987654321:role/r2' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save and re-verify' }));
    await waitFor(() => expect(mocks.update).toHaveBeenCalledWith('a', { aws: { role_arn: 'arn:aws:iam::210987654321:role/r2' } }));
    expect(mocks.remove).not.toHaveBeenCalled();
    expect(mocks.create).not.toHaveBeenCalled();
    // The row walks back through verification (list refetched).
    await waitFor(() => expect(within(screen.getByTestId('pull-row-a')).getByTestId('pull-state').textContent).toBe('verifying'));
    expect(screen.queryByTestId('cloud-pull-credential-dialog')).toBeNull();
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Re-verifying with the new credential',
      description: expect.stringMatching(/verifying → deploying → active/),
    }));
  });

  it('rotates an Entra app and sends only the changed id; a refusal stays in the dialog', async () => {
    const z = source('z', 'failed', { provider: 'azure_event_hubs', source_slug: 'azure_signin', aws: null, azure, last_error: 'azure_denied: Entra refused' });
    mocks.list.mockResolvedValue([z]);
    mocks.update.mockRejectedValueOnce(new mocks.ApiClientError('invalid pull source azure.directory_id: is a nano tenant', 'bad_request', undefined, 400));
    renderPage();
    const row = await screen.findByTestId('pull-row-z');
    fireEvent.click(within(row).getByRole('button', { name: 'Rotate credential for src-z' }));
    const dialog = await screen.findByTestId('cloud-pull-credential-dialog');
    expect((within(dialog).getByLabelText('Directory (tenant) ID') as HTMLInputElement).value).toBe(G1);
    const next = '44444444-4444-4444-8444-444444444444';
    fireEvent.change(within(dialog).getByLabelText('App (client) ID'), { target: { value: next.toUpperCase() } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save and re-verify' }));
    await waitFor(() => expect(mocks.update).toHaveBeenCalledWith('z', { azure: { client_id: next } }));
    expect((await within(dialog).findByTestId('cloud-pull-credential-error')).textContent).toMatch(/nano tenant/);
    expect(screen.getByTestId('cloud-pull-credential-dialog')).toBeTruthy();
  });

  it('a paused source stays paused and re-verifies on resume', async () => {
    mocks.list.mockResolvedValue([source('p', 'paused')]);
    renderPage();
    fireEvent.click(within(await screen.findByTestId('pull-row-p')).getByRole('button', { name: 'Rotate credential for src-p' }));
    const dialog = await screen.findByTestId('cloud-pull-credential-dialog');
    expect(within(dialog).getByTestId('cloud-pull-reverify-note').textContent).toMatch(/keeps this source paused.*when you resume/);
    expect(within(dialog).queryByTestId('cloud-pull-reverify-steps')).toBeNull();
  });

  it('offers no rotation for GCP rows (nano owns that identity) and points delete at rotation', async () => {
    mocks.list.mockResolvedValue([
      source('g', 'active', { provider: 'gcp_pubsub', source_slug: 'gcp_audit', aws: null, gcp: { subscription: 'projects/p/subscriptions/s', service_account: SA } }),
      source('a', 'active'),
    ]);
    renderPage();
    const gcp = await screen.findByTestId('pull-row-g');
    expect(within(gcp).queryByRole('button', { name: /Rotate credential/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Delete src-a' }));
    const confirm = await screen.findByRole('alertdialog');
    expect(confirm.textContent).toMatch(/use Rotate credential instead.*skipped/);
  });

  it('hides rotation without log_sources:edit', async () => {
    mocks.perms.granted = new Set(['log_sources:view', 'log_sources:delete']);
    mocks.list.mockResolvedValue([source('a', 'active')]);
    renderPage();
    const row = await screen.findByTestId('pull-row-a');
    expect(within(row).queryByRole('button', { name: /Rotate credential/ })).toBeNull();
  });
});
