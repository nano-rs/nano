// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5079: test-vrl asks for OCSF validation; publish and deploy carry the
// OCSF gate's samples / unattested acknowledgement, and an empty gate keeps
// the body exactly as before.
import { describe, expect, it, vi } from 'vitest';
import { LogSourcesApi, ocsfGateBody } from './log-sources';
import { ocsfGateRequest } from '@/components/log-sources/OcsfGate';

function api() {
  const request = vi.fn().mockResolvedValue({});
  const longRequest = vi.fn().mockResolvedValue({ success: true });
  return { request, longRequest, ls: new LogSourcesApi(request, longRequest) };
}

const bodyOf = (call: unknown[]) => {
  const init = call[1] as { body?: string } | undefined;
  return init?.body ? JSON.parse(init.body) : undefined;
};

describe('OCSF gate bodies (NAN-5079)', () => {
  it('drops blank samples and an unset acknowledgement', () => {
    expect(ocsfGateBody(undefined)).toEqual({});
    expect(ocsfGateBody({ ocsfSampleLogs: ['', '  '], acknowledgeUnattested: false })).toEqual({});
    expect(ocsfGateBody({ ocsfSampleLogs: ['a', ' '], acknowledgeUnattested: true })).toEqual({
      ocsf_sample_logs: ['a'],
      acknowledge_unattested: true,
    });
  });

  it('keeps a plain publish and deploy bodiless', async () => {
    const { longRequest, ls } = api();
    await ls.publishLogSource('a');
    await ls.deployLogSource('a');
    expect(bodyOf(longRequest.mock.calls[0])).toBeUndefined();
    expect(bodyOf(longRequest.mock.calls[1])).toBeUndefined();
  });

  it('sends samples with the revision guard on publish, and on deploy', async () => {
    const { longRequest, ls } = api();
    await ls.publishLogSource('a', '2026-11-11T00:00:00Z', { ocsf: { ocsfSampleLogs: ['raw 1'] } });
    await ls.deployLogSource('a', { ocsf: { acknowledgeUnattested: true } });
    expect(bodyOf(longRequest.mock.calls[0])).toEqual({
      expected_updated_at: '2026-11-11T00:00:00Z',
      ocsf_sample_logs: ['raw 1'],
    });
    expect(bodyOf(longRequest.mock.calls[1])).toEqual({ acknowledge_unattested: true });
  });

  it('sends Add data\'s own unattested install as system-initiated, not an acknowledgement', async () => {
    const { longRequest, ls } = api();
    await ls.deployLogSource('a', { ocsf: { unattestedSystemInstall: true } });
    expect(bodyOf(longRequest.mock.calls[0])).toEqual({ unattested_system_install: true });
  });

  it('starts the gated routes as deploy jobs (the gate answers 422 before any job)', async () => {
    const { longRequest, ls } = api();
    await ls.deployLogSource('a', { ocsf: { ocsfSampleLogs: ['raw'] } });
    expect(longRequest.mock.calls[0][0]).toBe('/api/log-sources/a/deploy?wait=false');
  });

  it('asks test-vrl for OCSF validation and binds the source when given', async () => {
    const { request, ls } = api();
    await ls.testLogSourceVrl('. = {}', 'raw', undefined, 'lsrc_1');
    expect(bodyOf(request.mock.calls[0])).toEqual({
      vrl_code: '. = {}',
      sample_log: 'raw',
      validate_ocsf: true,
      log_source_id: 'lsrc_1',
    });
  });

  it('acknowledges an unattested go-live only on a first go-live with no sample', () => {
    const ack = { sample: '', acknowledgeUnattested: true };
    expect(ocsfGateRequest(ack, true)).toEqual({ ocsfSampleLogs: [], acknowledgeUnattested: true });
    expect(ocsfGateRequest(ack, false).acknowledgeUnattested).toBe(false);
    expect(ocsfGateRequest({ sample: 'a\n\n b ', acknowledgeUnattested: true }, true)).toEqual({
      ocsfSampleLogs: ['a', 'b'],
      acknowledgeUnattested: false,
    });
  });
});
