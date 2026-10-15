// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { pipelineDraftRecovery, pipelineDraftRecoveryKey, draftFingerprint, type PipelineDraftRecovery } from './pipeline-model';
import { publicationSnapshot } from './api/pipelines';
import type { PipelineDraft } from './pipeline-types';

const draft: PipelineDraft = { name: 'Firewall', description: '', revision: 4, steps: [{ id: 'vrl', name: 'Edited parser', enabled: true, kind: 'vrl', config: { code: '.edited = true' } }] };
const savedFingerprint = draftFingerprint({ ...draft, revision: 3, steps: [] });
const original = publicationSnapshot({ id: 'lsrc_firewall', updated_at: '2026-10-09T10:00:00Z', parser_vrl: '.saved = true', extension_enabled: true, extension_vrl: '.extension = true' });

test('route recovery preserves unsaved configuration and original CAS without sample payloads', () => {
  const client = new QueryClient();
  const key = pipelineDraftRecoveryKey('tenant-a:user-a:epoch-1', original.sourceId);
  const contaminated = Object.assign({}, draft, { capture: { events: [{ password: 'secret sample' }] }, preview: { outputs: ['secret sample'] } });
  const recovery = pipelineDraftRecovery(contaminated, savedFingerprint, original);
  client.setQueryDefaults(key, { gcTime: Infinity });
  client.setQueryData(key, recovery);
  // A later route mount receives the same user draft and original server baseline.
  const restored = client.getQueryData<PipelineDraftRecovery>(key)!;
  expect(restored.draft.steps[0].config.code).toBe('.edited = true');
  expect(restored.sourceSnapshot.expectedUpdatedAt).toBe('2026-10-09T10:00:00Z');
  expect(restored.savedFingerprint).toBe(savedFingerprint);
  expect(JSON.stringify(restored).includes('secret sample')).toBe(false);
  draft.steps[0].config.code = '.changed_later = true';
  expect(restored.draft.steps[0].config.code).toBe('.edited = true');
  client.clear();
});

test('draft recovery keys isolate users and tenants and clear with the owning runtime', () => {
  const client = new QueryClient();
  const key = pipelineDraftRecoveryKey('tenant-a:user-a:epoch-1', original.sourceId);
  client.setQueryData(key, pipelineDraftRecovery(draft, savedFingerprint, original));
  expect(client.getQueryData(pipelineDraftRecoveryKey('tenant-b:user-a:epoch-2', original.sourceId))).toBe(undefined);
  expect(client.getQueryData(pipelineDraftRecoveryKey('tenant-a:user-b:epoch-2', original.sourceId))).toBe(undefined);
  client.clear();
  expect(client.getQueryData(key)).toBe(undefined);
});
