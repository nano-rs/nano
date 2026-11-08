import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DetectionsApi } from './detections';

describe('DetectionsApi guarded lifecycle requests', () => {
  const request = vi.fn();
  const api = new DetectionsApi(request);

  beforeEach(() => {
    request.mockReset().mockResolvedValue({ id: 'rule_one' });
  });

  it.each(['staging', 'live'] as const)(
    'carries expected_mode when promoting from %s',
    async (expectedMode) => {
      await api.promoteDetection('rule_one', expectedMode);
      expect(request).toHaveBeenCalledWith('/api/rules/rule_one/promote', {
        method: 'POST',
        body: JSON.stringify({ expected_mode: expectedMode }),
      });
    },
  );

  it('carries expected_mode when demoting', async () => {
    await api.demoteDetection('rule_one', 'alerting');
    expect(request).toHaveBeenCalledWith('/api/rules/rule_one/demote', {
      method: 'POST',
      body: JSON.stringify({ expected_mode: 'alerting' }),
    });
  });

  it.each([
    ['pauseDetection', 'pause', 'live'],
    ['resumeDetection', 'resume', 'paused'],
  ] as const)('carries expected_mode for guarded %s requests', async (method, path, expectedMode) => {
    await api[method]('rule_one', expectedMode);
    expect(request).toHaveBeenCalledWith(`/api/rules/rule_one/${path}`, {
      method: 'POST',
      body: JSON.stringify({ expected_mode: expectedMode }),
    });
  });
});
