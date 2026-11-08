// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { authHeader, connectStage, CONNECT_SUMMARY, statusReceiving } from './connect-stage';

describe('connectStage (NAN-4890 order, NAN-4912 dedicated)', () => {
  it('token first, then waiting, then receiving', () => {
    expect(connectStage({ busy: false, failed: false, issued: false, receiving: false })).toBe('none');
    expect(connectStage({ busy: true, failed: false, issued: false, receiving: false })).toBe('pending');
    expect(connectStage({ busy: false, failed: true, issued: false, receiving: false })).toBe('failed');
    expect(connectStage({ busy: false, failed: false, issued: true, receiving: false })).toBe('ready');
    expect(CONNECT_SUMMARY.ready).toBe('waiting for first event');
  });

  it('events already arriving (legacy sender, converted source) read as receiving without a new token', () => {
    expect(connectStage({ busy: false, failed: false, issued: false, receiving: true })).toBe('receiving');
  });

  it('HEC uses the Splunk scheme, everything else Bearer', () => {
    expect(authHeader('hec', 'nit_x')).toBe('Authorization: Splunk nit_x');
    expect(authHeader('http')).toBe('Authorization: Bearer <token>');
    expect(statusReceiving({ events_24h: 2 })).toBe(true);
    expect(statusReceiving(undefined)).toBe(false);
  });
});
