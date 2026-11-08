// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Where a new source's Connect step stands (NAN-4890, ported to the ClickHouse
 * product by NAN-4912). The order is fixed: a token first, then data sent with
 * it, then its first events. Nothing about data is shown as pending until a
 * token is ready, and a token that is being issued (or failed) reports its own
 * state instead of "waiting for data". Issuing never waits on a parser: the
 * source receives events before its parser is published.
 */

import type { LogSourceConnectStatus } from '@/lib/api/log-source-connect';

export type ConnectStage =
  /** No token for this source yet. */
  | 'none'
  /** Issuing the token. */
  | 'pending'
  /** The last issue failed; the reason is on screen with a retry. */
  | 'failed'
  /** A token exists; no event has arrived for the source yet. */
  | 'ready'
  /** Events are arriving for the source. */
  | 'receiving';

export function connectStage(input: { busy: boolean; failed: boolean; issued: boolean; receiving: boolean }): ConnectStage {
  if (input.receiving) return 'receiving';
  if (input.issued) return 'ready';
  if (input.busy) return 'pending';
  if (input.failed) return 'failed';
  return 'none';
}

/** The short state shown in the collapsed Connect summary. */
export const CONNECT_SUMMARY: Record<ConnectStage, string> = {
  none: 'no token yet',
  pending: 'issuing token',
  failed: 'token failed',
  ready: 'waiting for first event',
  receiving: 'receiving',
};

/** The request header a sender authenticates with (HEC's scheme is a wire literal). */
export function authHeader(protocol: 'hec' | 'http' | 'otlp', token?: string): string {
  const value = token ?? '<token>';
  return protocol === 'hec' ? `Authorization: Splunk ${value}` : `Authorization: Bearer ${value}`;
}

/** Events have arrived for the source (parsed or not). */
export function statusReceiving(status: Pick<LogSourceConnectStatus, 'events_24h'> | undefined | null): boolean {
  return (status?.events_24h ?? 0) > 0;
}
