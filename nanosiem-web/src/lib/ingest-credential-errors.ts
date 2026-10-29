// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Human copy for the ingest-credential API's refusal codes (NAN-2592 / 9001640).
 *
 * The API answers 403 `ingest_credential_refused: <code>`, 410 `<code>: …`
 * and rejected requests carry `disposition = "<code>: <text>"`. The code is
 * the stable part; the UI maps it to what the user can do about it.
 */

import { ApiClientError } from '@/lib/api';

export type IngestCredentialRefusal =
  | 'template_unavailable'
  | 'source_platform_only'
  | 'requester_refused'
  | 'permission_missing'
  | 'source_restricted'
  | 'restricted_sources_unacknowledged'
  | 'mixed_restrictions_require_manage'
  | 'membership_inactive'
  | 'requester_inactive'
  | 'tenant_inactive'
  | 'not_requester'
  | 'reveal_key_missing'
  | 'limit_reached'
  | 'collector_unavailable'
  | 'already_revealed'
  | 'sealed_token_expired'
  | 'credential_revoked'
  | 'not_sealed'
  | 'not_found'
  | 'unknown';

export interface IngestCredentialProblem {
  code: IngestCredentialRefusal;
  title: string;
  detail: string;
  /** The user can fix it on this screen (tick the acknowledgement). */
  needsAcknowledgement?: boolean;
  /** Retrying the same request cannot help; issue a new credential instead. */
  terminal?: boolean;
}

const COPY: Record<Exclude<IngestCredentialRefusal, 'unknown'>, Omit<IngestCredentialProblem, 'code'>> = {
  template_unavailable: {
    title: 'No active parser',
    detail: 'This source has no active parser. Activate its parser, then issue a credential again.',
    terminal: true,
  },
  source_platform_only: {
    title: 'Platform-managed source',
    detail: 'The audit source is managed by nano and cannot receive user-issued credentials. Choose another source for your data.',
    terminal: true,
  },
  requester_refused: {
    title: 'Credential request refused',
    detail: 'This credential request is not permitted. Choose an allowed source or ask a tenant admin to review your access, then request a new credential.',
    terminal: true,
  },
  permission_missing: {
    title: 'Permission required',
    detail: 'Issuing and revoking ingest credentials needs the log_sources:deploy permission. Ask a tenant admin.',
  },
  source_restricted: {
    title: 'Source is hidden from you',
    detail:
      'Your groups cannot see events from this source, so you cannot issue a credential that writes to it. Ask an admin with source_scopes:manage.',
  },
  restricted_sources_unacknowledged: {
    title: 'Restricted source: acknowledgement required',
    detail:
      'Some groups cannot see this source. Issuing a credential for it needs source_scopes:manage and an explicit acknowledgement that the token can write restricted data.',
    needsAcknowledgement: true,
  },
  mixed_restrictions_require_manage: {
    title: 'Restricted sources need source_scopes:manage',
    detail:
      'The sources you picked have different visibility restrictions. Only a user with source_scopes:manage can issue a credential that spans them, and must acknowledge it.',
    needsAcknowledgement: true,
  },
  membership_inactive: {
    title: 'Membership inactive',
    detail: 'Your tenant membership is not active. Ask a tenant admin to restore it.',
  },
  requester_inactive: {
    title: 'Requester inactive',
    detail: 'The user who requested this credential is no longer active, so it was not issued.',
    terminal: true,
  },
  tenant_inactive: {
    title: 'Tenant inactive',
    detail: 'This tenant is suspended or not yet active. Contact support.',
  },
  not_requester: {
    title: 'Only the requester can reveal it',
    detail: 'The token is sealed to the browser of the user who requested it. Issue your own credential.',
    terminal: true,
  },
  reveal_key_missing: {
    title: 'Request was missing its browser key',
    detail: 'The request did not carry a reveal key, so no token could be sealed to it. Issue a new credential.',
    terminal: true,
  },
  limit_reached: {
    title: 'Too many pending requests',
    detail: 'This tenant has 64 credential requests waiting. Wait for them to finish or expire, then try again.',
  },
  collector_unavailable: {
    title: 'Collector credentials are not available yet',
    detail: 'This tenant’s ingest endpoint accepts per-source credentials only.',
  },
  already_revealed: {
    title: 'Already revealed',
    detail: 'The token was shown once and cannot be shown again. Revoke the credential if you did not save it, then issue a new one.',
    terminal: true,
  },
  sealed_token_expired: {
    title: 'Reveal window expired',
    detail: 'The sealed token was not collected within 10 minutes. Revoke the credential and issue a new one.',
    terminal: true,
  },
  credential_revoked: {
    title: 'Credential revoked',
    detail: 'The credential was revoked before its token was revealed. Issue a new one.',
    terminal: true,
  },
  not_sealed: {
    title: 'No sealed token',
    detail: 'This request predates sealed delivery, so it has no token to reveal. Issue a new credential.',
    terminal: true,
  },
  not_found: {
    title: 'Not found',
    detail: 'The request or credential no longer exists. Refresh the list.',
    terminal: true,
  },
};

const KNOWN = new Set(Object.keys(COPY));

/** The stable code inside a server message or a rejected request's `disposition`. */
export function refusalCode(text: string | null | undefined): IngestCredentialRefusal {
  if (!text) return 'unknown';
  const refused = /ingest_credential_refused:\s*([a-z_]+)/.exec(text);
  if (refused && KNOWN.has(refused[1])) return refused[1] as IngestCredentialRefusal;
  if (/limit reached/i.test(text)) return 'limit_reached';
  const leading = /(?:^|:\s*)([a-z][a-z_]+):/.exec(text);
  if (leading && KNOWN.has(leading[1])) return leading[1] as IngestCredentialRefusal;
  for (const code of KNOWN) if (new RegExp(`\\b${code}\\b`).test(text)) return code as IngestCredentialRefusal;
  return 'unknown';
}

export function describeRefusal(code: IngestCredentialRefusal, fallback?: string): IngestCredentialProblem {
  if (code === 'unknown') {
    return { code, title: 'Request failed', detail: fallback || 'The server refused the request.' };
  }
  return { code, ...COPY[code] };
}

/** Map any thrown error from the ingest-credential endpoints to user copy. */
export function describeIngestCredentialError(err: unknown): IngestCredentialProblem {
  const message = err instanceof Error ? err.message : String(err ?? '');
  let code = refusalCode(message);
  if (code === 'unknown' && err instanceof ApiClientError && err.status === 404) code = 'not_found';
  return describeRefusal(code, message);
}
