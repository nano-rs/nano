// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * What went wrong issuing an ingest token, in words an analyst can act on
 * (main's NAN-2593 module, re-scoped by NAN-4922 to the single-tenant
 * `POST /api/ingest-tokens` errors: no hosted refusal codes exist here).
 */

export interface IngestCredentialProblem {
  title: string;
  detail: string;
  /** Retrying the same request cannot succeed. */
  terminal: boolean;
}

function statusOf(err: unknown): number | undefined {
  const status = (err as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : undefined;
}

function messageOf(err: unknown): string {
  return err instanceof Error && err.message ? err.message : 'The request failed.';
}

export function describeIngestCredentialError(err: unknown): IngestCredentialProblem {
  const status = statusOf(err);
  const message = messageOf(err);
  switch (status) {
    case 400:
      return { title: 'Check the token name', detail: message, terminal: true };
    case 401:
      return { title: 'Session expired', detail: 'Sign in again, then issue the token.', terminal: true };
    case 403:
      return {
        title: 'Not allowed to issue tokens',
        detail: 'Issuing an ingest token needs the settings:system permission. Ask an administrator.',
        terminal: true,
      };
    case 404:
      return { title: 'Source not found', detail: 'The source was deleted. Go back to step 1 and pick it again.', terminal: true };
    case 409:
      return { title: 'Name already used', detail: `${message} Pick another token name.`, terminal: true };
    case 503:
      return {
        title: 'Token delivery is not configured',
        detail: `${message} Vector reads tokens from the shared dynamic volume; this deployment has none.`,
        terminal: true,
      };
    default:
      return { title: 'Could not issue the token', detail: message, terminal: false };
  }
}
