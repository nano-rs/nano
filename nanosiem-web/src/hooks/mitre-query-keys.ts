// SPDX-License-Identifier: AGPL-3.0-or-later

interface AccessTokenClaims {
  sub?: string;
  jti?: string;
  iat?: number;
}

/**
 * Build a non-secret cache scope from authenticated JWT claims. The JTI keeps
 * data from one login session from being reused by another account/session.
 */
export function mitreAuthScope(userId: string | undefined, token: string | null): string {
  if (!userId) return 'anonymous';
  if (!token) return `${userId}:no-session`;

  try {
    const encodedPayload = token.split('.')[1];
    if (!encodedPayload) return `${userId}:unknown-session`;
    const padded = encodedPayload
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(encodedPayload.length / 4) * 4, '=');
    const claims = JSON.parse(atob(padded)) as AccessTokenClaims;
    const subject = claims.sub ?? userId;
    const session = claims.jti ?? claims.iat?.toString() ?? 'unknown-session';
    return `${userId}:${subject}:${session}`;
  } catch {
    return `${userId}:unknown-session`;
  }
}

export function normalizeMitreFilter(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))].sort();
}

export const mitreQueryKeys = {
  all: ['mitre'] as const,
  catalog: (authScope: string) => [...mitreQueryKeys.all, 'catalog', authScope] as const,
  coverage: (authScope: string, severity: string, mode: string) =>
    [...mitreQueryKeys.all, 'coverage', authScope, severity, mode] as const,
};

interface MitreQueryInvalidator {
  invalidateQueries: (options: { queryKey: readonly string[] }) => Promise<unknown> | unknown;
}

export async function invalidateMitreQueries(queryClient: MitreQueryInvalidator): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: mitreQueryKeys.all });
}
