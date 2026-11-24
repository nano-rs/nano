// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5834: the "VRL invalid" toast description. The full compiler output is
 * a multi-line diagnostic (one error rendered 400+ px tall in a toast, over
 * the editor's own action buttons) and the editor already shows it in its
 * Diagnostics panel, so the toast carries a one-line summary only.
 */
export function vrlErrorToastDescription(errors: readonly string[]): string {
  const n = errors.filter((e) => e.trim().length > 0).length;
  if (n === 0) return 'See Diagnostics for details.';
  return `${n} ${n === 1 ? 'error' : 'errors'}. See Diagnostics for details.`;
}
