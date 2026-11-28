// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5900: the "Admin" API-key preset, client half.
 *
 * The server resolves the preset (`"preset": "admin"` on create): every
 * permission in the catalogue at creation time, only if the creator holds all
 * of them, and only with an expiry. This module mirrors those rules so the
 * dialog can explain them up front; the server is the one that enforces them.
 *
 * It is a snapshot: permissions added by a later nano release are not added
 * to an existing admin key. That is on purpose, so an upgrade never quietly
 * gives a stored key new powers.
 */

export const ADMIN_PRESET_ID = 'admin';

export interface CatalogueEntry {
  id: string;
}

/** Catalogue permissions the creator can't grant. Empty means the Admin preset is allowed. */
export function adminPresetMissing(
  catalogue: readonly CatalogueEntry[],
  canGrant: (permissionId: string) => boolean,
): string[] {
  return catalogue.map(p => p.id).filter(id => !canGrant(id)).sort((a, b) => a.localeCompare(b));
}

/** Can this creator pick the Admin preset? Never before the catalogue loads. */
export function canUseAdminPreset(
  catalogue: readonly CatalogueEntry[],
  canGrant: (permissionId: string) => boolean,
): boolean {
  return catalogue.length > 0 && adminPresetMissing(catalogue, canGrant).length === 0;
}

/**
 * Does a key hold every permission in the live catalogue? Used to label admin
 * keys in the list. A key made with the preset before a newer release added
 * permissions stops matching, which is correct: it no longer has them all.
 */
export function isAdminKey(keyPermissions: readonly string[], catalogue: readonly CatalogueEntry[]): boolean {
  if (catalogue.length === 0) return false;
  const held = new Set(keyPermissions);
  return catalogue.every(p => held.has(p.id));
}
