/**
 * NAN-5329: a role or API key may only be granted permissions its creator
 * holds (the server refuses the rest: "Cannot grant permissions you don't
 * hold"). Pickers use these helpers to keep ungrantable permissions
 * unselectable up front instead of failing on submit.
 */

export type CanGrant = (permissionId: string) => boolean;

export const GRANT_ALL: CanGrant = () => true;

/** An unselected permission can be ticked only when grantable; a selected one can always be cleared. */
export function canToggleGrant(permissionId: string, selected: boolean, canGrant: CanGrant): boolean {
  return selected || canGrant(permissionId);
}

/** Bulk-select helpers (select all, presets) only add what the creator can grant. */
export function grantableOnly(ids: readonly string[], canGrant: CanGrant): string[] {
  return ids.filter((id) => canGrant(id));
}

export const UNGRANTABLE_HINT = "You don't hold this permission, so you can't grant it.";
