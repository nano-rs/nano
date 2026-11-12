// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5321: Deploy renders the ACTIVE (published) version, never the editor's
 * working draft (NAN-2293 / NAN-2304). Only a source that has never been
 * published deploys its working copy. The dialog must say which one ships.
 */
export function deployDialogDescription(
  name: string,
  activeVersion: number | null | undefined,
  hasDraft: boolean,
): string {
  if (!activeVersion) {
    return `Deploy "${name}" to Vector. Incoming logs matching this source type will be parsed using the current VRL.`;
  }
  const base = `Redeploy "${name}" to Vector using the published version (v${activeVersion}).`;
  return hasDraft ? `${base} Unpublished draft changes are not included; use Publish to ship them.` : base;
}
