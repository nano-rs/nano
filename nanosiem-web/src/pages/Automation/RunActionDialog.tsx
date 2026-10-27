// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — compatibility alias. The Run action form is now the right-side
 * sheet from the design mock (RunActionSheet); the props are unchanged.
 */
export { RunActionSheet as RunActionDialog, RunActionSheet } from './RunActionSheet';
export type { RunActionPreset, RunActionSheetProps } from './RunActionSheet';
