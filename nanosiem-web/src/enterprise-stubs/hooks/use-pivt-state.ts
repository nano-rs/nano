// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for usePivtState. PIVT (the AI assistant shell) is
// enterprise-only; in open builds AppLayout still mounts <PivtSummon> +
// <PivtShellOverlay> until the AppLayout gating in Task #17 lands, so we
// hand back a frozen no-op state object. The components themselves are
// stubbed to render nothing, so the state's only role is keeping the type
// contract whole and the keyboard shortcut handlers no-ops.

export type PivtMode = 'dock' | 'float' | 'hidden';

export interface PivtState {
  mode: PivtMode;
  isOpen: boolean;
  dockWidth: number;
  floatPos: { x: number; y: number };
  toggle: () => void;
  open: () => void;
  close: () => void;
  setMode: (mode: PivtMode) => void;
  setDockWidth: (width: number) => void;
  setFloatPos: (pos: { x: number; y: number }) => void;
  switchDockFloat: () => void;
}

export const MIN_DOCK_WIDTH = 320;
export const MAX_DOCK_WIDTH = 640;

const NOOP = () => {};

const STUB_STATE: PivtState = {
  mode: 'hidden',
  isOpen: false,
  dockWidth: MIN_DOCK_WIDTH,
  floatPos: { x: 0, y: 0 },
  toggle: NOOP,
  open: NOOP,
  close: NOOP,
  setMode: NOOP,
  setDockWidth: NOOP,
  setFloatPos: NOOP,
  switchDockFloat: NOOP,
};

export function usePivtState(): PivtState {
  return STUB_STATE;
}
