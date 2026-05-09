// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ValidationState {
  valid: boolean;
  error?: string;
  matchCount?: number;
}

export interface CursorCoordinates {
  top: number;
  left: number;
}
