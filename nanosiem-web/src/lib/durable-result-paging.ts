// SPDX-License-Identifier: AGPL-3.0-or-later

export function durableArtifactPageForOffset(
  absoluteOffset: number,
  pageRows: number,
  pages: number,
): number {
  if (pageRows <= 0 || pages <= 0) return 0;
  return Math.min(Math.floor(Math.max(0, absoluteOffset) / pageRows), pages - 1);
}

export function localResultStart(absoluteOffset: number, resultRowOffset: number): number {
  return Math.max(0, absoluteOffset - Math.max(0, resultRowOffset));
}
