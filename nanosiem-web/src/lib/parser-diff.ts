// SPDX-License-Identifier: AGPL-3.0-or-later

// Generic line-by-line diff used by both the enterprise ParserEditChat
// (meloD-driven VRL editor) and the open LogSourceDetail (manual VRL diff
// display). Lifted out of `components/parser/ParserEditChat.tsx` so the
// open consumer doesn't pull the chat panel into its bundle (NAN-745).

export interface DiffLine {
  type: 'added' | 'removed' | 'unchanged' | 'context';
  content: string;
  lineNumber?: number;
}

export interface VrlUpdateInfo {
  newVrl: string;
  previousVrl: string;
  diff: DiffLine[];
}

// Simple diff algorithm — line-by-line LCS-based.
export function computeDiff(oldText: string, newText: string): DiffLine[] {
  const oldLines = oldText.split('\n');
  const newLines = newText.split('\n');
  const diff: DiffLine[] = [];

  const lcs = computeLCS(oldLines, newLines);

  let oldIdx = 0;
  let newIdx = 0;
  let lcsIdx = 0;

  while (oldIdx < oldLines.length || newIdx < newLines.length) {
    if (lcsIdx < lcs.length && oldIdx < oldLines.length && oldLines[oldIdx] === lcs[lcsIdx]) {
      if (newIdx < newLines.length && newLines[newIdx] === lcs[lcsIdx]) {
        diff.push({ type: 'unchanged', content: oldLines[oldIdx], lineNumber: newIdx + 1 });
        oldIdx++;
        newIdx++;
        lcsIdx++;
      } else {
        diff.push({ type: 'added', content: newLines[newIdx], lineNumber: newIdx + 1 });
        newIdx++;
      }
    } else if (oldIdx < oldLines.length && (lcsIdx >= lcs.length || oldLines[oldIdx] !== lcs[lcsIdx])) {
      diff.push({ type: 'removed', content: oldLines[oldIdx] });
      oldIdx++;
    } else if (newIdx < newLines.length) {
      diff.push({ type: 'added', content: newLines[newIdx], lineNumber: newIdx + 1 });
      newIdx++;
    }
  }

  return diff;
}

function computeLCS(a: string[], b: string[]): string[] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const lcs: string[] = [];
  let i = m, j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      lcs.unshift(a[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  return lcs;
}
