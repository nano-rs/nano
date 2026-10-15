// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Editor-free VRL highlighting for read-only listings and line diffs
 * (NAN-3195). Same tokenizer and colours as VrlEditor, without mounting a
 * CodeMirror view per row. Pair with `useVrlHighlight` (./use-vrl-highlight).
 */
import type { VrlSegment } from './vrl-language';

/**
 * One highlighted line. `text` is the line as the caller sees it; when the
 * segments don't spell exactly that (a diff library that numbered lines
 * differently, or a blank-line placeholder like ' '), render `text` plainly
 * rather than the wrong tokens.
 */
export function VrlLine({ segments, text }: { segments: VrlSegment[] | undefined; text: string }) {
  if (!segments || segments.map((s) => s.text).join('') !== text) return <>{text}</>;
  return (
    <>
      {segments.map((seg, i) =>
        seg.style ? (
          <span key={i} style={seg.style} data-vrl-token="">
            {seg.text}
          </span>
        ) : (
          <span key={i}>{seg.text}</span>
        ),
      )}
    </>
  );
}
