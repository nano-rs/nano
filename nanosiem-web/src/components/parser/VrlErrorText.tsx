// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5329: VRL compile errors are multi-line diagnostics with box drawing
 * (`┌─ :326:1773`, `│`, `^`). Rendered in a <p>, the newlines and alignment
 * collapsed into one unbroken paragraph. Keep them as preformatted mono text,
 * scrolling horizontally instead of re-wrapping the diagnostic art.
 */
export function VrlErrorText({ error }: { error: string }) {
  return (
    <pre
      data-testid="vrl-error-text"
      className="font-mono text-red-400 text-[11px] leading-relaxed whitespace-pre overflow-x-auto px-3 py-2 m-0"
    >
      {error}
    </pre>
  );
}
