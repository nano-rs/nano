// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Strip markdown formatting to plain text for truncated/inline contexts —
 * list-row previews, chips, labels, titles — where rendering markdown would be
 * busy or impossible. Content surfaces should render markdown via
 * `@/components/ui/markdown` instead of stripping it.
 *
 * Removes bold/italic (`**`, `*`, `__`, `_`), headers, inline `code`,
 * `[link](url)` (keeping the label), and `>` blockquote markers.
 */
export function stripMarkdown(text: string): string {
  return text
    .replace(/\*\*([^*]+)\*\*/g, '$1') // **bold** -> bold
    .replace(/\*([^*]+)\*/g, '$1') // *italic* -> italic
    .replace(/__([^_]+)__/g, '$1') // __bold__ -> bold
    .replace(/_([^_]+)_/g, '$1') // _italic_ -> italic
    .replace(/^#+\s*/gm, '') // # headers -> text
    .replace(/`([^`]+)`/g, '$1') // `code` -> code
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // [text](url) -> text
    .replace(/>\s*/g, '') // > blockquotes
    .trim();
}
