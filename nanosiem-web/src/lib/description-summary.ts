// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First paragraph of a multi-paragraph description (parser descriptions carry
 * a summary, then a blank line, then a version changelog). NAN-5326: page
 * headers showed the whole changelog run together as one paragraph. Headers
 * show the summary; detail rows render the full text with line breaks kept.
 */
export function descriptionSummary(description: string | null | undefined): string {
  if (!description) return '';
  const trimmed = description.trim();
  const para = trimmed.split(/\n[ \t]*\n/)[0] ?? trimmed;
  return para.replace(/\s*\n\s*/g, ' ').trim();
}
