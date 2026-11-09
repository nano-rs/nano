// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5087: per-feed attribution sections of nano's platform feed bundle NOTICE.

/** One feed's section of the bundle NOTICE (`[feed_id] license_id` + text). */
export interface FeedNotice { feedId: string; licenseId: string; text: string }

/**
 * Split the bundle NOTICE (see `notice_for` in platform_enrichment/portable.rs)
 * into its header and per-feed sections. Text is kept verbatim.
 */
export function parseFeedNotice(notice: string | null | undefined): { header: string; feeds: Map<string, FeedNotice> } {
  const feeds = new Map<string, FeedNotice>();
  if (!notice) return { header: '', feeds };
  const [header, ...chunks] = notice.split(/\n(?=\[[^\]\n]+\][^\n]*\n)/);
  for (const chunk of chunks) {
    const m = /^\[([^\]\n]+)\][ \t]*([^\n]*)\n([\s\S]*)$/.exec(chunk.trim());
    if (m) feeds.set(m[1], { feedId: m[1], licenseId: m[2].trim(), text: m[3].trim() });
  }
  return { header: header.trim(), feeds };
}
