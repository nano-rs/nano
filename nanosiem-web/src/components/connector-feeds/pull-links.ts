// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5903: Pull feeds is the one place a pull feed is set up. Other pages
 * (the Marketplace, empty states) hop to it with these links instead of
 * embedding a form.
 */

export const PULL_FEEDS_PATH = '/ingestion/log-sources/pull-feeds';

/** The structured refusal for a start whose lanes have no log source. */
export const LOG_SOURCES_MISSING = 'LOG_SOURCES_MISSING';

/** Pull feeds with New pull feed open for `connector`. */
export function pullNewFeedPath(connector: string): string {
  return `${PULL_FEEDS_PATH}?new=${encodeURIComponent(connector)}`;
}

/** What a refused start was: resuming the feed, or adopting its spec update. */
export type FixSetupKind = 'resume' | 'adopt';

/** Pull feeds offering Fix setup for the feed `feedId`, repeating `kind`. */
export function pullFixSetupPath(feedId: string, kind: FixSetupKind): string {
  return `${PULL_FEEDS_PATH}?fix=${encodeURIComponent(feedId)}&action=${kind}`;
}
