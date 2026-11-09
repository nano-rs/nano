// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-5114: "Update available" banner visibility and per-version dismissal. */

import type { UpdateStatusResponse } from './api';

export const UPDATE_BANNER_DISMISSED_KEY = 'nano.update-banner.dismissed-version';

export function readDismissedUpdate(): string | null {
  try {
    return window.localStorage.getItem(UPDATE_BANNER_DISMISSED_KEY);
  } catch {
    return null;
  }
}

export function writeDismissedUpdate(version: string) {
  try {
    window.localStorage.setItem(UPDATE_BANNER_DISMISSED_KEY, version);
  } catch {
    // Private mode / blocked storage: dismissal lasts for this page only.
  }
}

/** Show only a strictly newer release with both links, unless that version was dismissed. */
export function shouldShowUpdateBanner(status: UpdateStatusResponse | null | undefined, dismissedVersion: string | null): boolean {
  if (!status?.update_available || !status.latest_version) return false;
  if (!status.upgrade_url || !status.release_notes_url) return false;
  return dismissedVersion !== status.latest_version;
}
