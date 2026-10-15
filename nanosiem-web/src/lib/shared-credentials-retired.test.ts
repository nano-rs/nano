// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { CLOUD_PULL_PATH, CREDENTIALS_RETIRED_ON_SHARED } from './shared-credentials-retired';

describe('NAN-3620 shared credential retirement constants', () => {
  it('points at Log Sources → Cloud pull', () => {
    expect(CLOUD_PULL_PATH).toBe('/ingestion/log-sources/cloud-pull');
  });

  it('matches the API refusal code', () => {
    expect(CREDENTIALS_RETIRED_ON_SHARED).toBe('credentials_retired_on_shared');
  });
});
