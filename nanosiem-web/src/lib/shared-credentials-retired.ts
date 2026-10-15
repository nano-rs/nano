// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3620: Ingestion → Credentials is retired on hosted-shared tenants (new
 * stored cloud credentials are refused; existing rows stay manageable through
 * the API). Nothing there consumes them for ingest and hosted cloud pull is
 * keyless. Open core and dedicated are unchanged.
 */

/** Log Sources → Cloud pull: the keyless hosted replacement. */
export const CLOUD_PULL_PATH = '/ingestion/log-sources/cloud-pull';

/** API error code for a refused credential write on shared (HTTP 410). */
export const CREDENTIALS_RETIRED_ON_SHARED = 'credentials_retired_on_shared';
