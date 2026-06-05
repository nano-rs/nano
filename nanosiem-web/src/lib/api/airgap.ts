// SPDX-License-Identifier: AGPL-3.0-or-later

// Air-gapped bundle import client (NAN-1201).
//
// Multipart uploads can't go through the shared `ApiClient.request`
// (it forces `Content-Type: application/json`, which would clobber the
// multipart boundary the browser sets), so this mirrors the same
// FormData + manual-fetch pattern used by `UploadApi.previewUpload`.

import { getServiceUrl } from './utils';
import { getAccessToken } from '../auth-token';

/**
 * Response from syncing an air-gapped parser bundle (NAN-1226).
 *
 * The upload is now SYNC-ONLY: it populates the parser repository catalog so
 * the items appear *available to import* on the repositories page. Nothing is
 * imported or deployed by the upload itself — the operator uses the page's
 * existing select → import (→ deploy) flow.
 */
export interface AirgapParserImportResponse {
  repository_id: string;
  content_version: string;
  /** Number of catalog items synced (made available to import). */
  synced: number;
}

async function postBundle<T>(endpoint: string, file: File): Promise<T> {
  const formData = new FormData();
  formData.append('file', file);

  const url = `${getServiceUrl(endpoint)}${endpoint}`;
  const headers: Record<string, string> = {};
  const token = getAccessToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: formData,
    credentials: 'include',
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({
      error: { code: 'UNKNOWN_ERROR', message: response.statusText },
    }));
    const error = errorBody.error || errorBody;
    throw new Error(error.message || 'Bundle import failed');
  }

  return response.json();
}

/**
 * Upload a signed, air-gapped parser bundle. SYNC-ONLY: populates the parser
 * repository catalog (items become available to import); does not import or
 * deploy. (NAN-1226)
 */
export function importParserBundle(file: File): Promise<AirgapParserImportResponse> {
  return postBundle<AirgapParserImportResponse>('/api/airgap/parsers/import', file);
}

/** Response from importing an offline license token bundle. */
export interface AirgapLicenseImportResponse {
  mode: string;
  state: string;
  valid: boolean;
  tier: string;
  expires_at: string;
  content_version: string;
  license_id?: string;
  customer?: string;
}

/** Upload + apply a signed, air-gapped (offline) license token bundle. */
export function importLicenseBundle(file: File): Promise<AirgapLicenseImportResponse> {
  return postBundle<AirgapLicenseImportResponse>('/api/airgap/license/import', file);
}

/** Response from importing an offline enrichment bundle (IP geo/ASN or IOC). */
export interface AirgapEnrichmentImportResponse {
  /** `ip_enrichment` | `ioc` — the bundle type that was imported. */
  bundle_type: string;
  content_version: string;
  records_imported: number;
  dictionary_reloaded: boolean;
}

/**
 * Upload + import a signed, air-gapped enrichment data bundle. The backend
 * reads the bundle manifest's `bundle_type` to discriminate IP geo/ASN vs IOC,
 * so the same call handles both shapes. Used by the air-gap import surface that
 * the marketplace routes connectivity-required items to (NAN-1212).
 */
export function importEnrichmentBundle(file: File): Promise<AirgapEnrichmentImportResponse> {
  return postBundle<AirgapEnrichmentImportResponse>('/api/airgap/enrichment/import', file);
}

/**
 * Response from syncing an air-gapped rule bundle (NAN-1226).
 *
 * SYNC-ONLY: populates the rule repository catalog (rules become *available to
 * import*); nothing is imported or activated by the upload.
 */
export interface AirgapRuleImportResponse {
  repository_id: string;
  content_version: string;
  /** Number of catalog rules synced (made available to import). */
  synced: number;
}

/**
 * Upload a signed, air-gapped rule bundle (nano native format). SYNC-ONLY:
 * populates the rule repository catalog; does not import. (NAN-1226)
 */
export function importRulesBundle(file: File): Promise<AirgapRuleImportResponse> {
  return postBundle<AirgapRuleImportResponse>('/api/airgap/rules/import', file);
}

/**
 * Response from syncing an air-gapped playbook bundle (NAN-1226).
 *
 * SYNC-ONLY: populates the playbook repository catalog (playbooks become
 * *available to import*); nothing is imported by the upload.
 */
export interface AirgapPlaybookImportResponse {
  repository_id: string;
  content_version: string;
  /** Number of catalog playbooks synced (made available to import). */
  synced: number;
}

/**
 * Upload a signed, air-gapped playbook bundle (markdown/yaml). SYNC-ONLY:
 * populates the playbook repository catalog; does not import. (NAN-1226)
 */
export function importPlaybooksBundle(file: File): Promise<AirgapPlaybookImportResponse> {
  return postBundle<AirgapPlaybookImportResponse>('/api/airgap/playbooks/import', file);
}
