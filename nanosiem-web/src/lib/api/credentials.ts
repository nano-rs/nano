// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud Credentials API routes
 * Handles cloud storage credential management (AWS S3, GCP Pub/Sub, Kafka).
 *
 * Secret material is mutated via `rotateCredential` (not `updateCredential`)
 * so that version history is preserved on the backend.
 */

import type {
  CloudCredential,
  CreateCloudCredentialRequest,
  CredentialListResponse,
  CredentialRotationResponse,
  CredentialVersionListResponse,
  RollbackCredentialRequest,
  RotateCredentialRequest,
  UpdateCloudCredentialRequest,
} from './types';

export class CredentialsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async listCredentials(): Promise<CredentialListResponse> {
    return this.request('/api/credentials');
  }

  async getCredential(id: string): Promise<CloudCredential> {
    return this.request(`/api/credentials/${id}`);
  }

  async createCredential(request: CreateCloudCredentialRequest): Promise<CloudCredential> {
    return this.request('/api/credentials', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async updateCredential(
    id: string,
    request: UpdateCloudCredentialRequest,
  ): Promise<CloudCredential> {
    return this.request(`/api/credentials/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteCredential(id: string): Promise<{ deleted: boolean; id: string }> {
    return this.request(`/api/credentials/${id}`, {
      method: 'DELETE',
    });
  }

  async listCredentialsByProvider(provider: 'aws_s3' | 'azure_blob'): Promise<CredentialListResponse> {
    return this.request(`/api/credentials/provider/${provider}`);
  }

  async rotateCredential(
    id: string,
    request: RotateCredentialRequest,
  ): Promise<CredentialRotationResponse> {
    return this.request(`/api/credentials/${id}/rotate`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async listCredentialVersions(id: string): Promise<CredentialVersionListResponse> {
    return this.request(`/api/credentials/${id}/versions`);
  }

  async rollbackCredential(
    id: string,
    request: RollbackCredentialRequest,
  ): Promise<CredentialRotationResponse> {
    return this.request(`/api/credentials/${id}/rollback`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}
