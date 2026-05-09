// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Authentication API routes
 * Handles user authentication, password management, and OIDC flows
 */

import type {
  AuthResponse,
  TokenPairResponse,
  CurrentUser,
  OidcProviderInfo,
  OidcAuthUrlResponse,
  OidcCallbackResponse,
  MfaSetupResponse,
  MfaSetupCompleteResponse,
  MfaStatusResponse,
} from './types';

export class AuthApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async login(email: string, password: string): Promise<AuthResponse> {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async logout(refreshToken: string): Promise<void> {
    return this.request('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  }

  async refreshToken(refreshToken: string): Promise<TokenPairResponse> {
    return this.request('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  }

  async getCurrentUser(): Promise<CurrentUser> {
    return this.request('/api/auth/me');
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    return this.request('/api/auth/password/reset-request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    return this.request('/api/auth/password/reset', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return this.request('/api/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  // MFA endpoints
  // The optional `challengeToken` arg covers forced enrolment — the user
  // is mid-login with no session yet, just a 5-minute mfa_challenge from
  // the prior login response. Voluntary enrolment from User Settings
  // omits it and authenticates via Bearer.
  async setupMfa(challengeToken?: string): Promise<MfaSetupResponse> {
    return this.request('/api/auth/mfa/setup', {
      method: 'POST',
      body: JSON.stringify(challengeToken ? { challenge_token: challengeToken } : {}),
    });
  }

  async verifyMfaSetup(
    code: string,
    challengeToken?: string,
  ): Promise<MfaSetupCompleteResponse> {
    return this.request('/api/auth/mfa/verify-setup', {
      method: 'POST',
      body: JSON.stringify(
        challengeToken ? { code, challenge_token: challengeToken } : { code },
      ),
    });
  }

  async verifyMfaChallenge(challengeToken: string, code: string): Promise<AuthResponse> {
    return this.request('/api/auth/mfa/challenge', {
      method: 'POST',
      body: JSON.stringify({ challenge_token: challengeToken, code }),
    });
  }

  async getMfaStatus(): Promise<MfaStatusResponse> {
    return this.request('/api/auth/mfa/status');
  }

  async disableMfa(password: string): Promise<void> {
    return this.request('/api/auth/mfa', {
      method: 'DELETE',
      body: JSON.stringify({ password }),
    });
  }

  async regenerateBackupCodes(password: string): Promise<MfaSetupCompleteResponse> {
    return this.request('/api/auth/mfa/backup-codes', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  async setMfaRequired(required: boolean): Promise<{ mfa_required: boolean }> {
    return this.request('/api/settings/mfa-required', {
      method: 'PUT',
      body: JSON.stringify({ required }),
    });
  }

  async adminResetMfa(userId: string): Promise<void> {
    return this.request(`/api/admin/users/${userId}/mfa`, { method: 'DELETE' });
  }

  // OIDC endpoints
  async getOidcProviders(): Promise<OidcProviderInfo[]> {
    return this.request('/api/auth/oidc/providers');
  }

  async getOidcAuthUrl(providerSlug: string, redirectUri: string): Promise<OidcAuthUrlResponse> {
    return this.request(`/api/auth/oidc/${providerSlug}/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`);
  }

  async handleOidcCallback(
    providerSlug: string,
    code: string,
    state: string,
    redirectUri: string,
  ): Promise<OidcCallbackResponse> {
    return this.request(`/api/auth/oidc/${providerSlug}/callback`, {
      method: 'POST',
      body: JSON.stringify({
        code,
        state,
        redirect_uri: redirectUri,
      }),
    });
  }
}
