// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Authentication Context
 *
 * Provides authentication state and methods throughout the application.
 * Handles local login, OIDC/SSO login, logout, token refresh, and permission checking.
 *
 * Access tokens are stored in-memory only (via auth-token.ts).
 * Refresh tokens are stored in HttpOnly cookies (managed by the backend).
 * On page reload, a silent refresh via cookie restores the session.
 *
 * Requirements: 10.4, 10.5
 * - 10.4: Redirect to login if not authenticated, check permissions for route access
 * - 10.5: Provide logout button that terminates the session
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../lib/api';
import { sessionCredentials } from '../lib/session-credentials';
import { requestCredentials } from '../lib/request-credentials';
import { setAccessToken, getAccessToken, clearAccessToken, persistDemoSession, restoreDemoSession, getDemoRefreshToken } from '../lib/auth-token';
import {
  accessOnlyRefreshResult,
  broadcastSessionInvalidation,
  broadcastSessionReplacement,
  broadcastTenantSessionRevocation,
  cookieMutationStillOwnsSession,
  cookieSlotForScope,
  coordinateBrowserRefresh,
  isRefreshSessionMessage,
  logoutMessageAffectsSlot,
  ORIGIN_COOKIE_SLOT,
  REFRESH_SESSION_CHANNEL_NAME,
  refreshSessionMessageReplacesScope,
  tenantCookieSlot,
  withBrowserCookieMutationLock,
} from '../lib/refresh-coordinator';
import {
  browserTenantRuntime,
  authenticatedRuntimeScope,
  type ActiveTenant,
  type DeploymentMode,
  type TenantRuntimeSnapshot,
} from '../lib/tenant-runtime';
import {
  canonicalTenantSlug,
  loginRequestBody,
  safeReturnPath,
  tenantContinuationBody,
  tenantSlugForAuthContinuation,
  verifyServerAuthIdentity,
} from '../lib/tenant-auth-shell';

// ============================================================================
// Types
// ============================================================================

export type QueryMode = 'standard' | 'advanced';
export type TimeRangePreset =
  | 'last_15_minutes'
  | 'last_hour'
  | 'last_4_hours'
  | 'last_24_hours'
  | 'last_7_days'
  | 'last_30_days';

export type LandingPage = 'search' | 'home' | 'cases' | 'dashboards' | 'rules';

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  preferred_query_mode?: QueryMode;
  default_time_range?: TimeRangePreset;
  landing_page?: LandingPage;
  isApiKey?: boolean;
  deployment_mode: DeploymentMode;
  active_tenant?: ActiveTenant;
}

/**
 * Public provider shape from `GET /api/auth/oidc/providers`.
 *
 * Mirrors `OidcProviderInfo` in nanosiem-core: slug and name only. It carried a
 * phantom `id` that the endpoint has never returned, so consumers keying on it
 * were keying on `undefined` (NAN-2179). Pre-auth, the slug is the identifier —
 * it is what `/authorize` takes and what the callback path is built from.
 */
export interface OidcProvider {
  name: string;
  slug: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  tenantRuntime: TenantRuntimeSnapshot;
}

export interface AuthContextType extends AuthState {
  permissions: string[];
  isDemoUser: boolean;
  login: (email: string, password: string, tenantSlug?: string) => Promise<void>;
  loginAsDemo: (displayName?: string) => Promise<void>;
  claimDemoToken: (token: string) => Promise<void>;
  loginWithOidc: (providerSlug: string, currentPath?: string) => Promise<void>;
  handleOidcCallback: (
    providerSlug: string,
    code: string,
    state: string,
  ) => Promise<string>;
  /** Activate a cookies-only hosted-shared OIDC session after exact bootstrap proof. */
  acceptSharedOidcSession: (user: User, expectedTenantSlug: string) => Promise<void>;
  /** Clear local authority after a callback changed cookies but later proof failed. */
  discardFailedSharedOidcSession: () => void;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
  hasAllPermissions: (permissions: string[]) => boolean;
  refreshAuth: () => Promise<boolean>;
  clearError: () => void;
  // MFA
  mfaPending: boolean;
  mfaSetupPending: boolean;
  challengeToken: string | null;
  pendingTenantSlug: string | null;
  verifyMfa: (code: string) => Promise<void>;
  cancelMfa: () => void;
  /**
   * Hosted-shared step-up (NAN-2361 wave 5): re-prove TOTP on the current
   * tenant session so fresh-MFA admin surfaces (SSO provider administration)
   * work without signing in again. Replaces this tab's bearer and the
   * session cookies; the session itself (its authentication fence) is kept.
   */
  stepUpMfa: (code: string) => Promise<void>;
}

// ============================================================================
// OIDC State (sessionStorage — non-sensitive, needed across redirect)
// ============================================================================

const OIDC_STATE_KEY = 'nanosiem_oidc_state';

interface OidcStateData {
  state: string;
  providerSlug: string;
  redirectUri: string;
  returnTo: string;
}

function storeOidcState(data: OidcStateData): void {
  sessionStorage.setItem(OIDC_STATE_KEY, JSON.stringify(data));
}

function getOidcState(): OidcStateData | null {
  try {
    const stored = sessionStorage.getItem(OIDC_STATE_KEY);
    if (!stored) return null;
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

function clearOidcState(): void {
  sessionStorage.removeItem(OIDC_STATE_KEY);
}

/**
 * Sanitizes a return path, returning '/' if invalid
 */
function sanitizeReturnPath(path: string | undefined): string {
  return safeReturnPath(path);
}

// ============================================================================
// API Functions
// ============================================================================

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  accessToken?: string
): Promise<T> {
  const capturedRuntime = browserTenantRuntime.current();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (accessToken) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
    credentials: requestCredentials(endpoint, headers, capturedRuntime.scope.kind === 'enterprise_shared'),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new AuthError(
      errorBody.message || errorBody.error || 'Request failed',
      response.status,
      errorBody.error
    );
  }

  // Handle 204 No Content
  if (response.status === 204) {
    browserTenantRuntime.assertCurrent(capturedRuntime);
    return {} as T;
  }

  const value = await response.json();
  browserTenantRuntime.assertCurrent(capturedRuntime);
  return value;
}

class AuthError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

// ============================================================================
// Multi-tab logout via BroadcastChannel
// ============================================================================

const AUTH_CHANNEL_NAME = 'nanosiem-auth';

function refreshScopeKey(
  scope: TenantRuntimeSnapshot['scope'],
  routeTenantSlug?: string,
): string {
  if (scope.kind === 'enterprise_shared' && scope.tenant.slug === routeTenantSlug) {
    return `enterprise_shared:${scope.tenant.id}:${scope.userId}`;
  }
  if (routeTenantSlug) return `enterprise_shared_slug:${routeTenantSlug}`;
  if (scope.kind === 'anonymous') return 'anonymous';
  if (scope.kind === 'enterprise_shared') {
    return `enterprise_shared:${scope.tenant.id}:${scope.userId}`;
  }
  return `${scope.kind}:${scope.userId}`;
}

function currentRouteTenantSlug(): string | undefined {
  return typeof window === 'undefined'
    ? undefined
    : tenantSlugForAuthContinuation(window.location.pathname);
}

/** This tab's cookie slot right now (NAN-3548). */
function currentCookieSlot(): string {
  return cookieSlotForScope(browserTenantRuntime.current().scope, currentRouteTenantSlug());
}

/** Cookie slot of a freshly authenticated identity. */
function authenticatedCookieSlot(state: AuthState): string {
  return cookieSlotForScope(state.tenantRuntime.scope);
}

function broadcastLogout(cookieSlot: string): void {
  try {
    const channel = new BroadcastChannel(AUTH_CHANNEL_NAME);
    channel.postMessage({ type: 'logout', cookieSlot });
    channel.close();
  } catch {
    // BroadcastChannel not supported — single-tab fallback
  }
}

// ============================================================================
// Context
// ============================================================================

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ============================================================================
// Provider Component
// ============================================================================

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
    tenantRuntime: browserTenantRuntime.current(),
  });

  const authenticatedState = useCallback((user: User, expectedTenantSlug?: string): AuthState => {
    const verified = verifyServerAuthIdentity(user, expectedTenantSlug);
    const scope = authenticatedRuntimeScope({
      userId: user.id,
      roles: user.roles,
      activeTenant: user.active_tenant,
      deploymentMode: verified.deploymentMode,
    });
    return {
      user,
      isAuthenticated: true,
      isLoading: false,
      error: null,
      tenantRuntime: browserTenantRuntime.activate(scope),
    };
  }, []);

  const anonymousState = useCallback((error: string | null = null): AuthState => ({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    error,
    tenantRuntime: browserTenantRuntime.activate({ kind: 'anonymous' }),
  }), []);

  // MFA state
  const [mfaPending, setMfaPending] = useState(false);
  const [mfaSetupPending, setMfaSetupPending] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [pendingTenantSlug, setPendingTenantSlug] = useState<string | null>(null);

  const refreshTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Deduplication: concurrent callers wait on the same promise
  const refreshPromiseRef = useRef<Promise<boolean> | null>(null);

  // Schedule token refresh before expiration
  const scheduleTokenRefresh = useCallback((expiresInSeconds: number) => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
    }

    // Refresh 1 minute before expiration
    const refreshMs = (expiresInSeconds * 1000) - 60000;

    if (refreshMs > 0) {
      refreshTimeoutRef.current = setTimeout(async () => {
        await refreshAuth().catch(() => false);
      }, refreshMs);
    }
  }, []);

  // Refresh authentication via HttpOnly refresh_token cookie (or demo refresh token)
  const refreshAuth = useCallback(async (): Promise<boolean> => {
    // Dedup: if a refresh is already in-flight, return the same promise
    if (refreshPromiseRef.current) return refreshPromiseRef.current;

    const doRefresh = async (): Promise<boolean> => {
      try {
        // Demo users: send refresh token in body (no HttpOnly cookie)
        // Regular users: empty body, refresh token is in the HttpOnly cookie
        const demoRefreshToken = getDemoRefreshToken();
        const runtimeScope = browserTenantRuntime.current().scope;
        const pathTenantSlug = currentRouteTenantSlug();
        const refreshTenantSlug = pathTenantSlug
          ?? (runtimeScope.kind === 'enterprise_shared' ? runtimeScope.tenant.slug : undefined);
        const currentRefreshScopeKey = refreshScopeKey(runtimeScope, refreshTenantSlug);
        const refreshCookieSlot = cookieSlotForScope(runtimeScope, refreshTenantSlug);
        const body = demoRefreshToken
          ? JSON.stringify({ refresh_token: demoRefreshToken })
          : JSON.stringify(tenantContinuationBody(refreshTenantSlug));

        const refreshOperation = () => apiRequest<{
          access_token: string;
          refresh_token: string;
          expires_in: number;
        }>('/api/auth/refresh', {
          method: 'POST',
          body,
          signal: AbortSignal.timeout(10_000),
        });
        // Demo sessions intentionally retain their existing per-tab refresh
        // contract. Regular rotating HttpOnly cookies get one cross-tab winner.
        const response = demoRefreshToken
          ? await refreshOperation()
          : await coordinateBrowserRefresh(async () => {
              const refreshed = await refreshOperation();
              // Never put the rotating refresh credential on BroadcastChannel.
              return accessOnlyRefreshResult(refreshed);
            }, {
              requireCoordination:
                browserTenantRuntime.current().scope.kind === 'enterprise_shared'
                || (typeof window !== 'undefined' && window.location.pathname.startsWith('/t/')),
              scopeKey: currentRefreshScopeKey,
              cookieSlot: refreshCookieSlot,
            });

        // Verify the winner token against the expected route/tenant before it
        // can replace this tab's in-memory bearer credential.
        const userInfo = await apiRequest<User>('/api/auth/me', { signal: AbortSignal.timeout(10_000) }, response.access_token);
        const nextState = authenticatedState(userInfo, refreshTenantSlug);
        setAccessToken(response.access_token, response.expires_in);

        // Update demo session with new tokens
        if (
          demoRefreshToken
          && 'refresh_token' in response
          && typeof response.refresh_token === 'string'
        ) {
          persistDemoSession(response.access_token, response.refresh_token, response.expires_in, userInfo);
        }

        setState(nextState);

        // A route-slug-only refresh scope is not an authenticated identity.
        // Announce only after /auth/me and exact tenant validation succeeded.
        if (!demoRefreshToken) {
          broadcastSessionReplacement(
            refreshScopeKey(nextState.tenantRuntime.scope),
            authenticatedCookieSlot(nextState),
          );
        }

        scheduleTokenRefresh(response.expires_in);
        return true;
      } catch {
        clearAccessToken();
        // The shared request gate invokes handleAuthFailure once for the queue.
        return false;
      } finally {
        refreshPromiseRef.current = null;
      }
    };

    refreshPromiseRef.current = sessionCredentials.runRefresh(doRefresh);
    return refreshPromiseRef.current;
  }, [anonymousState, authenticatedState, scheduleTokenRefresh]);

  // Handle auth failure from API client (401 that couldn't be refreshed)
  const handleAuthFailure = useCallback(() => {
    // Clear any scheduled refresh
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
      refreshTimeoutRef.current = null;
    }

    clearAccessToken();
    setPendingTenantSlug(null);

    // Update state to logged out
    setState(anonymousState('Session expired — sign in again'));
  }, [anonymousState]);

  // Initialize auth state on mount
  useEffect(() => {
    // Register auth failure callback with API client
    // This handles 401s that occur during normal API calls
    api.setAuthFailureCallback(handleAuthFailure);

    // Register refresh callback for 401 retry in ApiClient
    api.setRefreshCallback(refreshAuth);

    const initAuth = async () => {
      // Clear legacy localStorage tokens (one-time migration)
      if (localStorage.getItem('nanosiem_auth')) {
        localStorage.removeItem('nanosiem_auth');
      }

      // Skip silent refresh on OIDC callback pages — the callback component
      // will authenticate via handleOidcCallback, and racing with refreshAuth
      // would use a stale cookie and fail.
      if (
        window.location.pathname.startsWith('/auth/callback')
        || window.location.pathname.startsWith('/auth/shared/oidc/')
      ) {
        setState(prev => ({ ...prev, isLoading: false }));
        return;
      }

      // Restore demo session from localStorage (survives page reloads)
      const demoSession = restoreDemoSession();
      if (demoSession) {
        const restoredDemoUser = {
          ...(demoSession.user as Omit<User, 'deployment_mode'>),
          deployment_mode: 'demo' as const,
        };
        setAccessToken(demoSession.accessToken, 900); // re-set in memory
        setState(authenticatedState(restoredDemoUser));
        scheduleTokenRefresh(900);
        return;
      }

      // Attempt silent refresh via HttpOnly cookie
      await refreshAuth().catch(() => false);
    };

    initAuth();

    // Listen for logout and origin-wide session replacement events from other
    // tabs. A different tenant/user owns the one rotating cookie, so this tab
    // must discard its in-memory bearer and scheduled refresh immediately.
    let channel: BroadcastChannel | null = null;
    let sessionChannel: BroadcastChannel | null = null;
    try {
      channel = new BroadcastChannel(AUTH_CHANNEL_NAME);
      channel.onmessage = (event) => {
        if (logoutMessageAffectsSlot(event.data, currentCookieSlot())) {
          clearAccessToken();
          if (refreshTimeoutRef.current) {
            clearTimeout(refreshTimeoutRef.current);
            refreshTimeoutRef.current = null;
          }
          setPendingTenantSlug(null);
          setState(anonymousState());
        }
      };
      sessionChannel = new BroadcastChannel(REFRESH_SESSION_CHANNEL_NAME);
      sessionChannel.onmessage = (event) => {
        if (!isRefreshSessionMessage(event.data)) return;
        const currentScopeKey = refreshScopeKey(browserTenantRuntime.current().scope);
        // NAN-3548: only a mutation of THIS tab's cookie pair can end it. A
        // sign-in or refresh for another tenant on the pooled host wrote a
        // different pair and must not log this tab out.
        if (!refreshSessionMessageReplacesScope(event.data, currentScopeKey, currentCookieSlot())) return;
        clearAccessToken();
        if (refreshTimeoutRef.current) {
          clearTimeout(refreshTimeoutRef.current);
          refreshTimeoutRef.current = null;
        }
        setPendingTenantSlug(null);
        setState(anonymousState(
          event.data.kind === 'session-replaced'
            ? 'Another organization session replaced this browser session.'
            : 'This browser session is no longer valid. Please sign in again.',
        ));
      };
    } catch {
      // BroadcastChannel not supported
    }

    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
      channel?.close();
      sessionChannel?.close();
    };
  }, [anonymousState, authenticatedState, refreshAuth, handleAuthFailure]);

  // Login with email and password (may return MFA challenge)
  const login = useCallback(async (
    email: string,
    password: string,
    tenantSlug?: string,
  ): Promise<void> => {
    const selectedTenant = tenantSlug === undefined
      ? undefined
      : canonicalTenantSlug(tenantSlug);
    setPendingTenantSlug(selectedTenant ?? null);
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    setMfaPending(false);
    setMfaSetupPending(false);
    setChallengeToken(null);

    try {
      await withBrowserCookieMutationLock(async () => {
        // Use raw fetch to inspect the response shape (may be MFA challenge).
        // The endpoint can write auth cookies on its success path, so it owns
        // the same origin-wide mutation lock as refresh.
        const response = await apiRequest<Record<string, unknown>>('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify(loginRequestBody(email, password, selectedTenant)),
        });

        // Check if MFA is required
        if (response.mfa_required) {
          setChallengeToken(response.challenge_token as string);
          setMfaPending(true);
          setState(prev => ({ ...prev, isLoading: false, error: null }));
          return; // Don't navigate — Login page will show MFA form
        }

        // Check if MFA setup is required (admin-enforced)
        if (response.mfa_setup_required) {
          setChallengeToken(response.challenge_token as string);
          setMfaSetupPending(true);
          setState(prev => ({ ...prev, isLoading: false, error: null }));
          return; // Don't navigate — Login page will redirect to MFA setup
        }

        // Normal login success
        const authResponse = response as unknown as {
          user: User;
          tokens: { access_token: string; refresh_token: string; expires_in: number };
        };
        setAccessToken(authResponse.tokens.access_token, authResponse.tokens.expires_in);
        const userInfo = await apiRequest<User>(
          '/api/auth/me', {}, authResponse.tokens.access_token,
        );

        const nextState = authenticatedState(userInfo, selectedTenant);
        setState(nextState);
        broadcastSessionReplacement(
          refreshScopeKey(nextState.tenantRuntime.scope),
          authenticatedCookieSlot(nextState),
        );
        setPendingTenantSlug(null);

        scheduleTokenRefresh(authResponse.tokens.expires_in);
      }, {
        requireCoordination: selectedTenant !== undefined,
        cookieSlot: selectedTenant === undefined ? ORIGIN_COOKIE_SLOT : tenantCookieSlot(selectedTenant),
      });
    } catch (error) {
      clearAccessToken();
      const message = error instanceof AuthError
        ? error.message
        : 'An unexpected error occurred';

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, [authenticatedState, scheduleTokenRefresh]);

  // Verify MFA challenge (TOTP code or backup code)
  const verifyMfa = useCallback(async (code: string): Promise<void> => {
    if (!challengeToken) throw new Error('No MFA challenge pending');

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      await withBrowserCookieMutationLock(async () => {
        const response = await apiRequest<{
          user: User;
          tokens: { access_token: string; refresh_token: string; expires_in: number };
        }>('/api/auth/mfa/challenge', {
          method: 'POST',
          body: JSON.stringify({
            challenge_token: challengeToken,
            code,
            ...tenantContinuationBody(pendingTenantSlug ?? undefined),
          }),
        });

        setAccessToken(response.tokens.access_token, response.tokens.expires_in);
        const userInfo = await apiRequest<User>(
          '/api/auth/me', {}, response.tokens.access_token,
        );
        setMfaPending(false);
        setMfaSetupPending(false);
        setChallengeToken(null);

        const nextState = authenticatedState(userInfo, pendingTenantSlug ?? undefined);
        setState(nextState);
        broadcastSessionReplacement(
          refreshScopeKey(nextState.tenantRuntime.scope),
          authenticatedCookieSlot(nextState),
        );
        setPendingTenantSlug(null);

        scheduleTokenRefresh(response.tokens.expires_in);
      }, {
        requireCoordination: pendingTenantSlug !== null,
        cookieSlot: pendingTenantSlug === null ? ORIGIN_COOKIE_SLOT : tenantCookieSlot(pendingTenantSlug),
      });
    } catch (error) {
      clearAccessToken();
      const message = error instanceof AuthError
        ? error.message
        : 'Invalid code — please try again';

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, [authenticatedState, challengeToken, pendingTenantSlug, scheduleTokenRefresh]);

  // Hosted-shared MFA step-up on the current session (cookie-carried so the
  // answer's Set-Cookie replaces the session cookies; no bearer on purpose).
  const stepUpMfa = useCallback(async (code: string): Promise<void> => {
    await withBrowserCookieMutationLock(async () => {
      const response = await apiRequest<{
        user: User;
        tokens: { access_token: string; refresh_token: string; expires_in: number };
      }>('/api/auth/shared/mfa/step-up', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      setAccessToken(response.tokens.access_token, response.tokens.expires_in);
      const userInfo = await apiRequest<User>('/api/auth/me', {}, response.tokens.access_token);
      setState(prev => ({ ...prev, user: userInfo, error: null }));
      scheduleTokenRefresh(response.tokens.expires_in);
    }, { requireCoordination: false, cookieSlot: currentCookieSlot() });
  }, [scheduleTokenRefresh]);

  // Cancel MFA challenge (go back to login)
  const cancelMfa = useCallback(() => {
    setMfaPending(false);
    setMfaSetupPending(false);
    setChallengeToken(null);
    setPendingTenantSlug(null);
    setState(prev => ({ ...prev, error: null }));
  }, []);

  // Start a demo session (no credentials needed)
  const loginAsDemo = useCallback(async (displayName?: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await api.demo.createSession(displayName);

      setAccessToken(response.auth.access_token, response.auth.expires_in);

      const demoUser = {
        id: response.auth.user.id,
        email: `demo-${response.session_id}@demo.nano.local`,
        name: response.auth.user.name,
        roles: response.auth.user.roles,
        permissions: response.auth.user.permissions,
        deployment_mode: 'demo' as const,
      };

      // Persist demo session in sessionStorage for page reload survival
      persistDemoSession(response.auth.access_token, response.auth.refresh_token, response.auth.expires_in, demoUser);

      setState(authenticatedState(demoUser));

      scheduleTokenRefresh(response.auth.expires_in);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start demo session';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      throw error;
    }
  }, [authenticatedState, scheduleTokenRefresh]);

  // Claim a demo session by one-time token (from unique link)
  const claimDemoToken = useCallback(async (token: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await api.demo.claimToken(token);

      setAccessToken(response.auth.access_token, response.auth.expires_in);

      const demoUser = {
        id: response.auth.user.id,
        email: `demo-${response.session_id}@demo.nano.local`,
        name: response.auth.user.name,
        roles: response.auth.user.roles,
        permissions: response.auth.user.permissions,
        deployment_mode: 'demo' as const,
      };

      persistDemoSession(response.auth.access_token, response.auth.refresh_token, response.auth.expires_in, demoUser);

      setState(authenticatedState(demoUser));

      scheduleTokenRefresh(response.auth.expires_in);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid or expired demo link';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      throw error;
    }
  }, [authenticatedState, scheduleTokenRefresh]);

  // Initiate OIDC login
  const loginWithOidc = useCallback(async (providerSlug: string, currentPath?: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const redirectUri = `${window.location.origin}/auth/callback/${providerSlug}`;
      // Sanitize returnTo to prevent open redirect attacks
      const returnTo = sanitizeReturnPath(currentPath !== '/login' ? currentPath : undefined);

      const response = await apiRequest<{
        url: string;
        state: string;
      }>(`/api/auth/oidc/${providerSlug}/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`);

      // Store the state token client-side too so the callback page can do a
      // local sanity check before round-tripping. The server-side transaction
      // store (NAN-657) is the actual security boundary; this is just a UX
      // guard against navigating to /auth/callback with stale querystring.
      storeOidcState({
        state: response.state,
        providerSlug,
        redirectUri,
        returnTo,
      });

      // Redirect to OIDC provider
      window.location.href = response.url;
    } catch (error) {
      const message = error instanceof AuthError
        ? error.message
        : 'Failed to initiate SSO login';

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, []);

  // Handle OIDC callback - returns the redirect path instead of navigating
  const handleOidcCallback = useCallback(async (
    providerSlug: string,
    code: string,
    state: string,
  ): Promise<string> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    const storedState = getOidcState();

    // Local sanity check (UX). The server-side transaction store is the real
    // security boundary — it'll reject unknown/expired/replayed states regardless
    // of what we do here.
    if (!storedState || storedState.state !== state) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Invalid authentication state. Please try again.',
      }));
      clearOidcState();
      throw new Error('Invalid authentication state');
    }

    try {
      return await withBrowserCookieMutationLock(async () => {
        const response = await apiRequest<{
          user: User;
          tokens: {
            access_token: string;
            refresh_token: string;
            expires_in: number;
          };
        }>(`/api/auth/oidc/${providerSlug}/callback`, {
          method: 'POST',
          body: JSON.stringify({
            code,
            state,
            redirect_uri: storedState.redirectUri,
          }),
        });

        // Access token in memory; refresh token already set as HttpOnly cookie by backend
        setAccessToken(response.tokens.access_token, response.tokens.expires_in);
        const userInfo = await apiRequest<User>(
          '/api/auth/me', {}, response.tokens.access_token,
        );

        const nextState = authenticatedState(userInfo);
        setState(nextState);
        broadcastSessionReplacement(
          refreshScopeKey(nextState.tenantRuntime.scope),
          authenticatedCookieSlot(nextState),
        );

        scheduleTokenRefresh(response.tokens.expires_in);

        clearOidcState();

        // Return the redirect path instead of navigating. Re-validate returnTo
        // even though it was sanitized on storage (defense in depth).
        return sanitizeReturnPath(storedState.returnTo);
      });
    } catch (error) {
      clearAccessToken();
      const message = error instanceof AuthError
        ? error.message
        : 'SSO authentication failed';

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      clearOidcState();
      throw error;
    }
  }, [authenticatedState, scheduleTokenRefresh]);

  // Logout - returns true when complete, caller handles navigation
  const logout = useCallback(async (): Promise<void> => {
    const token = getAccessToken();
    const runtimeScope = browserTenantRuntime.current().scope;
    const logoutScopeKey = refreshScopeKey(runtimeScope);
    const logoutCookieSlot = cookieSlotForScope(runtimeScope);
    let logoutFailure: unknown;
    let localCleanupComplete = false;

    const clearLocalSession = (notifyOtherTabs = true) => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
        refreshTimeoutRef.current = null;
      }
      clearAccessToken();
      setPendingTenantSlug(null);
      const nextState = anonymousState();
      setState(logoutFailure
        ? {
            ...nextState,
            error: logoutFailure instanceof AuthError
              ? logoutFailure.message
              : 'Logout could not be completed safely. Your local credentials were cleared.',
          }
        : nextState);
      if (notifyOtherTabs) {
        if (runtimeScope.kind === 'enterprise_shared') {
          broadcastTenantSessionRevocation(logoutScopeKey);
        } else {
          broadcastLogout(logoutCookieSlot);
          broadcastSessionInvalidation(logoutScopeKey, logoutCookieSlot);
        }
      }
      localCleanupComplete = true;
    };

    try {
      await withBrowserCookieMutationLock(async () => {
        const currentScopeKey = refreshScopeKey(browserTenantRuntime.current().scope);
        if (!cookieMutationStillOwnsSession(
          logoutScopeKey,
          token,
          currentScopeKey,
          getAccessToken(),
        )) {
          return;
        }
        try {
          // Shared mode revokes this tab's tenant namespace by bearer, with no
          // cookie mutation. Dedicated mode retains its HttpOnly-cookie flow.
          await apiRequest('/api/auth/logout', {
            method: 'POST',
            body: JSON.stringify({}),
          }, token ?? undefined);
        } catch (error) {
          // The server proves the origin-wide cookie now belongs to another
          // authenticated session. This is a stale completion from the old
          // tab, not a logout failure: clearing/broadcasting here would evict
          // the replacement tenant session that correctly won the cookie
          // mutation race.
          if (error instanceof AuthError && error.code === 'session_replaced') {
            clearLocalSession(false);
            return;
          }
          logoutFailure = error;
        }
        // Signal invalidation before releasing the cookie lock so no waiting
        // refresh can rotate or resurrect the just-cleared session.
        clearLocalSession();
      }, {
        requireCoordination: runtimeScope.kind === 'enterprise_shared',
        cookieSlot: logoutCookieSlot,
      });
    } catch (error) {
      logoutFailure = logoutFailure ?? error;
      if (!localCleanupComplete) clearLocalSession();
    }

    if (logoutFailure) {
      throw logoutFailure;
    }
    // Navigation handled by caller on success
  }, [anonymousState]);

  // Permission helpers
  const hasPermission = useCallback((permission: string): boolean => {
    if (!state.user) return false;
    // Admin has all permissions
    if (state.user.permissions.includes('*')) return true;
    return state.user.permissions.includes(permission);
  }, [state.user]);

  const hasAnyPermission = useCallback((permissions: string[]): boolean => {
    if (!state.user) return false;
    if (state.user.permissions.includes('*')) return true;
    return permissions.some(p => state.user!.permissions.includes(p));
  }, [state.user]);

  const hasAllPermissions = useCallback((permissions: string[]): boolean => {
    if (!state.user) return false;
    if (state.user.permissions.includes('*')) return true;
    return permissions.every(p => state.user!.permissions.includes(p));
  }, [state.user]);

  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  const acceptSharedOidcSession = useCallback(async (
    _callbackUser: User,
    expectedTenantSlug: string,
  ): Promise<void> => {
    // The callback itself exposes no credential. While its cookie mutation
    // lock is still held, rotate the new HttpOnly refresh cookie once and keep
    // only the returned short-lived access bearer in this tab's memory. Search
    // is a separate service and intentionally accepts tenant-bound bearer auth,
    // not generic cookie POSTs.
    const response = await apiRequest<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify(tenantContinuationBody(expectedTenantSlug)),
    });
    const user = await apiRequest<User>('/api/auth/me', {}, response.access_token);
    setAccessToken(response.access_token, response.expires_in);
    setPendingTenantSlug(null);
    const nextState = authenticatedState(user, canonicalTenantSlug(expectedTenantSlug));
    setState(nextState);
    broadcastSessionReplacement(
      refreshScopeKey(nextState.tenantRuntime.scope),
      authenticatedCookieSlot(nextState),
    );
    scheduleTokenRefresh(response.expires_in);
  }, [authenticatedState, scheduleTokenRefresh]);

  const discardFailedSharedOidcSession = useCallback((): void => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
      refreshTimeoutRef.current = null;
    }
    clearAccessToken();
    setPendingTenantSlug(null);
    setState(anonymousState());
  }, [anonymousState]);

  const isDemoUser = state.user?.roles?.includes('demo_analyst') ?? false;

  const value: AuthContextType = {
    ...state,
    permissions: state.user?.permissions || [],
    isDemoUser,
    login,
    loginAsDemo,
    claimDemoToken,
    loginWithOidc,
    handleOidcCallback,
    acceptSharedOidcSession,
    discardFailedSharedOidcSession,
    logout,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    refreshAuth,
    clearError,
    mfaPending,
    mfaSetupPending,
    challengeToken,
    pendingTenantSlug,
    verifyMfa,
    cancelMfa,
    stepUpMfa,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    console.error('useAuth called outside AuthProvider. AuthContext value:', AuthContext);
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// ============================================================================
// Utility: Get OIDC state for callback handling
// ============================================================================

export { getOidcState, clearOidcState };
