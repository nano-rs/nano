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
import { setAccessToken, getAccessToken, clearAccessToken, persistDemoSession, restoreDemoSession, getDemoRefreshToken } from '../lib/auth-token';

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
}

export interface AuthContextType extends AuthState {
  permissions: string[];
  isDemoUser: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginAsDemo: (displayName?: string) => Promise<void>;
  claimDemoToken: (token: string) => Promise<void>;
  loginWithOidc: (providerSlug: string, currentPath?: string) => Promise<void>;
  handleOidcCallback: (
    providerSlug: string,
    code: string,
    state: string,
  ) => Promise<string>;
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
  verifyMfa: (code: string) => Promise<void>;
  cancelMfa: () => void;
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
 * Validates that a return path is safe for redirection.
 * Prevents open redirect vulnerabilities by ensuring the path:
 * - Starts with a single forward slash (relative path)
 * - Does not contain protocol indicators
 * - Does not use protocol-relative URLs (//example.com)
 */
function isValidReturnPath(path: string): boolean {
  // Must start with exactly one forward slash (not //)
  if (!path.startsWith('/') || path.startsWith('//')) {
    return false;
  }

  // Must not contain protocol indicators
  if (path.includes(':')) {
    return false;
  }

  // Must not contain backslashes (Windows path or encoding tricks)
  if (path.includes('\\')) {
    return false;
  }

  // Must not contain encoded characters that could bypass validation
  // Check for %2f (/) %5c (\) %3a (:) encoded
  const lowerPath = path.toLowerCase();
  if (lowerPath.includes('%2f') || lowerPath.includes('%5c') || lowerPath.includes('%3a')) {
    return false;
  }

  return true;
}

/**
 * Sanitizes a return path, returning '/' if invalid
 */
function sanitizeReturnPath(path: string | undefined): string {
  if (!path || !isValidReturnPath(path)) {
    return '/';
  }
  return path;
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
    credentials: 'include',
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
    return {} as T;
  }

  return response.json();
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

function broadcastLogout(): void {
  try {
    const channel = new BroadcastChannel(AUTH_CHANNEL_NAME);
    channel.postMessage({ type: 'logout' });
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
  });

  // MFA state
  const [mfaPending, setMfaPending] = useState(false);
  const [mfaSetupPending, setMfaSetupPending] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);

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
        await refreshAuth();
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
        const body = demoRefreshToken
          ? JSON.stringify({ refresh_token: demoRefreshToken })
          : JSON.stringify({});

        const response = await apiRequest<{
          access_token: string;
          refresh_token: string;
          expires_in: number;
        }>('/api/auth/refresh', {
          method: 'POST',
          body,
        });

        setAccessToken(response.access_token, response.expires_in);

        // Get current user info
        const userInfo = await apiRequest<User>('/api/auth/me', {}, response.access_token);

        // Update demo session with new tokens
        if (demoRefreshToken) {
          persistDemoSession(response.access_token, response.refresh_token, response.expires_in, userInfo);
        }

        setState({
          user: userInfo,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });

        scheduleTokenRefresh(response.expires_in);
        return true;
      } catch {
        clearAccessToken();
        setState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        });
        return false;
      } finally {
        refreshPromiseRef.current = null;
      }
    };

    refreshPromiseRef.current = doRefresh();
    return refreshPromiseRef.current;
  }, [scheduleTokenRefresh]);

  // Handle auth failure from API client (401 that couldn't be refreshed)
  const handleAuthFailure = useCallback(() => {
    // Clear any scheduled refresh
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
      refreshTimeoutRef.current = null;
    }

    clearAccessToken();

    // Update state to logged out
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: 'Session expired. Please log in again.',
    });
  }, []);

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
      if (window.location.pathname.startsWith('/auth/callback')) {
        setState(prev => ({ ...prev, isLoading: false }));
        return;
      }

      // Restore demo session from localStorage (survives page reloads)
      const demoSession = restoreDemoSession();
      if (demoSession) {
        setAccessToken(demoSession.accessToken, 900); // re-set in memory
        setState({
          user: demoSession.user as User,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        scheduleTokenRefresh(900);
        return;
      }

      // Attempt silent refresh via HttpOnly cookie
      await refreshAuth();
    };

    initAuth();

    // Listen for logout events from other tabs
    let channel: BroadcastChannel | null = null;
    try {
      channel = new BroadcastChannel(AUTH_CHANNEL_NAME);
      channel.onmessage = (event) => {
        if (event.data?.type === 'logout') {
          clearAccessToken();
          if (refreshTimeoutRef.current) {
            clearTimeout(refreshTimeoutRef.current);
            refreshTimeoutRef.current = null;
          }
          setState({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
          });
        }
      };
    } catch {
      // BroadcastChannel not supported
    }

    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
      channel?.close();
    };
  }, [refreshAuth, handleAuthFailure]);

  // Login with email and password (may return MFA challenge)
  const login = useCallback(async (email: string, password: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    setMfaPending(false);
    setMfaSetupPending(false);
    setChallengeToken(null);

    try {
      // Use raw fetch to inspect the response shape (may be MFA challenge)
      const response = await apiRequest<Record<string, unknown>>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
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

      setState({
        user: authResponse.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      scheduleTokenRefresh(authResponse.tokens.expires_in);
    } catch (error) {
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
  }, [scheduleTokenRefresh]);

  // Verify MFA challenge (TOTP code or backup code)
  const verifyMfa = useCallback(async (code: string): Promise<void> => {
    if (!challengeToken) throw new Error('No MFA challenge pending');

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiRequest<{
        user: User;
        tokens: { access_token: string; refresh_token: string; expires_in: number };
      }>('/api/auth/mfa/challenge', {
        method: 'POST',
        body: JSON.stringify({ challenge_token: challengeToken, code }),
      });

      setAccessToken(response.tokens.access_token, response.tokens.expires_in);
      setMfaPending(false);
      setMfaSetupPending(false);
      setChallengeToken(null);

      setState({
        user: response.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      scheduleTokenRefresh(response.tokens.expires_in);
    } catch (error) {
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
  }, [challengeToken, scheduleTokenRefresh]);

  // Cancel MFA challenge (go back to login)
  const cancelMfa = useCallback(() => {
    setMfaPending(false);
    setMfaSetupPending(false);
    setChallengeToken(null);
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
      };

      // Persist demo session in sessionStorage for page reload survival
      persistDemoSession(response.auth.access_token, response.auth.refresh_token, response.auth.expires_in, demoUser);

      setState({
        user: demoUser,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      scheduleTokenRefresh(response.auth.expires_in);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start demo session';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      throw error;
    }
  }, [scheduleTokenRefresh]);

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
      };

      persistDemoSession(response.auth.access_token, response.auth.refresh_token, response.auth.expires_in, demoUser);

      setState({
        user: demoUser,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      scheduleTokenRefresh(response.auth.expires_in);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid or expired demo link';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      throw error;
    }
  }, [scheduleTokenRefresh]);

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

      setState({
        user: response.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      scheduleTokenRefresh(response.tokens.expires_in);

      clearOidcState();

      // Return the redirect path instead of navigating
      // Re-validate returnTo even though it was sanitized on storage (defense in depth)
      return sanitizeReturnPath(storedState.returnTo);
    } catch (error) {
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
  }, [scheduleTokenRefresh]);

  // Logout - returns true when complete, caller handles navigation
  const logout = useCallback(async (): Promise<void> => {
    const token = getAccessToken();

    try {
      // Empty body — refresh token is in the HttpOnly cookie
      await apiRequest('/api/auth/logout', {
        method: 'POST',
        body: JSON.stringify({}),
      }, token ?? undefined);
    } catch {
      // Ignore logout errors, clear local state anyway
    }

    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
    }

    clearAccessToken();
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });

    // Notify other tabs
    broadcastLogout();

    // Navigation handled by caller
  }, []);

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
    logout,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    refreshAuth,
    clearError,
    mfaPending,
    mfaSetupPending,
    challengeToken,
    verifyMfa,
    cancelMfa,
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
