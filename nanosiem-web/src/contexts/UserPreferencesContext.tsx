// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * User Preferences Context
 *
 * Provides user preferences state and methods throughout the application.
 * Manages query mode preference (Standard PPL vs Advanced SQL).
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { useAuth, QueryMode, TimeRangePreset, LandingPage } from './AuthContext';

// ============================================================================
// Types
// ============================================================================

export type SearchHubStyle = 'popover' | 'drawer';

export interface UserPreferences {
  preferred_query_mode: QueryMode;
  default_time_range: TimeRangePreset;
  search_hub_style: SearchHubStyle;
  landing_page: LandingPage;
}

export interface UserPreferencesContextType {
  preferences: UserPreferences;
  queryMode: QueryMode;
  defaultTimeRange: TimeRangePreset;
  searchHubStyle: SearchHubStyle;
  landingPage: LandingPage;
  isLoading: boolean;
  error: string | null;
  setQueryMode: (mode: QueryMode) => Promise<void>;
  setDefaultTimeRange: (range: TimeRangePreset) => Promise<void>;
  setSearchHubStyle: (style: SearchHubStyle) => Promise<void>;
  setLandingPage: (page: LandingPage) => Promise<void>;
  refreshPreferences: () => Promise<void>;
}

const defaultPreferences: UserPreferences = {
  preferred_query_mode: 'standard',
  default_time_range: 'last_hour',
  search_hub_style: 'popover',
  landing_page: 'home',
};

// ============================================================================
// Context
// ============================================================================

const UserPreferencesContext = createContext<UserPreferencesContextType | undefined>(undefined);

// ============================================================================
// Provider Component
// ============================================================================

interface UserPreferencesProviderProps {
  children: React.ReactNode;
}

export function UserPreferencesProvider({ children }: UserPreferencesProviderProps) {
  const { user, isAuthenticated } = useAuth();
  const [preferences, setPreferences] = useState<UserPreferences>(defaultPreferences);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize preferences from user info
  useEffect(() => {
    if (user) {
      setPreferences(prev => ({
        ...prev,
        preferred_query_mode: user.preferred_query_mode || 'standard',
        default_time_range: user.default_time_range || 'last_hour',
        search_hub_style: (user as { search_hub_style?: SearchHubStyle }).search_hub_style || 'popover',
        landing_page: user.landing_page || 'home',
      }));
    } else if (!isAuthenticated) {
      setPreferences(defaultPreferences);
    }
  }, [user, isAuthenticated]);

  // Fetch preferences from API
  const refreshPreferences = useCallback(async () => {
    if (!isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await api.getUserPreferences();
      setPreferences(response);
    } catch (err) {
      console.error('Failed to fetch preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch preferences');
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  // Update query mode
  const setQueryMode = useCallback(async (mode: QueryMode) => {
    if (!isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await api.updateUserPreferences({
        preferred_query_mode: mode,
      });
      setPreferences(response);
    } catch (err) {
      console.error('Failed to update preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to update preferences');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  // Update default time range
  const setDefaultTimeRange = useCallback(async (range: TimeRangePreset) => {
    if (!isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await api.updateUserPreferences({
        default_time_range: range,
      });
      setPreferences(response);
    } catch (err) {
      console.error('Failed to update preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to update preferences');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  // Update search hub style
  const setSearchHubStyle = useCallback(async (style: SearchHubStyle) => {
    if (!isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await api.updateUserPreferences({
        search_hub_style: style,
      });
      setPreferences(response);
    } catch (err) {
      console.error('Failed to update preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to update preferences');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  // Update landing page
  const setLandingPage = useCallback(async (page: LandingPage) => {
    if (!isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await api.updateUserPreferences({
        landing_page: page,
      });
      setPreferences(response);
    } catch (err) {
      console.error('Failed to update preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to update preferences');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  const value: UserPreferencesContextType = {
    preferences,
    queryMode: preferences.preferred_query_mode,
    defaultTimeRange: preferences.default_time_range,
    searchHubStyle: preferences.search_hub_style,
    landingPage: preferences.landing_page,
    isLoading,
    error,
    setQueryMode,
    setDefaultTimeRange,
    setSearchHubStyle,
    setLandingPage,
    refreshPreferences,
  };

  return (
    <UserPreferencesContext.Provider value={value}>
      {children}
    </UserPreferencesContext.Provider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useUserPreferences(): UserPreferencesContextType {
  const context = useContext(UserPreferencesContext);
  if (context === undefined) {
    throw new Error('useUserPreferences must be used within a UserPreferencesProvider');
  }
  return context;
}

// Re-export types for convenience
export type { QueryMode, TimeRangePreset, LandingPage };
