// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Protected Route Component
 * 
 * Wraps routes that require authentication and optionally specific permissions.
 * Redirects to login if not authenticated, shows forbidden if lacking permissions.
 * 
 * Requirements: 10.4
 * - Redirect to login if not authenticated
 * - Check permissions for route access
 */

import { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Loader2, ShieldX } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';

interface ProtectedRouteProps {
  children: ReactNode;
  /** Single permission required to access this route */
  permission?: string;
  /** Multiple permissions - user needs ANY of these */
  anyPermission?: string[];
  /** Multiple permissions - user needs ALL of these */
  allPermissions?: string[];
  /** Custom fallback component when permission denied */
  fallback?: ReactNode;
}

export function ProtectedRoute({
  children,
  permission,
  anyPermission,
  allPermissions,
  fallback,
}: ProtectedRouteProps) {
  const location = useLocation();
  const { isAuthenticated, isLoading, hasPermission, hasAnyPermission, hasAllPermissions } = useAuth();

  // Show loading while checking auth state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }

  // Check permissions
  let hasRequiredPermission = true;

  if (permission) {
    hasRequiredPermission = hasPermission(permission);
  } else if (anyPermission && anyPermission.length > 0) {
    hasRequiredPermission = hasAnyPermission(anyPermission);
  } else if (allPermissions && allPermissions.length > 0) {
    hasRequiredPermission = hasAllPermissions(allPermissions);
  }

  // Show forbidden if lacking permissions
  if (!hasRequiredPermission) {
    if (fallback) {
      return <>{fallback}</>;
    }

    return <ForbiddenPage />;
  }

  return <>{children}</>;
}

/**
 * Default Forbidden Page
 */
function ForbiddenPage() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="text-center max-w-md">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-red-500/10 rounded-2xl mb-6">
          <ShieldX className="w-10 h-10 text-red-500" />
        </div>
        
        <h1 className="text-2xl font-bold text-foreground mb-2">
          Access Denied
        </h1>
        
        <p className="text-muted-foreground mb-6">
          You don't have permission to access this page.
          {user && (
            <span className="block mt-2 text-sm">
              Signed in as <span className="text-foreground">{user.email}</span>
            </span>
          )}
        </p>

        <div className="flex gap-3 justify-center">
          <Button
            variant="outline"
            onClick={() => window.history.back()}
            className="bg-transparent border-border text-foreground hover:bg-accent/50"
          >
            Go Back
          </Button>
          <Button
            onClick={() => window.location.href = '/'}
            className="bg-primary hover:bg-primary/90 text-foreground"
          >
            Go to Home
          </Button>
        </div>
      </div>
    </div>
  );
}

/**
 * Higher-order component for permission-based rendering
 */
interface RequirePermissionProps {
  children: ReactNode;
  permission?: string;
  anyPermission?: string[];
  allPermissions?: string[];
  fallback?: ReactNode;
}

export function RequirePermission({
  children,
  permission,
  anyPermission,
  allPermissions,
  fallback = null,
}: RequirePermissionProps) {
  const { hasPermission, hasAnyPermission, hasAllPermissions, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <>{fallback}</>;
  }

  let hasRequired = true;

  if (permission) {
    hasRequired = hasPermission(permission);
  } else if (anyPermission && anyPermission.length > 0) {
    hasRequired = hasAnyPermission(anyPermission);
  } else if (allPermissions && allPermissions.length > 0) {
    hasRequired = hasAllPermissions(allPermissions);
  }

  if (!hasRequired) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
