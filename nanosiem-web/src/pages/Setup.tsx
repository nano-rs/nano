// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * First-Run Setup Page
 * 
 * Provides a setup wizard for initial system configuration.
 * Creates the first admin account and optionally configures OIDC.
 * 
 * Requirements: 13.1, 13.2, 13.3
 * - 13.1: Display setup wizard when no users exist
 * - 13.2: Require creating an admin account with email and password
 * - 13.3: Optionally allow configuring an OIDC provider
 */

import { useState, FormEvent, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Mail, Lock, User, Loader2, CircleAlert, CircleCheck, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Logo } from '@/components/ui/logo';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

interface SetupStatus {
  initialized: boolean;
  has_users: boolean;
}

export function Setup() {
  const navigate = useNavigate();
  
  // Form state
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isCheckingStatus, setIsCheckingStatus] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  
  // Password validation state
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);

  // Check setup status on mount
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/setup/status`);
        if (response.ok) {
          const status: SetupStatus = await response.json();
          if (status.initialized || status.has_users) {
            // System already initialized, redirect to login
            navigate('/login', { replace: true });
          }
        }
      } catch {
        // If we can't check status, show the setup form anyway
      } finally {
        setIsCheckingStatus(false);
      }
    };

    checkStatus();
  }, [navigate]);

  // Validate password on change
  useEffect(() => {
    const errors: string[] = [];
    
    if (password.length > 0) {
      if (password.length < 12) {
        errors.push('At least 12 characters');
      }
      if (!/[a-z]/.test(password)) {
        errors.push('At least one lowercase letter');
      }
      if (!/[A-Z]/.test(password)) {
        errors.push('At least one uppercase letter');
      }
      if (!/[0-9]/.test(password)) {
        errors.push('At least one number');
      }
      if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('At least one special character');
      }
    }
    
    setPasswordErrors(errors);
  }, [password]);

  // Clear error when inputs change
  useEffect(() => {
    if (error) setError(null);
  }, [email, name, password, confirmPassword]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate inputs
    if (!email.trim()) {
      setError('Email is required');
      return;
    }

    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    if (!password) {
      setError('Password is required');
      return;
    }

    if (passwordErrors.length > 0) {
      setError('Password does not meet requirements');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/setup/initialize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim(),
          name: name.trim(),
          password,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({ message: 'Setup failed' }));
        throw new Error(errorBody.message || errorBody.error || 'Setup failed');
      }

      setSuccess(true);
      
      // Redirect to login after a short delay
      setTimeout(() => {
        navigate('/login', { replace: true });
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Show loading while checking status
  if (isCheckingStatus) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  // Show success message
  if (success) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-green-600 rounded-2xl mb-4">
            <CircleCheck className="w-10 h-10 text-foreground" />
          </div>
          <h1 className="text-2xl font-bold text-foreground mb-2">Setup Complete!</h1>
          <p className="text-muted-foreground mb-4">
            Your admin account has been created. Redirecting to login...
          </p>
          <Loader2 className="w-6 h-6 animate-spin text-primary mx-auto" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <Logo className="w-16 h-16 mx-auto mb-4" size="small" />
          <h1 className="text-2xl text-foreground">Welcome to <span className="font-light" style={{ fontFamily: 'Comfortaa, sans-serif' }}>nano</span></h1>
          <p className="text-muted-foreground mt-2">Let's set up your admin account</p>
        </div>

        {/* Error Alert */}
        {error && (
          <Alert className="mb-6 bg-red-500/10 border-red-500/20">
            <CircleAlert className="h-4 w-4 text-red-500" />
            <AlertDescription className="text-red-200">
              {error}
            </AlertDescription>
          </Alert>
        )}

        {/* Setup Card */}
        <div className="bg-card rounded-2xl border border-border p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Name Field */}
            <div className="space-y-2">
              <Label htmlFor="name" className="text-foreground">
                Full Name
              </Label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  id="name"
                  type="text"
                  placeholder="Admin User"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="pl-10 bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-blue-500"
                  disabled={isSubmitting}
                  autoComplete="name"
                  autoFocus
                />
              </div>
            </div>

            {/* Email Field */}
            <div className="space-y-2">
              <Label htmlFor="email" className="text-foreground">
                Email Address
              </Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  placeholder="admin@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10 bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-blue-500"
                  disabled={isSubmitting}
                  autoComplete="email"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-2">
              <Label htmlFor="password" className="text-foreground">
                Password
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-blue-500"
                  disabled={isSubmitting}
                  autoComplete="new-password"
                />
              </div>
              {/* Password Requirements */}
              {password.length > 0 && passwordErrors.length > 0 && (
                <div className="mt-2 space-y-1">
                  <p className="text-xs text-muted-foreground">Password requirements:</p>
                  {passwordErrors.map((err, i) => (
                    <p key={i} className="text-xs text-red-400 flex items-center gap-1">
                      <span className="w-1 h-1 bg-red-400 rounded-full" />
                      {err}
                    </p>
                  ))}
                </div>
              )}
              {password.length > 0 && passwordErrors.length === 0 && (
                <p className="text-xs text-green-400 flex items-center gap-1 mt-2">
                  <CircleCheck className="w-3 h-3" />
                  Password meets all requirements
                </p>
              )}
            </div>

            {/* Confirm Password Field */}
            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-foreground">
                Confirm Password
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="••••••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="pl-10 bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-blue-500"
                  disabled={isSubmitting}
                  autoComplete="new-password"
                />
              </div>
              {confirmPassword.length > 0 && password !== confirmPassword && (
                <p className="text-xs text-red-400 flex items-center gap-1 mt-1">
                  <span className="w-1 h-1 bg-red-400 rounded-full" />
                  Passwords do not match
                </p>
              )}
              {confirmPassword.length > 0 && password === confirmPassword && password.length > 0 && (
                <p className="text-xs text-green-400 flex items-center gap-1 mt-1">
                  <CircleCheck className="w-3 h-3" />
                  Passwords match
                </p>
              )}
            </div>

            <Button
              type="submit"
              className="w-full bg-primary hover:bg-primary/90 text-foreground"
              disabled={isSubmitting || passwordErrors.length > 0 || password !== confirmPassword}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Creating Account...
                </>
              ) : (
                <>
                  Create Admin Account
                  <ChevronRight className="w-4 h-4 ml-2" />
                </>
              )}
            </Button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-muted-foreground text-sm mt-6">
          This account will have full administrative access to nano
        </p>
      </div>
    </div>
  );
}
