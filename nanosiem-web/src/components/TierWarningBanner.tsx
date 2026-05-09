// SPDX-License-Identifier: AGPL-3.0-or-later

import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle } from 'lucide-react';
import type { TierWarning } from '@/lib/api/types';

interface TierWarningBannerProps {
  warnings: TierWarning[];
  className?: string;
}

/**
 * Displays proactive warnings when resources are approaching tier limits.
 * Only renders when there are active warnings (80%+ usage).
 */
export function TierWarningBanner({ warnings, className }: TierWarningBannerProps) {
  if (warnings.length === 0) return null;

  return (
    <div className={className}>
      {warnings.map((warning) => (
        <Alert key={warning.resource} variant="warning" className="mb-2">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between">
            <span>{warning.message}</span>
            <span className="text-xs font-medium ml-4 whitespace-nowrap">
              {warning.percent_used}% used
            </span>
          </AlertDescription>
        </Alert>
      ))}
    </div>
  );
}
