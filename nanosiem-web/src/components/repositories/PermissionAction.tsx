// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { ActionAccess } from './repository-action-policy';

export function PermissionAction({
  access,
  children,
}: {
  access: ActionAccess;
  children: ReactNode;
}) {
  if (access.allowed) return children;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="inline-flex cursor-not-allowed"
          role="group"
          tabIndex={0}
          aria-label={access.reason ?? undefined}
        >
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent>{access.reason}</TooltipContent>
    </Tooltip>
  );
}
