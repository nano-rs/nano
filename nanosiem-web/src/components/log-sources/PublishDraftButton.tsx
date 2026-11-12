// SPDX-License-Identifier: AGPL-3.0-or-later
import { Rocket } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

/** NAN-4847 (ported for NAN-4912): what Save and Publish do to incoming events. */
export const SAVE_DRAFT_TOOLTIP = "Save this draft. Incoming events aren't affected until you publish.";
export const PUBLISH_DRAFT_TOOLTIP =
  'Make this draft live for incoming events. The previous version is kept in history.';
export const PUBLISH_NEEDS_VALIDATION_TOOLTIP = 'Validate the parser before you publish.';

/** Publish a log source's draft. Needs a TooltipProvider above it. */
export function PublishDraftButton({
  label,
  className,
  publishing,
  validated,
  onPublish,
}: {
  label: string;
  className?: string;
  publishing: boolean;
  validated: boolean;
  onPublish: () => void;
}) {
  const disabled = publishing || !validated;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* A disabled button fires no pointer events; the span keeps the tooltip reachable. */}
        <span className="inline-flex" tabIndex={disabled ? 0 : undefined}>
          <Button
            size="sm"
            className={cn('h-7 text-[11.5px] gap-1.5', className)}
            disabled={disabled}
            onClick={onPublish}
          >
            {publishing ? <LoadingIcon className="w-3 h-3" /> : <Rocket className="w-3 h-3" />}
            {label}
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent className="text-[11px]">
        {validated ? PUBLISH_DRAFT_TOOLTIP : PUBLISH_NEEDS_VALIDATION_TOOLTIP}
      </TooltipContent>
    </Tooltip>
  );
}
