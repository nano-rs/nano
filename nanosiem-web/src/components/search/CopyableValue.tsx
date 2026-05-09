// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useCallback } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyableValueProps {
  /** The value to copy to clipboard */
  value: string;
  /** Optional click handler (e.g. for navigation/drill-down) */
  onClick?: () => void;
  /** Additional classes for the text */
  className?: string;
  /** Override display text (defaults to value) */
  children?: React.ReactNode;
  /** Truncate text with ellipsis when parent constrains width */
  truncate?: boolean;
}

export function CopyableValue({ value, onClick, className, children, truncate: shouldTruncate }: CopyableValueProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }, [value]);

  return (
    <span className={`inline-flex items-center gap-0.5 group/copy${shouldTruncate ? ' min-w-0 max-w-full' : ''}`}>
      <span
        className={`${shouldTruncate ? 'truncate ' : ''}${onClick ? 'cursor-pointer ' : ''}${className || ''}`}
        onClick={onClick}
      >
        {children || value}
      </span>
      <button
        className="opacity-0 group-hover/copy:opacity-60 hover:opacity-100! transition-opacity p-0 h-auto shrink-0"
        onClick={handleCopy}
        title="Copy"
      >
        {copied
          ? <Check className="h-3 w-3 text-green-500" />
          : <Copy className="h-3 w-3" />
        }
      </button>
    </span>
  );
}
