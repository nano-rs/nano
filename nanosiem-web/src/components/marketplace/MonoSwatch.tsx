// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';

const CATEGORY_TONE: Record<string, string> = {
  data: 'oklch(72% 0.18 28)',
  agent: 'oklch(80% 0.13 78)',
  identity: 'oklch(70% 0.16 160)',
  collector: 'oklch(72% 0.14 230)',
  security: 'oklch(74% 0.16 290)',
};

export function getCategoryTone(category: string): string {
  return CATEGORY_TONE[category] || CATEGORY_TONE.data;
}

interface MonoSwatchProps {
  /** Single character to render (typically first letter of integration name) */
  ch: string;
  /** OKLCH color string. Use {@link getCategoryTone} for category default. */
  tone: string;
  /** Pixel size of the swatch (square). */
  size?: number;
  className?: string;
}

export function MonoSwatch({ ch, tone, size = 38, className }: MonoSwatchProps) {
  return (
    <div
      className={cn('rounded-md flex items-center justify-center shrink-0 font-semibold relative overflow-hidden border', className)}
      style={{
        width: size,
        height: size,
        background: `color-mix(in oklab, ${tone} 14%, transparent)`,
        borderColor: `color-mix(in oklab, ${tone} 32%, transparent)`,
        color: tone,
        fontSize: size * 0.46,
      }}
    >
      <span
        className="absolute inset-0"
        style={{
          background: `radial-gradient(120% 80% at 30% 0%, color-mix(in oklab, ${tone} 14%, transparent), transparent)`,
        }}
      />
      <span className="relative tracking-tight">{ch}</span>
    </div>
  );
}
