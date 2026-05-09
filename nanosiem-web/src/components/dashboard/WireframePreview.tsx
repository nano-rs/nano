// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';

export type WireframeKind = 'bar' | 'timechart' | 'stat' | 'pie' | 'table' | 'topN' | 'heatmap' | 'gauge' | 'area';
export type WireframeCell = { w: number; k: WireframeKind };
export type WireframeSpec = WireframeCell[][];

interface WireframePreviewProps {
  spec: WireframeSpec;
  height?: number;
  className?: string;
}

export function WireframePreview({ spec, height = 84, className }: WireframePreviewProps) {
  if (!spec.length) return null;
  return (
    <div className={cn('w-full flex flex-col gap-[3px]', className)} style={{ height }}>
      {spec.map((row, ri) => {
        const total = row.reduce((s, c) => s + c.w, 0);
        return (
          <div key={ri} className="flex-1 flex gap-[3px] min-h-0">
            {row.map((cell, ci) => (
              <div
                key={ci}
                className="rounded-[3px] bg-primary/[0.07] border border-primary/20 flex items-center justify-center overflow-hidden text-primary/70"
                style={{ flex: cell.w / total }}
              >
                <MiniGlyph kind={cell.k} />
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

function MiniGlyph({ kind }: { kind: WireframeKind }) {
  const stroke = 'currentColor';
  switch (kind) {
    case 'bar':
      return (
        <svg viewBox="0 0 24 18" className="w-[60%] h-[60%]" fill="none" stroke={stroke} strokeWidth="1.2">
          <line x1="4" y1="14" x2="20" y2="14" />
          <rect x="5" y="10" width="2.5" height="4" fill="currentColor" />
          <rect x="9" y="7" width="2.5" height="7" fill="currentColor" />
          <rect x="13" y="4" width="2.5" height="10" fill="currentColor" />
          <rect x="17" y="9" width="2.5" height="5" fill="currentColor" />
        </svg>
      );
    case 'timechart':
    case 'area':
      return (
        <svg viewBox="0 0 28 16" className="w-[70%] h-[60%]" fill="none" stroke={stroke} strokeWidth="1.2">
          <polyline points="2,12 6,9 10,11 14,6 18,8 22,4 26,7" />
        </svg>
      );
    case 'table':
      return (
        <svg viewBox="0 0 24 16" className="w-[70%] h-[60%]" fill="none" stroke={stroke} strokeWidth="1">
          <line x1="2" y1="4" x2="22" y2="4" />
          <line x1="2" y1="8" x2="22" y2="8" />
          <line x1="2" y1="12" x2="22" y2="12" />
        </svg>
      );
    case 'stat':
      return (
        <svg viewBox="0 0 20 14" className="w-[60%] h-[60%]" fill="none" stroke={stroke} strokeWidth="1.3">
          <path d="M2 9 Q6 6 10 8 T18 5" />
        </svg>
      );
    case 'pie':
      return (
        <svg viewBox="0 0 20 20" className="w-[60%] h-[60%]">
          <circle cx="10" cy="10" r="6" fill="none" stroke="currentColor" strokeWidth="1.3" />
          <path d="M10 4 A6 6 0 0 1 16 10 L10 10 Z" fill="currentColor" opacity="0.6" />
        </svg>
      );
    case 'gauge':
      return (
        <svg viewBox="0 0 24 14" className="w-[70%] h-[60%]" fill="none" stroke={stroke} strokeWidth="1.3">
          <path d="M3 12 A9 9 0 0 1 21 12" />
          <line x1="12" y1="12" x2="18" y2="5" />
        </svg>
      );
    case 'heatmap':
      return (
        <svg viewBox="0 0 24 14" className="w-[75%] h-[70%]">
          {Array.from({ length: 6 }).flatMap((_, r) =>
            Array.from({ length: 10 }).map((_, c) => (
              <rect
                key={`${r}-${c}`}
                x={2 + c * 2}
                y={2 + r * 2}
                width="1.6"
                height="1.6"
                fill="currentColor"
                opacity={0.15 + ((r * c) % 7) * 0.12}
              />
            )),
          )}
        </svg>
      );
    case 'topN':
      return (
        <svg viewBox="0 0 28 16" className="w-[80%] h-[70%]" fill="none" stroke={stroke} strokeWidth="0.9">
          {[2, 5, 8, 11].map((y, i) => (
            <g key={i}>
              <line x1="3" y1={y} x2="9" y2={y} />
              <rect x="11" y={y - 0.8} width={14 - i * 3} height="1.6" fill="currentColor" opacity={0.6 - i * 0.1} />
            </g>
          ))}
        </svg>
      );
    default:
      return <div className="w-2 h-2 rounded-sm bg-primary/40" />;
  }
}

const RECIPES: WireframeSpec[] = [
  [[{ w: 1, k: 'bar' }, { w: 1, k: 'timechart' }, { w: 1, k: 'stat' }, { w: 1, k: 'pie' }],
   [{ w: 2, k: 'table' }, { w: 2, k: 'topN' }],
   [{ w: 1, k: 'area' }, { w: 1, k: 'heatmap' }, { w: 2, k: 'table' }]],
  [[{ w: 2, k: 'timechart' }, { w: 1, k: 'stat' }, { w: 1, k: 'stat' }],
   [{ w: 1, k: 'bar' }, { w: 3, k: 'table' }],
   [{ w: 2, k: 'heatmap' }, { w: 2, k: 'topN' }]],
  [[{ w: 4, k: 'heatmap' }],
   [{ w: 1, k: 'gauge' }, { w: 1, k: 'stat' }, { w: 2, k: 'timechart' }],
   [{ w: 2, k: 'table' }, { w: 2, k: 'bar' }]],
  [[{ w: 2, k: 'timechart' }, { w: 2, k: 'topN' }],
   [{ w: 1, k: 'stat' }, { w: 1, k: 'stat' }, { w: 1, k: 'stat' }, { w: 1, k: 'stat' }],
   [{ w: 4, k: 'table' }]],
  [[{ w: 3, k: 'timechart' }, { w: 1, k: 'stat' }],
   [{ w: 2, k: 'bar' }, { w: 2, k: 'pie' }],
   [{ w: 4, k: 'table' }]],
  [[{ w: 1, k: 'gauge' }, { w: 3, k: 'area' }],
   [{ w: 2, k: 'bar' }, { w: 2, k: 'table' }]],
  [[{ w: 2, k: 'bar' }, { w: 2, k: 'topN' }],
   [{ w: 1, k: 'stat' }, { w: 1, k: 'stat' }, { w: 2, k: 'timechart' }],
   [{ w: 4, k: 'table' }]],
];

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function trimRecipeToCount(recipe: WireframeSpec, panelCount: number): WireframeSpec {
  const out: WireframeSpec = [];
  let remaining = Math.max(1, panelCount);
  for (const row of recipe) {
    if (remaining <= 0) break;
    const take = Math.min(row.length, remaining);
    out.push(row.slice(0, take));
    remaining -= take;
  }
  return out.length ? out : recipe.slice(0, 1);
}

export function synthesizePreview(seed: string, panelCount: number): WireframeSpec {
  if (panelCount <= 0) {
    return [[{ w: 4, k: 'stat' }]];
  }
  const recipe = RECIPES[hashString(seed) % RECIPES.length];
  return trimRecipeToCount(recipe, panelCount);
}
