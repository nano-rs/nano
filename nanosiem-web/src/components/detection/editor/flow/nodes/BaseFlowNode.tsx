// SPDX-License-Identifier: AGPL-3.0-or-later

import { memo, useState, useCallback, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Database,
  Filter,
  BarChart3,
  Layers,
  ShieldAlert,
  Table2,
  Wand2,
  ArrowUpDown,
  LineChart,
  Workflow,
} from 'lucide-react';
import type { StageCategory } from '@/lib/npl-flow-parser';
import type { FlowNodeData } from '@/lib/npl-flow-graph';

const CATEGORY_CONFIG: Record<
  StageCategory,
  { icon: React.ElementType; color: string; label: string }
> = {
  source: { icon: Database, color: 'var(--accent-green)', label: 'Source' },
  filter: { icon: Filter, color: 'var(--accent-yellow)', label: 'Filter' },
  aggregation: { icon: BarChart3, color: 'var(--accent-blue)', label: 'Aggregation' },
  enrichment: { icon: Layers, color: 'var(--accent-purple)', label: 'Enrichment' },
  'risk-scoring': { icon: ShieldAlert, color: 'var(--destructive)', label: 'Risk Scoring' },
  output: { icon: Table2, color: 'var(--accent-cyan)', label: 'Output' },
  transform: { icon: Wand2, color: 'var(--accent-orange)', label: 'Transform' },
  shaping: { icon: ArrowUpDown, color: 'var(--muted-foreground)', label: 'Shaping' },
  visualization: { icon: LineChart, color: 'var(--accent-light-blue)', label: 'Visualization' },
  advanced: { icon: Workflow, color: 'var(--accent-purple)', label: 'Advanced' },
};

function BaseFlowNode({ data }: NodeProps) {
  const { stage } = data as FlowNodeData;
  const config = CATEGORY_CONFIG[stage.category] || CATEGORY_CONFIG.advanced;
  const Icon = config.icon;
  const [open, setOpen] = useState(false);
  const nodeRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLDivElement>(null);
  const [detailPos, setDetailPos] = useState({ top: 0, left: 0 });

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setOpen((prev) => !prev);
  }, []);

  // Position the detail panel next to the node in viewport coordinates
  useEffect(() => {
    if (!open || !nodeRef.current) return;
    const rect = nodeRef.current.getBoundingClientRect();
    setDetailPos({ top: rect.top, left: rect.right + 8 });
  }, [open]);

  // Close on outside click or scroll
  useEffect(() => {
    if (!open) return;
    const handleClose = (e: MouseEvent) => {
      if (
        detailRef.current && !detailRef.current.contains(e.target as Node) &&
        nodeRef.current && !nodeRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    const handleScroll = () => setOpen(false);
    document.addEventListener('mousedown', handleClose);
    document.addEventListener('wheel', handleScroll, { passive: true });
    return () => {
      document.removeEventListener('mousedown', handleClose);
      document.removeEventListener('wheel', handleScroll);
    };
  }, [open]);

  return (
    <>
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !border-border !bg-muted-foreground" />
      <div
        ref={nodeRef}
        onContextMenu={handleContextMenu}
        className="bg-card border border-border rounded-lg px-3 py-2.5 w-[260px] shadow-sm hover:shadow-md transition-shadow"
        style={{ borderLeftWidth: 3, borderLeftColor: config.color }}
      >
        <div className="flex items-center gap-2 mb-1">
          <div
            className="flex items-center justify-center w-5 h-5 rounded"
            style={{ backgroundColor: `color-mix(in srgb, ${config.color} 15%, transparent)` }}
          >
            <Icon className="w-3 h-3" style={{ color: config.color }} />
          </div>
          <span
            className="text-[10px] font-medium uppercase tracking-wider"
            style={{ color: config.color }}
          >
            {config.label}
          </span>
        </div>
        <div className="text-xs font-medium text-card-foreground truncate">
          {stage.label || stage.command}
        </div>
        {stage.description && stage.description !== stage.label && (
          <div className="text-[10px] text-muted-foreground truncate mt-0.5">
            {stage.description}
          </div>
        )}
      </div>
      {open && createPortal(
        <div
          ref={detailRef}
          className="fixed z-[9999] max-w-[400px] p-3 bg-popover border border-border rounded-lg shadow-lg"
          style={{ top: detailPos.top, left: detailPos.left }}
        >
          <div className="flex items-center gap-2 mb-2">
            <Icon className="w-3.5 h-3.5" style={{ color: config.color }} />
            <span className="text-xs font-medium" style={{ color: config.color }}>
              {config.label}
            </span>
            <span className="text-[10px] text-muted-foreground">Stage {stage.index + 1}</span>
          </div>
          <pre className="text-xs text-card-foreground whitespace-pre-wrap break-words font-mono bg-muted/30 rounded-md p-2">
            {stage.rawText}
          </pre>
        </div>,
        document.body
      )}
      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !border-border !bg-muted-foreground" />
    </>
  );
}

export default memo(BaseFlowNode);
