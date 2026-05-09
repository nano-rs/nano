// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  useReactFlow,
  useNodesState,
  ReactFlowProvider,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { nodeTypes } from './nodes';

interface FlowCanvasProps {
  nodes: Node[];
  edges: Edge[];
}

const defaultEdgeOptions = {
  type: 'smoothstep' as const,
  style: { stroke: 'var(--primary)', strokeWidth: 1.5 },
  animated: false,
};

function FitViewOnChange({ nodes }: { nodes: Node[] }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    const timer = setTimeout(() => fitView({ padding: 0.2 }), 50);
    return () => clearTimeout(timer);
  }, [nodes, fitView]);
  return null;
}

function FlowCanvasInner({ nodes: initialNodes, edges }: FlowCanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);

  // Sync when new nodes come in from the parser (different rule loaded, query edited)
  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  return (
    <div className="w-full h-full [&_.react-flow__attribution]:hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        nodeTypes={nodeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
        maxZoom={2}
      >
        <FitViewOnChange nodes={initialNodes} />
        <Controls
          showInteractive={false}
          className="!bg-card !border-border !shadow-sm [&>button]:!bg-card [&>button]:!border-border [&>button]:!text-card-foreground [&>button:hover]:!bg-muted"
        />
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="var(--border)" />
      </ReactFlow>
    </div>
  );
}

export function FlowCanvas({ nodes, edges }: FlowCanvasProps) {
  return (
    <ReactFlowProvider>
      <FlowCanvasInner nodes={nodes} edges={edges} />
    </ReactFlowProvider>
  );
}
