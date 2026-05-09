// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Convert FlowGraph (parsed nPL stages) into React Flow nodes and edges
 * using dagre for automatic left-to-right layout.
 */

import dagre from '@dagrejs/dagre';
import type { Node, Edge } from '@xyflow/react';
import type { FlowGraph, PipeStage } from './npl-flow-parser';

export interface FlowNodeData extends Record<string, unknown> {
  stage: PipeStage;
}

const NODE_WIDTH = 260;
const NODE_HEIGHT = 90;

/**
 * Build React Flow nodes and edges from a FlowGraph, positioned via dagre.
 */
export function buildFlowGraph(flowGraph: FlowGraph): { nodes: Node<FlowNodeData>[]; edges: Edge[] } {
  const { stages, branches } = flowGraph;

  if (stages.length === 0) {
    return { nodes: [], edges: [] };
  }

  // Build adjacency: default is linear chain
  const edges: Edge[] = [];
  const branchedIndices = new Set<number>();

  // Mark all indices that are part of branches
  for (const branch of branches) {
    for (const path of branch.paths) {
      for (const idx of path) {
        branchedIndices.add(idx);
      }
    }
  }

  // Add branch edges
  for (const branch of branches) {
    for (const path of branch.paths) {
      // Source → first node in path
      edges.push({
        id: `e-${branch.sourceIndex}-${path[0]}`,
        source: `stage-${branch.sourceIndex}`,
        target: `stage-${path[0]}`,
        type: 'smoothstep',
      });

      // Edges within path
      for (let i = 0; i < path.length - 1; i++) {
        edges.push({
          id: `e-${path[i]}-${path[i + 1]}`,
          source: `stage-${path[i]}`,
          target: `stage-${path[i + 1]}`,
          type: 'smoothstep',
        });
      }

      // Last node in path → merge
      edges.push({
        id: `e-${path[path.length - 1]}-${branch.mergeIndex}`,
        source: `stage-${path[path.length - 1]}`,
        target: `stage-${branch.mergeIndex}`,
        type: 'smoothstep',
      });
    }
  }

  // Add linear edges for non-branched consecutive stages
  for (let i = 0; i < stages.length - 1; i++) {
    const currentBranched = branchedIndices.has(i);
    const nextBranched = branchedIndices.has(i + 1);

    // Skip if this edge is handled by a branch
    const isBranchSource = branches.some((b) => b.sourceIndex === i);
    const isMergeTarget = branches.some((b) => b.mergeIndex === i + 1);

    if (isBranchSource) continue; // Branch source → path starts handled above
    if (currentBranched) continue; // Within a branch path, handled above
    if (nextBranched && !isMergeTarget) continue;

    edges.push({
      id: `e-${i}-${i + 1}`,
      source: `stage-${i}`,
      target: `stage-${i + 1}`,
      type: 'smoothstep',
    });
  }

  // Build dagre graph for positioning
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'LR', ranksep: 80, nodesep: 40, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));

  for (const stage of stages) {
    g.setNode(stage.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }

  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  dagre.layout(g);

  // Convert to React Flow nodes
  const nodes: Node<FlowNodeData>[] = stages.map((stage) => {
    const nodeWithPosition = g.node(stage.id);
    return {
      id: stage.id,
      type: 'pipeStage',
      position: {
        x: nodeWithPosition.x - NODE_WIDTH / 2,
        y: nodeWithPosition.y - NODE_HEIGHT / 2,
      },
      data: { stage },
    };
  });

  return { nodes, edges };
}
