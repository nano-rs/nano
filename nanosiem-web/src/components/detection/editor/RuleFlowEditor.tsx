// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState, useEffect } from 'react';
import { parseNplFlow } from '@/lib/npl-flow-parser';
import { buildFlowGraph } from '@/lib/npl-flow-graph';
import { FlowCanvas } from './flow/FlowCanvas';
import { GitMerge } from 'lucide-react';

interface RuleFlowEditorProps {
  query: string;
}

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export default function RuleFlowEditor({ query }: RuleFlowEditorProps) {
  const debouncedQuery = useDebounce(query, 300);

  const { nodes, edges } = useMemo(() => {
    const flowGraph = parseNplFlow(debouncedQuery);
    return buildFlowGraph(flowGraph);
  }, [debouncedQuery]);

  if (!debouncedQuery.trim()) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-muted-foreground gap-3">
        <GitMerge className="w-10 h-10 opacity-30" />
        <p className="text-sm">Write a detection query to see its flow</p>
      </div>
    );
  }

  return (
    <div className="w-full h-full">
      <FlowCanvas nodes={nodes} edges={edges} />
    </div>
  );
}
