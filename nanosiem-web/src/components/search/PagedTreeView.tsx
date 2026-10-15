// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import type { TreePageResponse, TimeRange } from '@/lib/api/types';
import { abortableDelay } from '@/lib/abortable-delay';
import { useReportPhase2Status } from './footer-reporter';
import { TreeVisualization, type TreeNode, type TreeConfig } from './TreeVisualization';

interface Props {
  marker: Record<string, unknown>;
  nodes: TreeNode[];
  config: TreeConfig;
  onFilter?: (field: string, value: string) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}
interface PageState {
  key: string; nodes: TreeNode[]; page?: TreePageResponse; jobId?: string;
  loading: boolean; pageLoading: boolean; error?: string;
}
const pathKey = (path: number[]) => JSON.stringify(path);
export function appendTreeChildren(nodes: TreeNode[], path: number[], children: TreeNode[], offset: number, next: number | null): TreeNode[] {
  return nodes.map(node => pathKey(node._page_path ?? []) === pathKey(path)
    ? { ...node, children: offset ? [...node.children, ...children] : children, _next_children_offset: next }
    : { ...node, children: appendTreeChildren(node.children ?? [], path, children, offset, next) });
}
export function PagedTreeView({ marker, nodes, config, ...props }: Props) {
  const pending = marker._tree_pending === true;
  const query = typeof marker._tree_query === 'string' ? marker._tree_query : '';
  const range = marker._tree_time_range as TimeRange | undefined;
  const scopeKey = browserTenantRuntime.current().key;
  const key = JSON.stringify([scopeKey, query, range, marker._tree_run_id]);
  const [state, setState] = useState<PageState | null>(null);
  const owner = useRef<{ key: string; controller: AbortController } | null>(null);
  const requests = useRef(new Set<string>());
  useEffect(() => {
    if (!pending || !query || !range) return;
    const controller = new AbortController();
    const signal = controller.signal;
    owner.current = { key, controller }; requests.current = new Set();
    const current = () => owner.current?.controller === controller && !signal.aborted && browserTenantRuntime.current().key === scopeKey;
    setState({ key, nodes: [], loading: true, pageLoading: false });
    void (async () => {
      try {
        try {
          const page = await api.getTreePage({ query, time_range: range, limit: 25 }, signal);
          if (!current()) return;
          setState({ key, nodes: page.nodes as unknown as TreeNode[], page, loading: true, pageLoading: false });
        } catch { if (!current()) return; }
        const job = await api.searchAsync({ query, time_range: range, limit: 1, skip_histogram: true, skip_field_stats: true, priority: 'analytics' }, undefined, signal);
        if (!current()) return;
        setState(previous => previous?.key === key ? { ...previous, jobId: job.job_id } : previous);
        while (current()) {
          const page = await api.getTreePage({ job_id: job.job_id, limit: 25 }, signal);
          if (!current()) return;
          if (page.status === 'completed') {
            setState({ key, nodes: page.nodes as unknown as TreeNode[], page, jobId: job.job_id, loading: false, pageLoading: false });
            return;
          }
          if (page.status === 'failed' || page.status === 'cancelled') throw new Error(page.error ?? `Tree job ${page.status}`);
          await abortableDelay(750, signal);
        }
      } catch (error) {
        if (current()) setState(previous => previous?.key === key ? { ...previous, loading: false, error: error instanceof Error ? error.message : String(error) } : previous);
      }
    })();
    return () => { controller.abort(); if (owner.current?.controller === controller) owner.current = null; };
  }, [pending, key, query]);
  const active = state?.key === key ? state : null;
  useReportPhase2Status({ loading: pending && (!active || active.loading), settled: !pending || !!active && !active.loading, error: active?.error, totalCount: active?.page && !active.page.preview ? active.page.total_count : undefined });
  const load = async (path: number[], offset: number) => {
    const ownership = owner.current;
    if (!active?.jobId || active.page?.preview || !ownership || ownership.key !== key) return;
    const requestKey = `${pathKey(path)}:${offset}`;
    if (requests.current.has(requestKey)) return;
    requests.current.add(requestKey);
    setState(previous => previous?.key === key ? { ...previous, pageLoading: true, error: undefined } : previous);
    try {
      const page = await api.getTreePage({ job_id: active.jobId, parent_path: path, offset, limit: 25 }, ownership.controller.signal);
      if (owner.current !== ownership || ownership.controller.signal.aborted) return;
      if (page.status !== 'completed') throw new Error(page.error ?? 'Tree page unavailable');
      setState(previous => previous?.key === key ? { ...previous,
        nodes: path.length ? appendTreeChildren(previous.nodes, path, page.nodes as unknown as TreeNode[], offset, page.next_offset) : [...previous.nodes, ...page.nodes as unknown as TreeNode[]],
        page: path.length ? previous.page : page, error: undefined,
      } : previous);
    } catch (error) {
      if (owner.current === ownership && !ownership.controller.signal.aborted) setState(previous => previous?.key === key ? { ...previous, error: error instanceof Error ? error.message : String(error) } : previous);
    } finally {
      if (owner.current === ownership) {
        requests.current.delete(requestKey);
        setState(previous => previous?.key === key ? { ...previous, pageLoading: requests.current.size > 0 } : previous);
      }
    }
  };
  if (!pending) return <TreeVisualization nodes={nodes} config={config} {...props} />;
  return <div className="flex flex-col min-h-0">
    <div role="status" className="px-3 py-2 font-mono text-[10.5px] text-muted-foreground border-b border-border">
      {active?.page?.preview ? 'Bounded 200-row preview; ancestry and counts are provisional. ' : active?.page ? `${active.page.total_roots} roots / ${active.page.total_nodes} nodes in the materialized view. ` : 'Loading first roots… '}
      {active?.loading && 'Exact tree queued or loading… '}
      {active?.page?.source_truncated && !active.page.preview && 'Input or branches were truncated; ancestry beyond retrieved rows is unknown. '}
      {active?.page?.note && `${active.page.note} `}
      {active?.error && <span role="alert">{active.error}</span>}
      {active?.pageLoading && 'Loading tree page…'}
    </div>
    <TreeVisualization key={`${key}:${active?.page?.preview ? 'preview' : 'exact'}`} nodes={active?.nodes ?? []}
      config={(active?.page?.config as unknown as TreeConfig) ?? config} {...props} serverPaged
      onLoadChildren={(node, offset) => { void load(node._page_path ?? [], offset); }} />
    {!active?.page?.preview && active?.page?.next_offset != null && <button disabled={active.pageLoading} className="border-t border-border px-3 py-2 text-[11px] font-mono" onClick={() => void load([], active.page!.next_offset!)}>Load more roots</button>}
  </div>;
}
