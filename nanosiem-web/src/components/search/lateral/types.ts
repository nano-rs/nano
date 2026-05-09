// SPDX-License-Identifier: AGPL-3.0-or-later

// Shape returned by the backend `_lateral_graph` payload (NAN-396).
// Mirrors `nanosiem-core/src/search/service/lateral_graph.rs` serialisation.

export type LateralBand = 'critical' | 'high' | 'medium' | 'low';

export type LateralRole =
  | 'seed'
  | 'identity'
  | 'pivot'
  | 'spread'
  | 'tooling'
  | 'crown'
  | 'crown-jewel'
  | 'dead-end'
  | 'edge';

export type LateralNodeType = 'host' | 'user' | 'ip' | 'process';

export type LateralMethodId =
  | 'auth-rdp'
  | 'auth-smb'
  | 'auth-kerberos'
  | 'auth-winrm'
  | 'network-smb'
  | 'network-rdp'
  | 'network-winrm'
  | 'network-other'
  | 'process-psexec'
  | 'process-wmic'
  | 'process-psrem';

export type LateralMethodGroup = 'auth' | 'network' | 'process';

export interface LateralNode {
  id: string;
  type: LateralNodeType;
  hop: number;
  label: string;
  sub: string;
  band: LateralBand;
  role: LateralRole;
  firstSeen: string;
  events: number;
  flags?: string[];
}

export interface LateralEdge {
  from: string;
  to: string;
  method: LateralMethodId | string;
  detail: string;
  count: number;
  firstSeen: string;
  band: LateralBand;
}

export interface LateralEvidenceRow {
  at: string;
  user?: string;
  logonType?: string;
  source?: string;
  result?: string;
  peer?: string;
  port?: string;
  proto?: string;
  name?: string;
  parent?: string;
  cmd?: string;
  host?: string;
  flags?: string[];
}

export interface LateralEvidence {
  auth: LateralEvidenceRow[];
  network: LateralEvidenceRow[];
  process: LateralEvidenceRow[];
}

export interface LateralSummary {
  seed: { kind: 'host' | 'user'; id: string };
  method: string;
  maxHops: number;
  windowLabel: string;
  windowStart: string;
  windowEnd: string;
  hops: number;
  nodes: number;
  edges: number;
  reachCritical: number;
  reachCrown: number;
  deadEnds: number;
  /** True when the backend pruned nodes/edges to stay within MAX_NODES_PER_HOP
      or MAX_TOTAL_NODES. `originalNodes` is the pre-prune node count. */
  truncated: boolean;
  originalNodes: number;
}

export interface LateralGraphPayload {
  nodes: LateralNode[];
  edges: LateralEdge[];
  critical_path: string[];
  critical_edges: [string, string][];
  evidence: Record<string, LateralEvidence>;
  summary: LateralSummary;
}
