// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for QueuesApi. Queues + routing rules ride on top of Cases, which is enterprise-only.

import type {
  Queue,
  QueueWithMembership,
  NewQueue,
  QueueUpdate,
  QueueRoutingRule,
  NewQueueRoutingRule,
  QueueRoutingRuleUpdate,
  QueueRoutingPreviewRequest,
  QueueRoutingPreviewResponse,
  GroupMembersResponse,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('QueuesApi is enterprise-only'));

export class QueuesApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  listQueues(): Promise<QueueWithMembership[]> {
    return ENTERPRISE_ONLY();
  }
  listMyQueues(): Promise<QueueWithMembership[]> {
    return ENTERPRISE_ONLY();
  }
  getQueue(_id: string): Promise<QueueWithMembership> {
    return ENTERPRISE_ONLY();
  }
  createQueue(_input: NewQueue): Promise<Queue> {
    return ENTERPRISE_ONLY();
  }
  updateQueue(_id: string, _input: QueueUpdate): Promise<Queue> {
    return ENTERPRISE_ONLY();
  }
  deleteQueue(_id: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  listQueueRoutingRules(): Promise<QueueRoutingRule[]> {
    return ENTERPRISE_ONLY();
  }
  createQueueRoutingRule(_input: NewQueueRoutingRule): Promise<QueueRoutingRule> {
    return ENTERPRISE_ONLY();
  }
  updateQueueRoutingRule(
    _id: string,
    _input: QueueRoutingRuleUpdate,
  ): Promise<QueueRoutingRule> {
    return ENTERPRISE_ONLY();
  }
  deleteQueueRoutingRule(_id: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  previewQueueRouting(
    _input: QueueRoutingPreviewRequest,
  ): Promise<QueueRoutingPreviewResponse> {
    return ENTERPRISE_ONLY();
  }
  getGroupMembers(_groupId: string): Promise<GroupMembersResponse> {
    return ENTERPRISE_ONLY();
  }
}
