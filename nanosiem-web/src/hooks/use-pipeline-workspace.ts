// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { usePipelineWorkspaceCore } from './use-pipeline-workspace-core';

export function usePipelineWorkspace(sourceId: string) {
  const { hasPermission, user } = useAuth();
  const { toast } = useToast();
  return usePipelineWorkspaceCore(sourceId, { api, hasPermission, scope: user?.id ?? 'anonymous', toast });
}
