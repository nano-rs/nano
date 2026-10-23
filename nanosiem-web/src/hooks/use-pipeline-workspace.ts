// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { usePipelineWorkspaceCore } from './use-pipeline-workspace-core';
export { captureView, previewEventInputs, CAPTURE_EXPIRED_REASON } from './use-pipeline-workspace-core';

export function usePipelineWorkspace(sourceId: string) {
  const { hasPermission, tenantRuntime } = useAuth();
  const { toast } = useToast();
  return usePipelineWorkspaceCore(sourceId, { api, hasPermission, scope: tenantRuntime.key, toast });
}
