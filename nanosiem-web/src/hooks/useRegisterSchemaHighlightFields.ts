// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * useRegisterSchemaHighlightFields — seed the editor tokenizers with the active
 * schema's field names (NAN-1241).
 *
 * The query editor, the detection editor, and the rendered-code-block
 * highlighter each keep a static `UDM_FIELD_NAMES` set that only knows UDM
 * columns. Under OCSF the promoted columns (`src_endpoint.ip`,
 * `actor.process.cmd_line`, `class_uid`, …) would render unhighlighted. This
 * hook fetches `GET /api/schema/fields` once and registers any names the UDM
 * set doesn't already cover into all three tokenizers.
 *
 * Under UDM the schema set is a subset of the UDM columns, so the register calls
 * are no-ops and highlighting stays byte-identical. Mount this once high in the
 * tree (App) so highlighting works on every editor surface, not just Search.
 */

import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { registerDynamicFields, registerDetectionDynamicFields } from '@/components/editor';
import { registerHighlightDynamicFields } from '@/lib/syntax-highlight';

export function useRegisterSchemaHighlightFields(enabled = true): void {
  const { data: schemaFields } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
    enabled,
  });

  useEffect(() => {
    if (!schemaFields) return;
    const names = schemaFields.fields.map((f) => f.name);
    if (names.length === 0) return;
    registerDynamicFields(names);
    registerDetectionDynamicFields(names);
    registerHighlightDynamicFields(names);
  }, [schemaFields]);
}
