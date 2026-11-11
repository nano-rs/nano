// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: SCIM provisioning is enterprise-only (NAN-5274), so no
// local group is ever fed by SCIM and the Groups page shows every group as
// Local. Returns data, never renders anything.

export interface ScimGroupSource {
  group_id: string;
  provider_id: string;
  provider_name: string;
  idp_group: string;
}

const EMPTY = new Map<string, ScimGroupSource[]>();

export function useScimGroupSources(_enabled: boolean): Map<string, ScimGroupSource[]> {
  void _enabled;
  return EMPTY;
}
