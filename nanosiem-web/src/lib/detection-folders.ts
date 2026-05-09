// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Detection folder definitions for organizing rules
 *
 * Folders are organized by data source type:
 * - network: Firewall, proxy, DNS, netflow detections
 * - identity: Active Directory, SSO, IAM detections
 * - endpoint: EDR, sysmon, process execution detections
 * - cloud: AWS, Azure, GCP detections
 * - stash: Archive folder - rules here are auto-disabled
 */

export interface FolderDefinition {
  id: string;
  name: string;
  icon: 'Network' | 'UserCheck' | 'Monitor' | 'Cloud' | 'Archive' | 'Folder';
  description: string;
  isSpecial?: boolean;
}

export const DEFAULT_FOLDERS: FolderDefinition[] = [
  {
    id: 'network',
    name: 'Network',
    icon: 'Network',
    description: 'Firewall, proxy, DNS, netflow detections'
  },
  {
    id: 'identity',
    name: 'Identity',
    icon: 'UserCheck',
    description: 'Active Directory, SSO, IAM detections'
  },
  {
    id: 'endpoint',
    name: 'Endpoint',
    icon: 'Monitor',
    description: 'EDR, sysmon, process execution detections'
  },
  {
    id: 'cloud',
    name: 'Cloud',
    icon: 'Cloud',
    description: 'AWS CloudTrail, Azure Activity, GCP detections'
  },
  {
    id: 'stash',
    name: 'Stash',
    icon: 'Archive',
    description: 'Archive folder - rules here are auto-disabled',
    isSpecial: true
  },
];

export const UNCATEGORIZED_FOLDER: FolderDefinition = {
  id: 'uncategorized',
  name: 'Uncategorized',
  icon: 'Folder',
  description: 'Rules without a folder assignment'
};

