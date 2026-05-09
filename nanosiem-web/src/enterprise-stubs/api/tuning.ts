// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for TuningAPI. Auto-tuning + tuning proposals are enterprise-only.

import type { TuningSettings } from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('TuningAPI is enterprise-only'));

export interface TuningProposal {
  id: string;
  rule_id: string;
  rule_name?: string;
  created_at: string;
  proposal_type: 'query_tuning' | 'hint_update';
  original_query: string;
  proposed_query: string;
  rationale: string;
  confidence_score: number;
  changes_summary: string[];
  affected_patterns: {
    field_name: string;
    field_value: string;
    occurrence_count: number;
    percentage: number;
  }[];
  safety_validation: {
    is_safe: boolean;
    warnings: string[];
    validation_checks: {
      check_name: string;
      passed: boolean;
      details: string;
    }[];
    critical_indicators_preserved: boolean;
  };
  status: string;
  current_hints?: unknown;
  proposed_hints?: unknown;
  hints_diff?: unknown;
  reviewer_notes?: string;
}

export interface TuningLogEntry {
  id: string;
  rule_id: string;
  rule_name: string;
  triggered_at: string;
  trigger_reason: string;
  proposal_id?: string;
  status: string;
}

export class TuningAPI {
  listProposals(): Promise<TuningProposal[]> {
    return ENTERPRISE_ONLY();
  }
  getProposal(_id: string): Promise<TuningProposal> {
    return ENTERPRISE_ONLY();
  }
  approveProposal(
    _id: string,
    _opts?: { comment?: string; modified_query?: string },
  ): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  rejectProposal(_id: string, _notes?: string): Promise<void> {
    return ENTERPRISE_ONLY();
  }
  listLogs(): Promise<TuningLogEntry[]> {
    return ENTERPRISE_ONLY();
  }
  getTuningSettings(_ruleId: string): Promise<TuningSettings> {
    return ENTERPRISE_ONLY();
  }
  updateTuningSettings(
    _ruleId: string,
    _settings: TuningSettings,
  ): Promise<TuningSettings> {
    return ENTERPRISE_ONLY();
  }
}
