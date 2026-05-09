// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for CustomEnrichmentApi. User-defined enrichments (Deno sandbox) are enterprise-only.

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('CustomEnrichmentApi is enterprise-only'));

export interface CustomEnrichmentSummary {
  id: string;
  namespace_id: string;
  name: string;
  description: string | null;
  enrichment_type: 'data' | 'agent';
  enabled: boolean;
  status: 'draft' | 'validating' | 'active' | 'failed';
  last_run_at: string | null;
  last_run_status: string | null;
  created_at: string;
}

export interface CustomEnrichmentDetail extends CustomEnrichmentSummary {
  code: string;
  code_language: string;
  code_version: number;
  config: Record<string, unknown>;
  credential_id: string | null;
  allowed_domains: string[];
  timeout_secs: number;
  last_error: string | null;
  updated_at: string;
}

export interface CreateCustomEnrichmentRequest {
  name: string;
  description?: string;
  enrichment_type: 'data' | 'agent';
  code: string;
  code_language?: string;
  config: Record<string, unknown>;
  credential_id?: string;
  allowed_domains: string[];
  timeout_secs?: number;
}

export interface UpdateCustomEnrichmentRequest {
  name?: string;
  description?: string;
  code?: string;
  config?: Record<string, unknown>;
  credential_id?: string;
  allowed_domains?: string[];
  timeout_secs?: number;
  change_summary?: string;
}

export interface ValidationStageResult {
  stage: 'syntax' | 'connection' | 'functional';
  success: boolean;
  errors: ValidationError[];
  warnings: string[];
  duration_ms: number;
}

export interface ValidationError {
  code: string;
  message: string;
  line: number | null;
  column: number | null;
  suggestion: string | null;
}

export interface ValidationResponse {
  stages: ValidationStageResult[];
  overall_success: boolean;
  sample_output: unknown | null;
  detected_schema: DetectedSchema | null;
}

export interface DetectedSchema {
  fields: DetectedField[];
  has_key_field: boolean;
  has_risk_score: boolean;
  has_tags: boolean;
  record_count: number;
}

export interface DetectedField {
  name: string;
  field_type: string;
  sample_value: unknown | null;
  is_array: boolean;
  is_nullable: boolean;
}

export interface VersionInfo {
  id: string;
  version: number;
  change_summary: string | null;
  created_by: string;
  created_at: string;
}

export interface VersionDiff {
  from_version: number;
  to_version: number;
  from_code: string;
  to_code: string;
}

export interface RunInfo {
  id: string;
  run_type: 'validation' | 'scheduled' | 'manual';
  status: 'running' | 'success' | 'failed';
  started_at: string;
  completed_at: string | null;
  records_fetched: number | null;
  records_stored: number | null;
  error_message: string | null;
  sample_output: unknown | null;
}

export interface GenerateCodeRequest {
  enrichment_type: 'data' | 'agent';
  description: string;
  curl_example?: string;
  api_docs?: string;
  sample_response?: string;
  key_type: 'ip' | 'domain' | 'hash' | 'url' | 'custom';
  is_ioc?: boolean;
  auth_type?: string;
  auth_header_name?: string;
  additional_context?: string;
}

export interface GenerateCodeResponse {
  code: string;
  explanation: string;
  detected_fields: {
    name: string;
    description: string | null;
    suggested_mapping: string | null;
  }[];
  suggested_domains: string[];
}

export interface CodeTemplates {
  data: string;
  agent: string;
}

export class CustomEnrichmentApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
  ) {
    void _request;
  }

  list(_enrichmentType?: 'data' | 'agent'): Promise<CustomEnrichmentSummary[]> {
    return ENTERPRISE_ONLY();
  }
  get(_id: string): Promise<CustomEnrichmentDetail> {
    return ENTERPRISE_ONLY();
  }
  create(_request: CreateCustomEnrichmentRequest): Promise<CustomEnrichmentDetail> {
    return ENTERPRISE_ONLY();
  }
  update(
    _id: string,
    _request: UpdateCustomEnrichmentRequest,
  ): Promise<CustomEnrichmentDetail> {
    return ENTERPRISE_ONLY();
  }
  delete(_id: string): Promise<{ deleted: boolean }> {
    return ENTERPRISE_ONLY();
  }
  validate(
    _id: string,
    _testArtifact?: string,
    _testArtifactType?: string,
  ): Promise<ValidationResponse> {
    return ENTERPRISE_ONLY();
  }
  deploy(_id: string): Promise<CustomEnrichmentDetail> {
    return ENTERPRISE_ONLY();
  }
  disable(_id: string): Promise<CustomEnrichmentDetail> {
    return ENTERPRISE_ONLY();
  }
  getVersions(_id: string): Promise<VersionInfo[]> {
    return ENTERPRISE_ONLY();
  }
  getVersionDiff(_id: string, _version: number): Promise<VersionDiff> {
    return ENTERPRISE_ONLY();
  }
  triggerRun(_id: string): Promise<RunInfo> {
    return ENTERPRISE_ONLY();
  }
  getRuns(_id: string, _limit?: number): Promise<RunInfo[]> {
    return ENTERPRISE_ONLY();
  }
  generateCode(_request: GenerateCodeRequest): Promise<GenerateCodeResponse> {
    return ENTERPRISE_ONLY();
  }
  getTemplates(): Promise<CodeTemplates> {
    return ENTERPRISE_ONLY();
  }
}
