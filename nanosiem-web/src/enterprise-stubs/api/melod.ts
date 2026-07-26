// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for MelodApi. meloD is the AI assistant — enterprise-only.

import type {
  MelodChatRequest,
  MelodCreateParserRequest,
  ParserProgressEvent,
  GeneratedParser,
  MelodBuildQueryRequest,
  MelodCreateDetectionRequest,
  MelodTuneDetectionRequest,
  MelodSummarizeRequest,
  MelodEditParserRequest,
  GenerateDashboardRequest,
  RefineDashboardRequest,
  FetchUrlForDetectionResponse,
  GenerateDetectionHintsRequest,
  AiAvailability,
  ProviderCredentials,
  UpdateProviderCredentialsRequest,
  AgentModelConfig,
  UpdateAgentModelConfigRequest,
  AvailableModel,
  CreateAvailableModelRequest,
  UpdateAvailableModelRequest,
  MelodJobStartResponse,
  MelodJobStatusResponse,
  ModelCatalogSyncResult,
  ModelCatalogStatus,
  CorrectQueryRequest,
  CorrectQueryResponse,
  ReviewQueryRequest,
  ReviewQueryResponse,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('MelodApi is enterprise-only'));

export class MelodApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    _getAccessToken: () => string | null,
    _baseUrl: string,
  ) {
    void _request;
    void _getAccessToken;
    void _baseUrl;
  }

  getMelodJobStatus(_jobId: string): Promise<MelodJobStatusResponse> {
    return ENTERPRISE_ONLY();
  }
  melodChat(_request: MelodChatRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodCreateParser(_request: MelodCreateParserRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodCreateParserStreaming(
    _request: MelodCreateParserRequest,
    _onProgress: (event: ParserProgressEvent) => void,
    onComplete: (parser: GeneratedParser | null, error?: string) => void,
  ): AbortController {
    onComplete(null, 'MelodApi is enterprise-only');
    return new AbortController();
  }
  melodBuildQuery(_request: MelodBuildQueryRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  correctQuery(_request: CorrectQueryRequest): Promise<CorrectQueryResponse> {
    return ENTERPRISE_ONLY();
  }
  reviewQuery(_request: ReviewQueryRequest): Promise<ReviewQueryResponse> {
    return ENTERPRISE_ONLY();
  }
  melodCreateDetection(
    _request: MelodCreateDetectionRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodTuneDetection(
    _request: MelodTuneDetectionRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodSummarize(_request: MelodSummarizeRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodEditParser(_request: MelodEditParserRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodGenerateDashboard(
    _request: GenerateDashboardRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  melodGetDashboardJob(_jobId: string): Promise<MelodJobStatusResponse> {
    return ENTERPRISE_ONLY();
  }
  melodRefineDashboard(
    _request: RefineDashboardRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  fetchUrlForDetection(_url: string): Promise<FetchUrlForDetectionResponse> {
    return ENTERPRISE_ONLY();
  }
  generateDetectionHints(
    _request: GenerateDetectionHintsRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  getAiAvailability(): Promise<AiAvailability> {
    return ENTERPRISE_ONLY();
  }
  listAiProviders(): Promise<ProviderCredentials[]> {
    return ENTERPRISE_ONLY();
  }
  getAiProvider(_provider: string): Promise<ProviderCredentials> {
    return ENTERPRISE_ONLY();
  }
  updateAiProvider(
    _provider: string,
    _request: UpdateProviderCredentialsRequest,
  ): Promise<ProviderCredentials> {
    return ENTERPRISE_ONLY();
  }
  validateAiProvider(_provider: string): Promise<{ success: boolean; message: string }> {
    return ENTERPRISE_ONLY();
  }
  listAgentModelConfigs(): Promise<AgentModelConfig[]> {
    return ENTERPRISE_ONLY();
  }
  getAgentModelConfig(_agentId: string): Promise<AgentModelConfig> {
    return ENTERPRISE_ONLY();
  }
  updateAgentModelConfig(
    _agentId: string,
    _request: UpdateAgentModelConfigRequest,
  ): Promise<AgentModelConfig> {
    return ENTERPRISE_ONLY();
  }
  listAvailableModels(): Promise<AvailableModel[]> {
    return ENTERPRISE_ONLY();
  }
  listAllAvailableModels(): Promise<AvailableModel[]> {
    return ENTERPRISE_ONLY();
  }
  createAvailableModel(_request: CreateAvailableModelRequest): Promise<AvailableModel> {
    return ENTERPRISE_ONLY();
  }
  updateAvailableModel(
    _modelId: string,
    _request: UpdateAvailableModelRequest,
  ): Promise<AvailableModel> {
    return ENTERPRISE_ONLY();
  }
  deleteAvailableModel(_modelId: string): Promise<{ deleted: boolean }> {
    return ENTERPRISE_ONLY();
  }
  syncModelCatalog(): Promise<ModelCatalogSyncResult> {
    return ENTERPRISE_ONLY();
  }
  getModelCatalogStatus(): Promise<ModelCatalogStatus> {
    return ENTERPRISE_ONLY();
  }
}
