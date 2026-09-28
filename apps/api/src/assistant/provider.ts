import type { AssistantContextItem } from '@drobon/shared';

/**
 * Provider boundary. Requests keep policy, user input, and untrusted evidence
 * in separate typed fields; provider implementations must not turn evidence
 * into instructions or use tools/network access.
 */
export interface AssistantProviderRequest {
  securityPolicy: string;
  userRequest: string;
  untrustedEvidence: readonly AssistantContextItem[];
}

export type AssistantProviderResult =
  | { state: 'UNAVAILABLE' }
  | { state: 'GENERATED'; answer: string };

export type AssistantProviderAvailability =
  | { state: 'NONE' | 'UNAVAILABLE'; providerId: null }
  | { state: 'AVAILABLE'; providerId: string };

export interface AssistantProvider {
  availability(): AssistantProviderAvailability;
  generate(request: AssistantProviderRequest): Promise<AssistantProviderResult>;
}

/** Production default: no remote model, credentials, startup dependency, or fake output. */
export function createNoAssistantProvider(): AssistantProvider {
  return {
    availability: () => ({ state: 'NONE', providerId: null }),
    generate: async () => ({ state: 'UNAVAILABLE' }),
  };
}
