import type {IntegrationProvider} from 'sentry/types/integrations';

export function GitLabIntegrationProviderFixture(
  params: Partial<IntegrationProvider> = {}
): IntegrationProvider {
  return {
    key: 'gitlab',
    slug: 'gitlab',
    name: 'GitLab',
    canAdd: true,
    features: [],
    setupDialog: {
      url: '/gitlab-integration-setup-uri/',
      width: 100,
      height: 100,
    },
    canDisable: true,
    metadata: {
      description: '*markdown* formatted _description_',
      features: [
        {
          description: '*markdown* feature description',
          featureGate: 'integrations-commits',
          featureId: 3,
        },
      ],
      author: 'Morty',
      noun: 'Installation',
      issue_url: 'http://example.com/integration_issue_url',
      source_url: 'http://example.com/integration_source_url',
      aspects: {
        alerts: [
          {
            type: 'warning',
            text: 'This is a an alert example',
          },
        ],
      },
    },
    ...params,
  };
}
