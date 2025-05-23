import {Fragment} from 'react';
import styled from '@emotion/styled';

import onboardingInstall from 'sentry-images/spot/onboarding-install.svg';

import {Alert} from 'sentry/components/core/alert';
import {LinkButton} from 'sentry/components/core/button/linkButton';
import {useProjectSeerPreferences} from 'sentry/components/events/autofix/preferences/hooks/useProjectSeerPreferences';
import {useAutofixRepos} from 'sentry/components/events/autofix/useAutofix';
import ExternalLink from 'sentry/components/links/externalLink';
import {t, tct} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import type {Project} from 'sentry/types/project';
import useOrganization from 'sentry/utils/useOrganization';

interface SeerNoticesProps {
  groupId: string;
  project: Project;
  hasGithubIntegration?: boolean;
}

function GithubIntegrationSetupCard() {
  const organization = useOrganization();

  return (
    <IntegrationCard key="no-readable-repos">
      <CardContent>
        <CardTitle>{t('Set Up the GitHub Integration')}</CardTitle>
        <CardDescription>
          <span>
            {tct('Seer is [bold:a lot better] when it has your codebase as context.', {
              bold: <b />,
            })}
          </span>
          <span>
            {tct(
              'Set up the [integrationLink:GitHub Integration] to allow Seer to go deeper when troubleshooting and fixing your issues–including writing the code and opening PRs.',
              {
                integrationLink: (
                  <ExternalLink
                    href={`/settings/${organization.slug}/integrations/github/`}
                  />
                ),
              }
            )}
          </span>
        </CardDescription>
        <LinkButton
          href={`/settings/${organization.slug}/integrations/github/`}
          size="sm"
          priority="primary"
        >
          {t('Set Up Now')}
        </LinkButton>
      </CardContent>
      <CardIllustration src={onboardingInstall} alt="Install" />
    </IntegrationCard>
  );
}

function SelectReposCard() {
  const organization = useOrganization();

  return (
    <IntegrationCard key="no-selected-repos">
      <CardContent>
        <CardTitle>{t('Pick Repositories to Work In')}</CardTitle>
        <CardDescription>
          <span>
            {tct('Seer is [bold:a lot better] when it has your codebase as context.', {
              bold: <b />,
            })}
          </span>
          <span>
            {tct(
              'Select the repos Seer can explore in this project to allow it to go deeper when troubleshooting and fixing your issues–including writing the code and opening PRs.',
              {
                integrationLink: (
                  <ExternalLink
                    href={`/settings/${organization.slug}/integrations/github/`}
                  />
                ),
              }
            )}
          </span>
          <span>
            {t(
              'You can also configure working branches and custom instructions so Seer acts just how you like.'
            )}
          </span>
          <span>
            {tct(
              '[bold:Open the Project Settings menu in the top right] to get started.',
              {
                bold: <b />,
              }
            )}
          </span>
        </CardDescription>
      </CardContent>
      <CardIllustration src={onboardingInstall} alt="Install" />
    </IntegrationCard>
  );
}

export function SeerNotices({groupId, hasGithubIntegration, project}: SeerNoticesProps) {
  const organization = useOrganization();
  const {repos} = useAutofixRepos(groupId);
  const {
    preference,
    codeMappingRepos,
    isLoading: isLoadingPreferences,
  } = useProjectSeerPreferences(project);

  const unreadableRepos = repos.filter(repo => repo.is_readable === false);
  const notices: React.JSX.Element[] = [];

  if (!hasGithubIntegration) {
    notices.push(<GithubIntegrationSetupCard key="github-setup" />);
  } else if (
    repos.length === 0 &&
    !preference?.repositories?.length &&
    !codeMappingRepos?.length &&
    !isLoadingPreferences
  ) {
    notices.push(<SelectReposCard key="repo-selection" />);
  }

  if (unreadableRepos.length > 1) {
    const githubRepos = unreadableRepos.filter(repo => repo.provider.includes('github'));
    const nonGithubRepos = unreadableRepos.filter(
      repo => !repo.provider.includes('github')
    );

    notices.push(
      <Alert type="warning" showIcon key="multiple-repos">
        {tct("Seer can't access these repositories: [repoList].", {
          repoList: <b>{unreadableRepos.map(repo => repo.name).join(', ')}</b>,
        })}
        {githubRepos.length > 0 && (
          <Fragment>
            {' '}
            {tct(
              'For best performance, enable the [integrationLink:GitHub integration].',
              {
                integrationLink: (
                  <ExternalLink
                    href={`/settings/${organization.slug}/integrations/github/`}
                  />
                ),
              }
            )}
          </Fragment>
        )}
        {nonGithubRepos.length > 0 && (
          <Fragment> {t('Seer currently only supports GitHub repositories.')}</Fragment>
        )}
      </Alert>
    );
  } else if (unreadableRepos.length === 1) {
    const unreadableRepo = unreadableRepos[0]!;
    notices.push(
      <Alert type="warning" showIcon key="single-repo">
        {unreadableRepo.provider.includes('github')
          ? tct(
              "Seer can't access the [repo] repository, make sure the [integrationLink:GitHub integration] is correctly set up.",
              {
                repo: <b>{unreadableRepo.name}</b>,
                integrationLink: (
                  <ExternalLink
                    href={`/settings/${organization.slug}/integrations/github/`}
                  />
                ),
              }
            )
          : tct(
              "Seer can't access the [repo] repository. It currently only supports GitHub repositories.",
              {repo: <b>{unreadableRepo.name}</b>}
            )}
      </Alert>
    );
  }

  if (notices.length === 0) {
    return null;
  }

  return <NoticesContainer>{notices}</NoticesContainer>;
}

const NoticesContainer = styled('div')`
  display: flex;
  flex-direction: column;
  gap: ${space(2)};
  align-items: stretch;
  margin-bottom: ${space(2)};
`;

const IntegrationCard = styled('div')`
  position: relative;
  overflow: hidden;
  border: 1px solid ${p => p.theme.border};
  border-radius: ${p => p.theme.borderRadius};
  display: flex;
  flex-direction: row;
  align-items: flex-end;
  gap: ${space(1)};
  background: linear-gradient(
    90deg,
    ${p => p.theme.backgroundSecondary}00 0%,
    ${p => p.theme.backgroundSecondary}FF 70%,
    ${p => p.theme.backgroundSecondary}FF 100%
  );
`;

const CardContent = styled('div')`
  padding: ${space(2)};
  display: flex;
  flex-direction: column;
  gap: ${space(2)};
  align-items: flex-start;
`;

const CardDescription = styled('div')`
  display: flex;
  flex-direction: column;
  gap: ${space(1)};
`;

const CardTitle = styled('h3')`
  font-size: ${p => p.theme.fontSizeLarge};
  font-weight: 600;
  margin-bottom: 0;
`;

const CardIllustration = styled('img')`
  height: 100%;
  object-fit: contain;
  max-width: 30%;
  margin-bottom: -6px;
  margin-right: 10px;
`;
