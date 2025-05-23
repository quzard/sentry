import styled from '@emotion/styled';

import {LinkButton} from 'sentry/components/core/button/linkButton';
import PageAlertBar from 'sentry/components/pageAlertBar';
import {IconLightning} from 'sentry/icons';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import type {Organization} from 'sentry/types/organization';
import type {AvatarProject} from 'sentry/types/project';
import {trackAnalytics} from 'sentry/utils/analytics';

function SampleEventAlert({
  organization,
  project,
}: {
  organization: Organization;
  project: AvatarProject;
}) {
  return (
    <PageAlertBar>
      <IconLightning />
      <TextWrapper>
        {t(
          'You are viewing a sample error. Configure Sentry to start viewing real errors.'
        )}
      </TextWrapper>
      <LinkButton
        size="xs"
        priority="primary"
        to={`/${organization.slug}/${project.slug}/getting-started/${
          project.platform || ''
        }`}
        onClick={() =>
          trackAnalytics('growth.sample_error_onboarding_link_clicked', {
            project_id: project.id?.toString(),
            organization,
            platform: project.platform,
          })
        }
      >
        {t('Get Started')}
      </LinkButton>
    </PageAlertBar>
  );
}

export default SampleEventAlert;

const TextWrapper = styled('span')`
  margin: 0 ${space(1)};
`;
