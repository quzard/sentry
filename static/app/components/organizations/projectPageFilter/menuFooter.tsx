import {Fragment} from 'react';

import Feature from 'sentry/components/acl/feature';
import {LinkButton} from 'sentry/components/core/button/linkButton';
import {IconAdd} from 'sentry/icons';
import {t} from 'sentry/locale';
import useOrganization from 'sentry/utils/useOrganization';
import useProjects from 'sentry/utils/useProjects';
import {makeProjectsPathname} from 'sentry/views/projects/pathname';

interface FeatureRenderProps {
  hasFeature: boolean;
  renderShowAllButton?: (props: {
    canShowAllProjects: boolean;
    onButtonClick: () => void;
  }) => React.ReactNode;
}

interface ProjectPageFilterMenuFooterProps {
  handleChange: (value: number[]) => void;
  showNonMemberProjects: boolean;
}

function ProjectPageFilterMenuFooter({
  handleChange,
  showNonMemberProjects,
}: ProjectPageFilterMenuFooterProps) {
  const organization = useOrganization();
  const {projects} = useProjects();

  return (
    <Fragment>
      <Feature
        organization={organization}
        features="organizations:global-views"
        hookName="feature-disabled:project-selector-all-projects"
        renderDisabled={false}
      >
        {({renderShowAllButton}: FeatureRenderProps) => {
          // if our hook is adding renderShowAllButton, render that
          if (showNonMemberProjects && renderShowAllButton && projects.length > 1) {
            return renderShowAllButton({
              onButtonClick: () => handleChange([]),
              canShowAllProjects: showNonMemberProjects,
            });
          }

          return null;
        }}
      </Feature>
      <LinkButton
        size="xs"
        aria-label={t('Add Project')}
        to={makeProjectsPathname({path: '/new/', organization})}
        icon={<IconAdd isCircled />}
      >
        {t('Project')}
      </LinkButton>
    </Fragment>
  );
}

export {ProjectPageFilterMenuFooter};
