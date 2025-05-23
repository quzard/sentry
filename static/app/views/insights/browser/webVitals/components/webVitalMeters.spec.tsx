import {OrganizationFixture} from 'sentry-fixture/organization';
import {PageFilterStateFixture} from 'sentry-fixture/pageFilters';

import {render, screen} from 'sentry-test/reactTestingLibrary';

import {useLocation} from 'sentry/utils/useLocation';
import usePageFilters from 'sentry/utils/usePageFilters';
import WebVitalMeters, {
  type ProjectData,
} from 'sentry/views/insights/browser/webVitals/components/webVitalMeters';
import type {ProjectScore} from 'sentry/views/insights/browser/webVitals/types';

jest.mock('sentry/utils/useLocation');
jest.mock('sentry/utils/usePageFilters');

describe('WebVitalMeters', function () {
  const organization = OrganizationFixture();
  const projectScore: ProjectScore = {
    lcpScore: 100,
    fcpScore: 100,
    clsScore: 100,
    ttfbScore: 100,
    inpScore: 100,
  };
  const projectData: ProjectData[] = [];

  beforeEach(function () {
    jest.mocked(useLocation).mockReturnValue({
      pathname: '',
      search: '',
      query: {},
      hash: '',
      state: undefined,
      action: 'PUSH',
      key: '',
    });
    jest.mocked(usePageFilters).mockReturnValue(PageFilterStateFixture());
  });

  it('renders web vital meters with interaction to next paint', async () => {
    render(<WebVitalMeters projectData={projectData} projectScore={projectScore} />, {
      organization,
    });

    await screen.findByText('Largest Contentful Paint');
    screen.getByText('First Contentful Paint');
    screen.getByText('Cumulative Layout Shift');
    screen.getByText('Time To First Byte');
    screen.getByText('Interaction to Next Paint');
  });
});
