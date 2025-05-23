import {Component} from 'react';
import type {Theme} from '@emotion/react';

import type {Client} from 'sentry/api';
import MiniBarChart from 'sentry/components/charts/miniBarChart';
import EmptyMessage from 'sentry/components/emptyMessage';
import LoadingError from 'sentry/components/loadingError';
import Panel from 'sentry/components/panels/panel';
import PanelBody from 'sentry/components/panels/panelBody';
import PanelHeader from 'sentry/components/panels/panelHeader';
import Placeholder from 'sentry/components/placeholder';
import {t} from 'sentry/locale';
import type {Series} from 'sentry/types/echarts';
import type {RouteComponentProps} from 'sentry/types/legacyReactRouter';
import type {Organization} from 'sentry/types/organization';

type Props = {
  api: Client;
  organization: Organization;
  theme: Theme;
} & Pick<
  RouteComponentProps<{
    keyId: string;
    projectId: string;
  }>,
  'params'
>;

type State = {
  emptyStats: boolean;
  error: boolean;
  loading: boolean;
  series: Series[];
  since: number;
  until: number;
};

const getInitialState = (): State => {
  const until = Math.floor(Date.now() / 1000);
  return {
    since: until - 3600 * 24 * 30,
    until,
    loading: true,
    error: false,
    series: [],
    emptyStats: false,
  };
};

class KeyStats extends Component<Props, State> {
  state = getInitialState();

  componentDidMount() {
    this.fetchData();
  }

  fetchData = () => {
    const {organization} = this.props;
    const {keyId, projectId} = this.props.params;
    this.props.api.request(
      `/projects/${organization.slug}/${projectId}/keys/${keyId}/stats/`,
      {
        query: {
          since: this.state.since,
          until: this.state.until,
          resolution: '1d',
        },
        success: data => {
          let emptyStats = true;
          const dropped: Series['data'] = [];
          const accepted: Series['data'] = [];
          data.forEach((p: any) => {
            if (p.total) {
              emptyStats = false;
            }
            dropped.push({name: p.ts * 1000, value: p.dropped});
            accepted.push({name: p.ts * 1000, value: p.accepted});
          });
          const series = [
            {
              seriesName: t('Accepted'),
              data: accepted,
            },
            {
              seriesName: t('Rate Limited'),
              data: dropped,
            },
          ];
          this.setState({
            series,
            emptyStats,
            error: false,
            loading: false,
          });
        },
        error: () => {
          this.setState({error: true, loading: false});
        },
      }
    );
  };

  render() {
    if (this.state.error) {
      return <LoadingError onRetry={this.fetchData} />;
    }

    return (
      <Panel>
        <PanelHeader>{t('Key usage in the last 30 days (by day)')}</PanelHeader>
        <PanelBody withPadding>
          {this.state.loading ? (
            <Placeholder height="150px" />
          ) : this.state.emptyStats ? (
            <EmptyMessage
              title={t('Nothing recorded in the last 30 days.')}
              description={t('Total events captured using these credentials.')}
            />
          ) : (
            <MiniBarChart
              isGroupedByDate
              series={this.state.series}
              height={150}
              colors={[this.props.theme.gray200, this.props.theme.red300]}
              stacked
              labelYAxisExtents
            />
          )}
        </PanelBody>
      </Panel>
    );
  }
}

export default KeyStats;
