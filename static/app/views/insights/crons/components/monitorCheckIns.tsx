import {Fragment} from 'react';
import styled from '@emotion/styled';

import {SectionHeading} from 'sentry/components/charts/styles';
import {Tag} from 'sentry/components/core/badge/tag';
import {Tooltip} from 'sentry/components/core/tooltip';
import {DateTime} from 'sentry/components/dateTime';
import Duration from 'sentry/components/duration';
import ProjectBadge from 'sentry/components/idBadge/projectBadge';
import LoadingError from 'sentry/components/loadingError';
import Pagination from 'sentry/components/pagination';
import {PanelTable} from 'sentry/components/panels/panelTable';
import Placeholder from 'sentry/components/placeholder';
import QuestionTooltip from 'sentry/components/questionTooltip';
import ShortId from 'sentry/components/shortId';
import {
  StatusIndicator,
  type StatusIndicatorProps,
} from 'sentry/components/statusIndicator';
import Text from 'sentry/components/text';
import {t, tct} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import {defined} from 'sentry/utils';
import {useLocation} from 'sentry/utils/useLocation';
import useOrganization from 'sentry/utils/useOrganization';
import {useUser} from 'sentry/utils/useUser';
import {QuickContextHovercard} from 'sentry/views/discover/table/quickContext/quickContextHovercard';
import {ContextType} from 'sentry/views/discover/table/quickContext/utils';
import type {Monitor, MonitorEnvironment} from 'sentry/views/insights/crons/types';
import {CheckInStatus} from 'sentry/views/insights/crons/types';
import {statusToText} from 'sentry/views/insights/crons/utils';
import {useMonitorCheckIns} from 'sentry/views/insights/crons/utils/useMonitorCheckIns';

import {DEFAULT_MAX_RUNTIME} from './monitorForm';

type Props = {
  monitor: Monitor;
  monitorEnvs: MonitorEnvironment[];
};

const checkStatusToIndicatorStatus: Record<
  CheckInStatus,
  StatusIndicatorProps['status']
> = {
  [CheckInStatus.OK]: 'success',
  [CheckInStatus.ERROR]: 'error',
  [CheckInStatus.IN_PROGRESS]: 'muted',
  [CheckInStatus.MISSED]: 'warning',
  [CheckInStatus.TIMEOUT]: 'error',
  [CheckInStatus.UNKNOWN]: 'muted',
};

const PER_PAGE = 10;

export function MonitorCheckIns({monitor, monitorEnvs}: Props) {
  const user = useUser();
  const location = useLocation();
  const organization = useOrganization();

  const {
    data: checkInList,
    getResponseHeader,
    isPending,
    isError,
  } = useMonitorCheckIns({
    orgSlug: organization.slug,
    projectSlug: monitor.project.slug,
    monitorIdOrSlug: monitor.slug,
    limit: PER_PAGE,
    expand: 'groups',
    environment: monitorEnvs.map(e => e.name),
    queryParams: {...location.query},
  });

  if (isError) {
    return <LoadingError />;
  }

  const emptyCell = <Text>{'\u2014'}</Text>;

  const hasMultiEnv = monitorEnvs.length > 1;

  const headers = [
    t('Status'),
    <RecordedHeader key="recorded-header">
      {t('Recorded')}
      <QuestionTooltip
        size="sm"
        title={t('The time when Sentry received the first check-in for this job.')}
      />
    </RecordedHeader>,
    t('Duration'),
    t('Issues'),
    ...(hasMultiEnv ? [t('Environment')] : []),
    t('Expected At'),
  ];

  const customTimezone =
    monitor.config.timezone && monitor.config.timezone !== user.options.timezone;

  return (
    <Fragment>
      <SectionHeading>{t('Recent Check-Ins')}</SectionHeading>
      <PanelTable
        headers={headers}
        isEmpty={!isPending && checkInList.length === 0}
        emptyMessage={t('No check-ins have been recorded for this time period.')}
      >
        {isPending
          ? [...new Array(PER_PAGE)].map((_, i) => (
              <RowPlaceholder key={i}>
                <Placeholder height="2rem" />
              </RowPlaceholder>
            ))
          : checkInList.map(checkIn => (
              <Fragment key={checkIn.id}>
                <Status>
                  <StatusIndicator
                    status={checkStatusToIndicatorStatus[checkIn.status]}
                    tooltipTitle={tct('Check-in Status: [status]', {
                      status: statusToText[checkIn.status],
                    })}
                  />
                  <Text>{statusToText[checkIn.status]}</Text>
                </Status>
                {checkIn.status === CheckInStatus.MISSED ? (
                  emptyCell
                ) : (
                  <div>
                    <Tooltip
                      disabled={!customTimezone}
                      title={
                        <DateTime
                          date={checkIn.dateAdded}
                          forcedTimezone={monitor.config.timezone ?? 'UTC'}
                          timeZone
                          seconds
                        />
                      }
                    >
                      <DateTime date={checkIn.dateAdded} timeZone seconds />
                    </Tooltip>
                  </div>
                )}
                {defined(checkIn.duration) ? (
                  <DurationContainer>
                    <Tooltip title={<Duration exact seconds={checkIn.duration / 1000} />}>
                      <Duration seconds={checkIn.duration / 1000} />
                    </Tooltip>
                    {checkIn.status === CheckInStatus.TIMEOUT && (
                      <TimeoutLateBy monitor={monitor} duration={checkIn.duration} />
                    )}
                  </DurationContainer>
                ) : checkIn.status === CheckInStatus.TIMEOUT ? (
                  <div>
                    <Tooltip
                      title={t(
                        'An in-progress check-in was received, but no closing check-in followed. Your job may be terminating before it reports to Sentry.'
                      )}
                    >
                      <Tag type="error">{t('Incomplete')}</Tag>
                    </Tooltip>
                  </div>
                ) : (
                  emptyCell
                )}
                {checkIn.groups && checkIn.groups.length > 0 ? (
                  <IssuesContainer>
                    {checkIn.groups.map(({id, shortId}) => (
                      <QuickContextHovercard
                        dataRow={{
                          ['issue.id']: id,
                          issue: shortId,
                        }}
                        contextType={ContextType.ISSUE}
                        organization={organization}
                        key={id}
                      >
                        <StyledShortId
                          shortId={shortId}
                          avatar={
                            <ProjectBadge
                              project={monitor.project}
                              hideName
                              avatarSize={12}
                            />
                          }
                          to={`/organizations/${organization.slug}/issues/${id}/`}
                        />
                      </QuickContextHovercard>
                    ))}
                  </IssuesContainer>
                ) : (
                  emptyCell
                )}
                {hasMultiEnv ? <div>{checkIn.environment}</div> : null}
                <div>
                  {checkIn.expectedTime ? (
                    <Tooltip
                      disabled={!customTimezone}
                      title={
                        <DateTime
                          date={checkIn.expectedTime}
                          forcedTimezone={monitor.config.timezone ?? 'UTC'}
                          timeZone
                          seconds
                        />
                      }
                    >
                      <Timestamp date={checkIn.expectedTime} timeZone seconds />
                    </Tooltip>
                  ) : (
                    emptyCell
                  )}
                </div>
              </Fragment>
            ))}
      </PanelTable>
      <Pagination pageLinks={getResponseHeader?.('Link')} />
    </Fragment>
  );
}

interface TimeoutLateByProps {
  duration: number;
  monitor: Monitor;
}

function TimeoutLateBy({monitor, duration}: TimeoutLateByProps) {
  const maxRuntimeSeconds = (monitor.config.max_runtime ?? DEFAULT_MAX_RUNTIME) * 60;
  const lateBySecond = duration / 1000 - maxRuntimeSeconds;

  const maxRuntime = (
    <strong>
      <Duration seconds={(monitor.config.max_runtime ?? DEFAULT_MAX_RUNTIME) * 60} />
    </strong>
  );

  const lateBy = (
    <strong>
      <Duration seconds={lateBySecond} />
    </strong>
  );

  return (
    <Tooltip
      title={tct(
        'The closing check-in occurred [lateBy] after this check-in was marked as timed out. The configured maximum allowed runtime is [maxRuntime].',
        {lateBy, maxRuntime}
      )}
    >
      <Tag type="error">
        {t('%s late', <Duration abbreviation seconds={lateBySecond} />)}
      </Tag>
    </Tooltip>
  );
}

const RecordedHeader = styled('div')`
  display: flex;
  gap: ${space(0.5)};
  align-items: center;
`;

const Status = styled('div')`
  line-height: 1.1;
`;

const DurationContainer = styled('div')`
  display: flex;
  gap: ${space(0.5)};
  align-items: center;
`;

const IssuesContainer = styled('div')`
  display: flex;
  flex-direction: column;
`;

const Timestamp = styled(DateTime)`
  color: ${p => p.theme.subText};
`;

const StyledShortId = styled(ShortId)`
  justify-content: flex-start;
`;

const RowPlaceholder = styled('div')`
  grid-column: 1 / -1;
  padding: ${space(1)};

  &:not(:last-child) {
    border-bottom: solid 1px ${p => p.theme.innerBorder};
  }
`;
