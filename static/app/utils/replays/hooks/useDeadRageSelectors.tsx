import {useApiQuery} from 'sentry/utils/queryClient';
import hydratedSelectorData from 'sentry/utils/replays/hydrateSelectorData';
import {useLocation} from 'sentry/utils/useLocation';
import useOrganization from 'sentry/utils/useOrganization';
import type {
  DeadRageSelectorListResponse,
  DeadRageSelectorQueryParams,
} from 'sentry/views/replays/types';

export default function useDeadRageSelectors(params: DeadRageSelectorQueryParams) {
  const organization = useOrganization();
  const location = useLocation();
  const {query} = location;

  const {isPending, isError, error, data, getResponseHeader} =
    useApiQuery<DeadRageSelectorListResponse>(
      [
        `/organizations/${organization.slug}/replay-selectors/`,
        {
          query: {
            query: params.query ?? '!count_dead_clicks:0',
            cursor: params.cursor,
            environment: query.environment,
            project: query.project,
            statsPeriod: query.statsPeriod,
            per_page: params.per_page,
            sort: query[params.prefix + 'sort'] ?? params.sort,
          },
        },
      ],
      {staleTime: Infinity}
    );

  return {
    isLoading: isPending,
    isError,
    error,
    data: hydratedSelectorData(
      data ? data.data : [],
      params.isWidgetData ? params.sort?.replace(/^-/, '') : null
    ),
    pageLinks: getResponseHeader?.('Link') ?? undefined,
  };
}
