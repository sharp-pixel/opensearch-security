/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.configuration;

import org.apache.lucene.search.BooleanClause;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DlsFilterLevelActionHandlerTest {

    @Test
    public void appliesDlsAsFilterToTopLevelCapableQuery() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(topLevelQuery.filter(dlsQuery)).thenReturn(topLevelQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY);

        assertThat(searchSource.query(), sameInstance(topLevelQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
        verify(topLevelQuery).filter(dlsQuery);
    }

    @Test
    public void usesQueryReturnedByTopLevelFilter() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        QueryBuilder filteredTopLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(filteredTopLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(filteredTopLevelQuery.getName()).thenReturn("top-level-query");
        when(topLevelQuery.filter(dlsQuery)).thenReturn(filteredTopLevelQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY);

        assertThat(searchSource.query(), sameInstance(filteredTopLevelQuery));
        verify(topLevelQuery).filter(dlsQuery);
    }

    @Test
    public void failsClosedWhenTopLevelFilterReturnsNull() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(topLevelQuery.filter(dlsQuery)).thenReturn(null);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY)
        );

        assertThat(exception.getMessage(), is("Top-level query returned no query after applying the DLS filter"));
        assertThat(searchSource.query(), sameInstance(topLevelQuery));
    }

    @Test
    public void failsClosedWhenTopLevelFilterCapabilityIsNotPreserved() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        QueryBuilder filteredQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(filteredQuery.supportsTopLevelFilter()).thenReturn(false);
        when(topLevelQuery.filter(dlsQuery)).thenReturn(filteredQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY)
        );

        assertThat(exception.getMessage(), is("Top-level query capability was not preserved after applying the DLS filter"));
        assertThat(searchSource.query(), sameInstance(topLevelQuery));
    }

    @Test
    public void failsClosedWhenTopLevelFilterChangesQueryType() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        QueryBuilder filteredQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(filteredQuery.supportsTopLevelFilter()).thenReturn(true);
        when(filteredQuery.getName()).thenReturn("different-top-level-query");
        when(topLevelQuery.filter(dlsQuery)).thenReturn(filteredQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY)
        );

        assertThat(exception.getMessage(), is("Top-level query type changed after applying the DLS filter"));
        assertThat(searchSource.query(), sameInstance(topLevelQuery));
    }

    @Test
    public void reportsTopLevelFilterFailureToActionListener() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        when(topLevelQuery.getName()).thenReturn("top-level-query");
        when(topLevelQuery.filter(dlsQuery)).thenReturn(null);

        boolean applied = DlsFilterLevelActionHandler.tryApplyFilterLevelDls(
            searchSource,
            dlsQuery,
            DlsFilterApplication.TOP_LEVEL_QUERY,
            listener
        );

        assertThat(applied, is(false));
        verify(listener).onFailure(
            org.mockito.ArgumentMatchers.argThat(
                exception -> exception instanceof OpenSearchSecurityException
                    && exception.getMessage().equals("Top-level query returned no query after applying the DLS filter")
            )
        );
        assertThat(searchSource.query(), sameInstance(topLevelQuery));
    }

    @Test
    public void failsClosedWhenTopLevelQueryContainsParentChildClause() {
        QueryBuilder parentChildQuery = mock(QueryBuilder.class);
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(parentChildQuery.getWriteableName()).thenReturn("has_child");
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(topLevelQuery);
            visitor.getChildVisitor(BooleanClause.Occur.MUST).accept(parentChildQuery);
            return null;
        }).when(topLevelQuery).visit(any(QueryBuilderVisitor.class));

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY)
        );

        assertThat(exception.getMessage(), is("Unable to preserve a top-level query containing parent or child clauses"));
        assertThat(searchSource.query(), sameInstance(topLevelQuery));
        verify(topLevelQuery, never()).filter(dlsQuery);
    }

    @Test
    public void wrapsQueryWithFilterLevelDlsQuery() {
        QueryBuilder originalQuery = QueryBuilders.matchAllQuery();
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(originalQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.FILTER_LEVEL);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), contains(sameInstance(originalQuery)));
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void failsClosedWhenTopLevelStrategyIsUsedForUnsupportedQuery() {
        QueryBuilder originalQuery = QueryBuilders.matchAllQuery();
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(originalQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.TOP_LEVEL_QUERY)
        );

        assertThat(exception.getMessage(), is("Query does not support top-level DLS filtering"));
        assertThat(searchSource.query(), sameInstance(originalQuery));
    }

    @Test
    public void usesDlsQueryWhenSearchHasNoQuery() {
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource();

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.FILTER_LEVEL);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void createsSearchSourceAndAppliesDlsWhenSearchHasNoSource() {
        SearchRequest searchRequest = new SearchRequest();
        BoolQueryBuilder dlsQuery = createDlsQuery();

        SearchSourceBuilder searchSource = DlsFilterLevelActionHandler.getOrCreateSearchSource(searchRequest);
        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.FILTER_LEVEL);

        assertThat(searchRequest.source(), sameInstance(searchSource));
        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void preservesExistingSearchSource() {
        SearchSourceBuilder existingSearchSource = SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery());
        SearchRequest searchRequest = new SearchRequest().source(existingSearchSource);

        SearchSourceBuilder searchSource = DlsFilterLevelActionHandler.getOrCreateSearchSource(searchRequest);

        assertThat(searchSource, sameInstance(existingSearchSource));
        assertThat(searchRequest.source(), sameInstance(existingSearchSource));
    }

    @Test
    public void filterLevelDlsMarkerPreventsReentry() {
        assertDlsMarkerPreventsReentry("true");
    }

    @Test
    public void topLevelQueryDlsMarkerPreventsReentry() {
        assertDlsMarkerPreventsReentry(ConfigConstants.OPENDISTRO_SECURITY_TOP_LEVEL_QUERY_DLS_DONE);
    }

    @Test
    public void unmarkedClusterActionUsesNormalDispatchChecks() {
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        when(context.getAction()).thenReturn("cluster:test");
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);

        boolean result = DlsFilterLevelActionHandler.handle(
            context,
            null,
            null,
            null,
            null,
            null,
            threadContext,
            DlsFilterApplication.FILTER_LEVEL
        );

        assertThat(result, is(true));
    }

    @Test
    public void wrapsTopLevelCapableQueryForFilterLevelDls() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(topLevelQuery);

        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.FILTER_LEVEL);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), contains(sameInstance(topLevelQuery)));
        verify(topLevelQuery, never()).filter(dlsQuery);
    }

    @Test
    public void rejectsNoneAsAQueryModificationStrategy() {
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery());

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, DlsFilterApplication.NONE)
        );

        assertThat(exception.getMessage(), is("DLS filter application must modify the query"));
    }

    private static BoolQueryBuilder createDlsQuery() {
        return QueryBuilders.boolQuery().minimumShouldMatch(1).should(QueryBuilders.termQuery("tenant", "allowed"));
    }

    private static void assertDlsMarkerPreventsReentry(String headerValue) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, headerValue);

        boolean result = DlsFilterLevelActionHandler.handle(
            null,
            null,
            null,
            null,
            null,
            null,
            threadContext,
            DlsFilterApplication.FILTER_LEVEL
        );

        assertThat(result, is(true));
    }
}
