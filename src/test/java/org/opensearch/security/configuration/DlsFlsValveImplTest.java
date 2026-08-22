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

import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.startree.StarTreeQueryContext;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsBaseContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsProcessedConfig;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DlsFlsValveImplTest {

    @Test
    public void appliesDlsFilterToCapableTopLevelQueryInAdaptiveMode() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, true);

        assertThat(result, is(DlsFilterApplication.TOP_LEVEL_QUERY));
    }

    @Test
    public void queryNameAloneDoesNotEnableTopLevelFiltering() {
        QueryBuilder query = mock(QueryBuilder.class);
        when(query.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(query));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void usesFilterLevelDlsForTermLookupQueryInAdaptiveMode() {
        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(mock(ActionRequest.class), true, true, true, true);

        assertThat(result, is(DlsFilterApplication.FILTER_LEVEL));
    }

    @Test
    public void termLookupTakesPrecedenceOverTopLevelQueryFiltering() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, true, true, true);

        assertThat(result, is(DlsFilterApplication.FILTER_LEVEL));
    }

    @Test
    public void usesLuceneLevelDlsForRegularQueryInAdaptiveMode() {
        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(
            mock(ActionRequest.class),
            true,
            false,
            true,
            true
        );

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotUseFilterLevelDlsWithoutDlsRestrictions() {
        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(
            mock(ActionRequest.class),
            false,
            true,
            true,
            true
        );

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void topLevelQueryDlsMarkerPreventsValveReentry() throws Exception {
        assertDlsMarkerPreventsValveReentry(ConfigConstants.OPENDISTRO_SECURITY_TOP_LEVEL_QUERY_DLS_DONE);
    }

    @Test
    public void filterLevelDlsMarkerPreventsValveReentry() throws Exception {
        assertDlsMarkerPreventsValveReentry("true");
    }

    private static void assertDlsMarkerPreventsValveReentry(String headerValue) throws Exception {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, headerValue);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("test-user"));
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        OptionallyResolvedIndices resolved = mock(OptionallyResolvedIndices.class);
        when(context.getAction()).thenReturn("indices:data/read/search[phase/query]");
        when(context.getRequest()).thenReturn(new SearchRequest());
        when(context.getResolvedIndices()).thenReturn(resolved);

        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        when(documentPrivileges.isUnrestricted(context, resolved)).thenReturn(false);
        FieldPrivileges fieldPrivileges = mock(FieldPrivileges.class);
        when(fieldPrivileges.isUnrestricted(context, resolved)).thenReturn(true);
        FieldMasking fieldMasking = mock(FieldMasking.class);
        when(fieldMasking.isUnrestricted(context, resolved)).thenReturn(true);
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        when(config.getFieldPrivileges()).thenReturn(fieldPrivileges);
        when(config.getFieldMasking()).thenReturn(fieldMasking);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.config()).thenReturn(config);

        ClusterService clusterService = mock(ClusterService.class);
        @SuppressWarnings("unchecked")
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting = mock(OpensearchDynamicSetting.class);
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(false);
        DlsFlsValveImpl valve = new DlsFlsValveImpl(
            Settings.EMPTY,
            mock(Client.class),
            clusterService,
            NamedXContentRegistry.EMPTY,
            threadPool,
            baseContext,
            mock(AdminDNs.class),
            mock(ResourcePluginInfo.class),
            resourceSharingEnabledSetting
        );

        boolean result = valve.invoke(context, mock(ActionListener.class));

        assertThat(result, is(true));
        verify(clusterService, never()).state();
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchHasNoSourceInAdaptiveMode() {
        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(new SearchRequest(), true, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchSourceHasNoQueryInAdaptiveMode() {
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource());

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void usesLuceneLevelDlsForNonSearchRequestInAdaptiveMode() {
        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(
            mock(ActionRequest.class),
            true,
            false,
            true,
            true
        );

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotSelectDlsModeForCapableQueryWithoutDlsRestrictions() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, false, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotApplyTopLevelQueryFilterWhenClusterContainsOlderNode() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, false, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotApplyTopLevelQueryFilterForCrossClusterSearch() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, false);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotApplyTopLevelQueryFilterWhenCapableQueryIsNotTopLevel() {
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        BoolQueryBuilder outerQuery = new BoolQueryBuilder().must(topLevelQuery);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(outerQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void doesNotApplyTopLevelQueryFilterForParentChildQuery() {
        QueryBuilder parentChildQuery = mock(QueryBuilder.class);
        when(parentChildQuery.getWriteableName()).thenReturn("has_child");
        QueryBuilder topLevelQuery = mock(QueryBuilder.class);
        when(topLevelQuery.supportsTopLevelFilter()).thenReturn(true);
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(parentChildQuery);
            return null;
        }).when(topLevelQuery).visit(any(QueryBuilderVisitor.class));
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(topLevelQuery));

        DlsFilterApplication result = DlsFlsValveImpl.selectAdaptiveDlsFilterApplication(searchRequest, true, false, true, true);

        assertThat(result, is(DlsFilterApplication.NONE));
    }

    @Test
    public void topLevelQueryDlsFilterRequiresOpenSearchThreeNineOnEveryNode() {
        assertThat(DlsFlsValveImpl.isTopLevelQueryDlsFilterSupported(null), is(false));
        assertThat(DlsFlsValveImpl.isTopLevelQueryDlsFilterSupported(Version.V_3_8_0), is(false));
        assertThat(DlsFlsValveImpl.isTopLevelQueryDlsFilterSupported(Version.V_3_9_0), is(true));
    }

    @Test
    public void disablesStarTreeBeforeSkippingTopLevelQueryWrapping() throws Exception {
        String index = "index";
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.isDlsQueryFilterApplied()).thenReturn(true);
        PrivilegesEvaluationContext privilegesEvaluationContext = mock(PrivilegesEvaluationContext.class);
        when(baseContext.getPrivilegesEvaluationContext()).thenReturn(privilegesEvaluationContext);

        DlsRestriction dlsRestriction = mock(DlsRestriction.class);
        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        when(documentPrivileges.getRestriction(privilegesEvaluationContext, index)).thenReturn(dlsRestriction);
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        when(config.getFieldPrivileges()).thenReturn(mock(FieldPrivileges.class));
        when(config.getFieldMasking()).thenReturn(mock(FieldMasking.class));
        when(baseContext.config()).thenReturn(config);

        SearchContext searchContext = mock(SearchContext.class);
        IndexMetadata indexMetadata = IndexMetadata.builder(index)
            .settings(Settings.builder().put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT))
            .numberOfShards(1)
            .numberOfReplicas(0)
            .build();
        IndexSettings indexSettings = new IndexSettings(indexMetadata, Settings.EMPTY);
        IndexShard indexShard = mock(IndexShard.class);
        when(indexShard.indexSettings()).thenReturn(indexSettings);
        when(searchContext.indexShard()).thenReturn(indexShard);
        QueryShardContext queryShardContext = mock(QueryShardContext.class);
        when(queryShardContext.getStarTreeQueryContext()).thenReturn(mock(StarTreeQueryContext.class));
        when(searchContext.getQueryShardContext()).thenReturn(queryShardContext);

        ClusterService clusterService = mock(ClusterService.class);
        @SuppressWarnings("unchecked")
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting = mock(OpensearchDynamicSetting.class);
        DlsFlsValveImpl valve = new DlsFlsValveImpl(
            Settings.EMPTY,
            mock(Client.class),
            clusterService,
            NamedXContentRegistry.EMPTY,
            threadPool,
            baseContext,
            mock(AdminDNs.class),
            mock(ResourcePluginInfo.class),
            resourceSharingEnabledSetting
        );

        valve.handleSearchContext(searchContext, threadPool);

        verify(queryShardContext).setStarTreeQueryContext(null);
        verify(dlsRestriction, never()).toBooleanQueryBuilder(any(), any());
    }
}
