/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

enum DlsFilterApplication {
    NONE,
    FILTER_LEVEL,
    TOP_LEVEL_QUERY;

    boolean appliesToQuery() {
        return this != NONE;
    }

    boolean preservesTopLevelQuery() {
        return this == TOP_LEVEL_QUERY;
    }
}
