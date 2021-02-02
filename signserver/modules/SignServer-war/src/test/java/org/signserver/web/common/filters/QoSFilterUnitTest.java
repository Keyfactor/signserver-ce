/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.web.common.filters;

import java.util.Enumeration;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import static org.signserver.common.GlobalConfiguration.SCOPE_GLOBAL;
import org.signserver.ejb.interfaces.GlobalConfigurationSession;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;

import static org.signserver.web.common.filters.QoSFilterProperties.QOS_CACHE_TTL_S;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_FILTER_ENABLED;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_MAX_PRIORITY;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_MAX_REQUESTS;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_PRIORITIES;

/**
 * Unit tests for the QoSFilter.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSFilterUnitTest {

    // Test that global configuration cache is created once at filter init and values are cached.
    @Test
    public void globalPropertiesCachedAtInit() {
        // given
        // on init cache should be created
        final int expectedInitialCacheRecreations = 1;
        final int expectedCacheSize = 5;
        final MockedQoSFilter filter = new MockedQoSFilter();
        filter.setGlobalProperty(QOS_FILTER_ENABLED, "true");
        filter.setGlobalProperty(QOS_MAX_REQUESTS, "1");
        filter.setGlobalProperty(QOS_MAX_PRIORITY, "1");
        filter.setGlobalProperty(QOS_PRIORITIES, "1:1");
        filter.setGlobalProperty(QOS_CACHE_TTL_S, "1");
        // when
        filter.init(new MockedFilterConfig());
        // then
        assertEquals(
                "Number of cache recreations",
                expectedInitialCacheRecreations,
                filter.getNumberOfCacheRecreations()
        );
        assertEquals("Expected proper cache size", expectedCacheSize, filter.getCacheMap().size());
    }

    // Test that global properties cache is not recreated when accessing a global property directly after init.
    @Test
    public void globalPropertiesNotRecreated() {
        // given
        // after (immediately) getting a property value, cache should not have been recreated
        final int expectedCacheRecreationsAfterOneRequest = 1;
        final int expectedCacheSize = 1;
        final MockedQoSFilter filter = new MockedQoSFilter();
        filter.setGlobalProperty(QOS_FILTER_ENABLED, "true");
        // when
        filter.init(new MockedFilterConfig());
        final String maxPriority = filter.getGlobalPropertyFromCache(QOS_MAX_PRIORITY);
        // then
        assertEquals("Number of cache recreations",
                     expectedCacheRecreationsAfterOneRequest,
                     filter.getNumberOfCacheRecreations());
        assertNull("Max priority is not set", maxPriority);
        assertEquals("Expected proper cache size", expectedCacheSize, filter.getCacheMap().size());
    }

    // Test that setting a global property will not immediately use the new value (i.e. still using cache).
    @Test
    public void globalPropertyCached() {
        // given
        // after (immediately) setting a property value, cache should not have been recreated
        final int expectedCacheRecreationsAfterOneRequest = 1;
        final int expectedCacheSize = 1;
        final MockedQoSFilter filter = new MockedQoSFilter();
        filter.setGlobalProperty(QOS_FILTER_ENABLED, "true");
        // when
        filter.init(new MockedFilterConfig());
        final String maxPriority = filter.getGlobalPropertyFromCache(QOS_MAX_PRIORITY);
        // then
        assertEquals("Number of cache recreations",
                     expectedCacheRecreationsAfterOneRequest,
                     filter.getNumberOfCacheRecreations());
        assertNull("Max priority is not set", maxPriority);
        assertEquals("Expected proper cache size", expectedCacheSize, filter.getCacheMap().size());
    }

    // Test that setting a global property will not immediately use the new value (i.e. still using cache).
    @Test
    public void globalPropertyCacheRecreated() throws InterruptedException {
        // given
        // after (immediately) setting a property value, cache should not have been recreated
        final int expectedCacheRecreationsBeforeTimeout = 1;
        final int expectedCacheSizeBeforeTimeout = 2;
        final int expectedCacheRecreationsAfterTimeout = 2;
        final int expectedCacheSizeAfterTimeout = 4;
        final String expectedMaxPriorityAfterTimeout = "111";
        final String expectedMaxRequestsAfterTimeout = "11";
        final MockedQoSFilter filter = new MockedQoSFilter();
        filter.setGlobalProperty(QOS_FILTER_ENABLED, "true");
        filter.setGlobalProperty(QOS_CACHE_TTL_S, "1");
        // when
        filter.init(new MockedFilterConfig());
        final String maxPriorityBeforeTimeout = filter.getGlobalPropertyFromCache(QOS_MAX_PRIORITY);
        final String maxRequestsBeforeTimeout = filter.getGlobalPropertyFromCache(QOS_MAX_REQUESTS);
        // then
        assertNull("Max priority is not set", maxPriorityBeforeTimeout);
        assertNull("Max requests is not set", maxRequestsBeforeTimeout);
        assertEquals("Number of cache recreations",
                expectedCacheRecreationsBeforeTimeout,
                filter.getNumberOfCacheRecreations());
        assertEquals("Expected proper cache size", expectedCacheSizeBeforeTimeout, filter.getCacheMap().size());
        // when
        filter.setGlobalProperty(QOS_MAX_PRIORITY, expectedMaxPriorityAfterTimeout);
        filter.setGlobalProperty(QOS_MAX_REQUESTS, expectedMaxRequestsAfterTimeout);
        Thread.sleep((filter.getCacheTtlS() + 1) * 1000);
        final String maxPriorityAfterTimeout = filter.getGlobalPropertyFromCache(QOS_MAX_PRIORITY);
        final String maxRequestsAfterTimeout = filter.getGlobalPropertyFromCache(QOS_MAX_REQUESTS);
        // then
        assertEquals("Number of cache recreations 2",
                expectedCacheRecreationsAfterTimeout,
                filter.getNumberOfCacheRecreations());
        assertEquals("Max priority", expectedMaxPriorityAfterTimeout, maxPriorityAfterTimeout);
        assertEquals("Max requests", maxRequestsAfterTimeout, maxRequestsAfterTimeout);
        assertEquals("Expected proper cache size", expectedCacheSizeAfterTimeout, filter.getCacheMap().size());
    }

    @Test
    public void shouldNotLoadCacheIfDisabled() throws Exception {
        // given
        final int expectedCacheSize = 1;
        final int expectedCacheRecreationsBeforeTimeout = 1;
        final int expectedCacheRecreationsAfterTimeout = 2;
        final MockedQoSFilter filter = new MockedQoSFilter();
        filter.setGlobalProperty(QOS_FILTER_ENABLED, "false");
        // when
        filter.init(new MockedFilterConfig());
        // then
        assertEquals("Number of cache recreations",
                expectedCacheRecreationsBeforeTimeout,
                filter.getNumberOfCacheRecreations());
        assertEquals("Expected proper cache size", expectedCacheSize, filter.getCacheMap().size());
        // when
        filter.setGlobalProperty(QOS_MAX_PRIORITY, "1");
        Thread.sleep((filter.getCacheTtlS() + 1) * 1000);
        final String maxPriorityAfterTimeout = filter.getGlobalPropertyFromCache(QOS_MAX_PRIORITY);
        // then
        assertEquals("Number of cache recreations 2",
                expectedCacheRecreationsAfterTimeout,
                filter.getNumberOfCacheRecreations());
        assertNull("Max priority is not set", maxPriorityAfterTimeout);
        assertEquals("Expected proper cache size", expectedCacheSize, filter.getCacheMap().size());
    }

    /**
     * Mocked implementation of the QoSFilter, keeping track of global property cache recreations and overriding global
     * property backing to use a GlobalConfigurationSessionMock to allow instrumenting property setting/getting.
     */
    private static class MockedQoSFilter extends QoSFilter {
        // keeps track of the number of times the global config cache has be recreated
        private int numberOfCacheRecreations;

        private final GlobalConfigurationSessionMock globalSession = new GlobalConfigurationSessionMock();

        public MockedQoSFilter() {
            numberOfCacheRecreations = 0;
        }

        /**
         * Get number of times recreateGlobalPropertyCache was invoked to read global properties from the session.
         *
         * @return the number of cache recreation times.
         */
        public int getNumberOfCacheRecreations() {
            return numberOfCacheRecreations;
        }

        /**
         * Set a global property on the mocked global session.
         *
         * @param property name of global property (with scope GLOB)
         * @param value value to set
         */
        public void setGlobalProperty(final String property, final String value) {
            globalSession.setProperty(SCOPE_GLOBAL, property, value);
        }

        @Override
        protected GlobalConfigurationSession getGlobalConfigurationSession() {
            return globalSession;
        }

        @Override
        protected void recreateGlobalPropertyCache() {
            numberOfCacheRecreations++;
            super.recreateGlobalPropertyCache();
        }

        @Override
        public long getCacheTtlS() {
            return 1L;
        }
    }

    /**
     * Mocked implementation of FilterConfig implementing enough to be able to init() the web filter outside of a real
     * servlet container.
     */
    private static class MockedFilterConfig implements FilterConfig {

        @Override
        public String getFilterName() {
            return "MockedQoSFilter";
        }

        @Override
        public ServletContext getServletContext() {
            // just return null, as the filter can handle null context
            return null;
        }

        @Override
        public String getInitParameter(String arg0) {
            // just return a dummy value, it will not actually be used
            return "0";
        }

        @Override
        public Enumeration<String> getInitParameterNames() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
