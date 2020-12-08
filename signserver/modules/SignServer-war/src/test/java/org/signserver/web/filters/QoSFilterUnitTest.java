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
package org.signserver.web.filters;

import java.util.Enumeration;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import static org.signserver.common.GlobalConfiguration.SCOPE_GLOBAL;
import org.signserver.ejb.interfaces.GlobalConfigurationSession;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;

/**
 * Unit tests for the QoSFilter.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSFilterUnitTest {

    /**
     * Test that global configuration cache is created once at filter init.
     *
     */
    @Test
    public void globalPropertiesCachedAtInit() {
        // given
        // initially cache should be created
        final int expectedInitalCacheRecreations = 1;
        /* after (immediatly) getting a property value, cache should not have
         * been recreated
         */
        final int expectedCacheRecreationsAfterOneRequest = 1;

        // when
        final MockedQoSFilter filter = new MockedQoSFilter();

        filter.init(new MockedFilterConfig());

        // then
        assertEquals("Number of cache recreations",
                     expectedInitalCacheRecreations,
                     filter.getNumberOfCacheRecreations());
    }

    /**
     * Test that global properties cache is not recreated when accessing
     * a global property directly after init.
     *
     */
    @Test
    public void globalPropertiesNotRecreated() {
        // given
        /* after (immediatly) getting a property value, cache should not have
         * been recreated
         */
        final int expectedCacheRecreationsAfterOneRequest = 1;

        // when
        final MockedQoSFilter filter = new MockedQoSFilter();

        filter.init(new MockedFilterConfig());
        final String enabled = filter.getGlobalParam("QOS_FILTER_ENABLED");

        // then
        assertNull("Enabled not set", enabled);
        assertEquals("Number of cache recreations",
                     expectedCacheRecreationsAfterOneRequest,
                     filter.getNumberOfCacheRecreations());
    }

    /**
     * Test that setting a global property will not immediatly use the new
     * value (i.e. still using cache).
     *
     */
    @Test
    public void globalPropertyCached() {
        // given
        /* after (immediatly) setting a property value, cache should not have
         * been recreated
         */
        final int expectedCacheRecreationsAfterOneRequest = 1;

        // when
        final MockedQoSFilter filter = new MockedQoSFilter();

        filter.init(new MockedFilterConfig());
        filter.setGlobalProperty("QOS_FILTER_ENABLED", "true");
        final String enabled = filter.getGlobalParam("QOS_FILTER_ENABLED");

        // then
        assertNull("Enabled not set", enabled);
        assertEquals("Number of cache recreations",
                     expectedCacheRecreationsAfterOneRequest,
                     filter.getNumberOfCacheRecreations());
    }

    /**
     * Mocked implementation of the QoSFilter, keeping track of global
     * property cache recreations and overriding global property backing to
     * use a GlobalConfigurationSessionMock to allow instrumenting property
     * setting/getting.
     *
     */
    private static class MockedQoSFilter extends QoSFilter {
        // keeps track of the number of times the global config cache has be recreated
        private int numberOfCacheRecreations;

        private GlobalConfigurationSessionMock globalSession =
                new GlobalConfigurationSessionMock();
        
        public MockedQoSFilter() {
            numberOfCacheRecreations = 0;
        }

        /**
         * Get number of times recreateGlobalPropertyCache was invoked
         * to read global properties from the session.
         *
         * @return 
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
        GlobalConfigurationSession getGlobalConfigurationSession() {
            return globalSession;
        }

        @Override
        void recreateGlobalPropertyCache() {
            numberOfCacheRecreations++;
            super.recreateGlobalPropertyCache();
        }
        
    };

    /**
     * Mocked implementation of FilterConfig implementing enough to be able
     * to init() the web filter outside of a real servlet container.
     *
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
