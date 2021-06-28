/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.enterprise.web.filters;

/**
 * This is a help class to define a configuration for a QoSFilter. It contains getters/setters and withXYZ methods to
 * chain the configuration.
 *
 * @author Andrey Sergeev 18-jan-2021
 * @version $Id$
 */
public class QoSFilterPropertiesBuilder {

    private String filterEnabled;
    private String priorities;
    private String maxRequests;
    private String maxPriority;
    private String cacheTtl;

    public static QoSFilterPropertiesBuilder builder() {
        return new QoSFilterPropertiesBuilder();
    }

    public String getFilterEnabled() {
        return filterEnabled;
    }

    public QoSFilterPropertiesBuilder withFilterEnabled(final String filterEnabled) {
        this.filterEnabled = filterEnabled;
        return this;
    }

    public String getPriorities() {
        return priorities;
    }

    public QoSFilterPropertiesBuilder withPriorities(final String priorities) {
        this.priorities = priorities;
        return this;
    }

    public String getMaxRequests() {
        return maxRequests;
    }

    public QoSFilterPropertiesBuilder withMaxRequests(final String maxRequests) {
        this.maxRequests = maxRequests;
        return this;
    }

    public String getMaxPriority() {
        return maxPriority;
    }

    public QoSFilterPropertiesBuilder withMaxPriority(final String maxPriority) {
        this.maxPriority = maxPriority;
        return this;
    }

    public String getCacheTtl() {
        return cacheTtl;
    }

    public QoSFilterPropertiesBuilder withCacheTtl(final String cacheTtl) {
        this.cacheTtl = cacheTtl;
        return this;
    }
}
