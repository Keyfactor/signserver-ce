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
package org.signserver.test.conf;

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
