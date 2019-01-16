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
package org.signserver.admin.gui;

import java.util.Collection;
import java.util.Properties;
import org.signserver.admin.gui.adminws.gen.AuthorizedClient;

/**
 * Class representing a worker and its status and configuration.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Worker {

    private final int workerId;
    private final String name;
    private final String statusSummary;
    private final Object[][] statusProperties;
    private final Object[][] configurationProperties;
    private final Properties configuration;
    private final boolean active;
    private final Collection<AuthorizedClient> authClients;
    private final boolean cryptoWorker;
    private final boolean cryptoConfigured;

    public Worker(int workerId, String name, String statusSummary,
            final Object[][] statusProperties,
            final Object[][] configurationProperties,
            final Properties configuration,
            final boolean active,
            final Collection<AuthorizedClient> authClients,
            final boolean cryptoWorker,
            final boolean cryptoConfigured) {
        this.workerId = workerId;
        this.name = name;
        this.statusSummary = statusSummary;
        this.statusProperties = statusProperties;
        this.configuration = configuration;
        this.configurationProperties = configurationProperties;
        this.active = active;
        this.authClients = authClients;
        this.cryptoWorker = cryptoWorker;
        this.cryptoConfigured = cryptoConfigured;
    }

    public String getName() {
        return name;
    }

    public int getWorkerId() {
        return workerId;
    }

    public String getStatusSummary() {
        return statusSummary;
    }

    public Object[][] getStatusProperties() {
        return statusProperties;
    }

    public Object[][] getConfigurationProperties() {
        return configurationProperties;
    }

    public Properties getConfiguration() {
        return configuration;
    }

    public boolean isActive() {
        return active;
    }

    public Collection<AuthorizedClient> getAuthClients() {
        return authClients;
    }

    public boolean isCryptoWorker() {
        return cryptoWorker;
    }

    public boolean isCryptoConfigured() {
        return cryptoConfigured;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Worker other = (Worker) obj;
        if (this.workerId != other.workerId) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + this.workerId;
        return hash;
    }

    @Override
    public String toString() {
        return "Worker[" + getName() + ", " + getWorkerId() + "]";
    }
}
