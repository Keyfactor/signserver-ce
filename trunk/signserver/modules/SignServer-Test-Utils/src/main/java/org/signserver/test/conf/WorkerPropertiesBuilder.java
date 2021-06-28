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
 * This is a help class to define a configuration for a Worker for tests. It contains getters/setters and withXYZ
 * methods to chain the configuration.
 *
 * @author Andrey Sergeev 09-dec-2020
 * @version $Id$
 */
public class WorkerPropertiesBuilder {

    private int workerId;
    private String authType;
    private String user1;
    private boolean disableKeyUsageCounter;
    private Long sleepTime;
    private String workerLogger;

    public static WorkerPropertiesBuilder builder() {
        return new WorkerPropertiesBuilder();
    }

    public int getWorkerId() {
        return workerId;
    }

    public void setWorkerId(final int workerId) {
        this.workerId = workerId;
    }

    public WorkerPropertiesBuilder withWorkerId(final int workerId) {
        this.workerId = workerId;
        return this;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(final String authType) {
        this.authType = authType;
    }

    public WorkerPropertiesBuilder withAuthType(final String authType) {
        this.authType = authType;
        return this;
    }

    public String getUser1() {
        return user1;
    }

    public void setUser1(final String user1) {
        this.user1 = user1;
    }

    public WorkerPropertiesBuilder withUser1(final String user1) {
        this.user1 = user1;
        return this;
    }

    public boolean isDisableKeyUsageCounter() {
        return disableKeyUsageCounter;
    }

    public void setDisableKeyUsageCounter(final boolean disableKeyUsageCounter) {
        this.disableKeyUsageCounter = disableKeyUsageCounter;
    }

    public WorkerPropertiesBuilder withDisableKeyUsageCounter(final boolean disableKeyUsageCounter) {
        this.disableKeyUsageCounter = disableKeyUsageCounter;
        return this;
    }

    public Long getSleepTime() {
        return sleepTime;
    }

    public void setSleepTime(final long sleepTime) {
        this.sleepTime = sleepTime;
    }

    public WorkerPropertiesBuilder withSleepTime(final long sleepTime) {
        this.sleepTime = sleepTime;
        return this;
    }

    public String getWorkerLogger() {
        return workerLogger;
    }

    public void setWorkerLogger(final String workerLogger) {
        this.workerLogger = workerLogger;
    }

    public WorkerPropertiesBuilder withWorkerLogger(final String workerLogger) {
        this.workerLogger = workerLogger;
        return this;
    }
}
