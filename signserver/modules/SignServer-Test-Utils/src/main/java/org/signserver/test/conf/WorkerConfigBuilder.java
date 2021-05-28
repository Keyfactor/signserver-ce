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

import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;

/**
 * This is an abstract help class to define a WorkerConfig for tests. It contains withXYZ methods to chain
 * the configuration.
 *
 * @author Andrey Sergeev
 * @version $Id: WorkerConfigBuilder.java 12421 2021-01-20 11:52:00Z andrey_s_helmes $
 */
public class WorkerConfigBuilder {

    @SuppressWarnings("rawtypes")
    public static Builder builder() {
        return new Builder() {
            @Override
            public Builder<?> getThis() {
                return this;
            }
        };
    }

    public abstract static class Builder<T extends Builder<T>> {

        private Integer workerId;
        private String workerName;
        private String workerType;

        public abstract T getThis();

        public T withWorkerId(final int workerId) {
            this.workerId = workerId;
            return this.getThis();
        }

        public T withWorkerName(final String workerName) {
            this.workerName = workerName;
            return this.getThis();
        }

        public T withWorkerType(final String workerType) {
            this.workerType = workerType;
            return this.getThis();
        }

        public WorkerConfig build() {
            final WorkerConfig config = new WorkerConfig();
            if(workerId != null) {
                config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
            }
            if(workerName != null) {
                config.setProperty("NAME", workerName);
            }
            if(workerType != null) {
                config.setProperty(WorkerConfig.TYPE, workerType);
            }
            return config;
        }
    }
}
