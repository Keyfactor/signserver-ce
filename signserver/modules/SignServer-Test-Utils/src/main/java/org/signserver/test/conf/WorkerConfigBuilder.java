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
import org.signserver.common.worker.WorkerConfigProperty;

/**
 * This is a help class to define a configuration of a Worker for tests. It contains withXYZ methods to chain
 * the configuration.
 *
 * @author Andrey Sergeev
 * @version $Id: WorkerConfigBuilder.java 12421 2021-01-20 11:52:00Z andrey_s_helmes $
 */
public class WorkerConfigBuilder {

    private Integer workerId;
    private String workerName;
    private String workerType;
    private String signatureFormat;
    private String signatureLevel;
    private String signatureAlgorithm;
    private String digestAlgorithm;
    private String tsaWorker;
    private String tsaUrl;
    private String addContentTimestamp;

    public static WorkerConfigBuilder builder() {
        return new WorkerConfigBuilder();
    }

    /**
     * Returns the WorkerConfig defined by input.
     *
     * @return the WorkerConfig defined by input.
     */
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
        if(signatureFormat != null) {
            config.setProperty(WorkerConfigProperty.AdES_SIGNATURE_FORMAT, signatureFormat);
        }
        if(signatureLevel != null) {
            config.setProperty("SIGNATURE_LEVEL", signatureLevel);
        }
        if(signatureAlgorithm != null) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
        }
        if(digestAlgorithm !=  null) {
            config.setProperty("DIGESTALGORITHM", digestAlgorithm);
        }
        if(tsaWorker != null) {
            config.setProperty("TSA_WORKER", "TimeStampSigner");
        }
        if(tsaUrl !=  null) {
            config.setProperty("TSA_URL", tsaUrl);
        }
        if(addContentTimestamp != null) {
            config.setProperty("ADD_CONTENT_TIMESTAMP", addContentTimestamp);
        }
        return config;
    }

    public WorkerConfigBuilder withWorkerId(final int workerId) {
        this.workerId = workerId;
        return this;
    }

    public WorkerConfigBuilder  withWorkerName(final String workerName) {
        this.workerName = workerName;
        return this;
    }

    public WorkerConfigBuilder withWorkerType(final String workerType) {
        this.workerType = workerType;
        return this;
    }

    public WorkerConfigBuilder withSignatureFormat(final String signatureFormat) {
        this.signatureFormat = signatureFormat;
        return this;
    }

    public WorkerConfigBuilder withSignatureLevel(final String signatureLevel) {
        this.signatureLevel = signatureLevel;
        return this;
    }

    public WorkerConfigBuilder withSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public WorkerConfigBuilder withDigestAlgorithm(final String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    public WorkerConfigBuilder withTsaWorker(final String tsaWorker) {
        this.tsaWorker = tsaWorker;
        return this;
    }

    public WorkerConfigBuilder withTsaUrl(final String tsaUrl) {
        this.tsaUrl = tsaUrl;
        return this;
    }

    public WorkerConfigBuilder withAddContentTimestamp(final String addContentTimestamp) {
        this.addContentTimestamp = addContentTimestamp;
        return this;
    }
}
