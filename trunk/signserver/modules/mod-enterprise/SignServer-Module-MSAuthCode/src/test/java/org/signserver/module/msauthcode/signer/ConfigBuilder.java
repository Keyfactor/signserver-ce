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
package org.signserver.module.msauthcode.signer;

import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;

/**
 * Utility class for setting up worker configurations for Authcode signers.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ConfigBuilder {
    private final WorkerConfig config = createConfig();
        
    private static WorkerConfig createConfig() {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        return config;
    }
        
    public ConfigBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
        return this;
    }

    public ConfigBuilder withDigestAlgorithm(String digestAlgorithm) {
        config.setProperty("DIGESTALGORITHM", digestAlgorithm);
        return this;
    }

    public ConfigBuilder withProgramName(String programName) {
        config.setProperty("PROGRAM_NAME", programName);
        return this;
    }

    public ConfigBuilder withProgramURL(String programURL) {
        config.setProperty("PROGRAM_URL", programURL);
        return this;
    }

    public ConfigBuilder withAllowProgramNameOverride(Boolean allowProgramNameOverride) {
        if (allowProgramNameOverride != null) {
            config.setProperty("ALLOW_PROGRAM_NAME_OVERRIDE", String.valueOf(allowProgramNameOverride));
        }
        return this;
    }

    public ConfigBuilder withAllowProgramURLOverride(Boolean allowProgramURLOverride) {
        if (allowProgramURLOverride != null) {
            config.setProperty("ALLOW_PROGRAM_URL_OVERRIDE", String.valueOf(allowProgramURLOverride));
        }
        return this;
    }

    public ConfigBuilder withLogRequestDigest(String logRequestDigest) {
        config.setProperty("LOGREQUEST_DIGESTALGORITHM", logRequestDigest);
        return this;
    }

    public ConfigBuilder withLogResponseDigest(String logResponseDigest) {
        config.setProperty("LOGRESPONSE_DIGESTALGORITHM", logResponseDigest);
        return this;
    }

    public ConfigBuilder withDoLogRequestDigest(boolean doLogRequestDigest) {
        config.setProperty("DO_LOGREQUEST_DIGEST", String.valueOf(doLogRequestDigest));
        return this;
    }

    public ConfigBuilder withDoLogResponseDigest(boolean doLogResponseDigest) {
        config.setProperty("DO_LOGRESPONSE_DIGEST", String.valueOf(doLogResponseDigest));
        return this;
    }

    public ConfigBuilder withTimestampFormat(String timestampFormat) {
        config.setProperty("TIMESTAMP_FORMAT", timestampFormat);
        return this;
    }

    public ConfigBuilder withNoRequestArchiving(String noRequestArchiving) {
        config.setProperty("NO_REQUEST_ARCHIVING", noRequestArchiving);
        return this;
    }

    public ConfigBuilder withTsaUrl(String url) {
        config.setProperty("TSA_URL", url);
        return this;
    }

    public WorkerConfig create() {
        return config;
    }
}
