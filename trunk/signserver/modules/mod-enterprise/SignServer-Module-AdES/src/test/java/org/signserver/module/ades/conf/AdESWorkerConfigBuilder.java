/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.conf;

import org.signserver.common.WorkerConfig;
import org.signserver.module.ades.AdESWorkerConfigProperty;
import org.signserver.test.conf.WorkerConfigBuilder;

/**
 * This is a help class to define a WorkerConfig for AdES tests. It contains withXYZ methods to chain
 * the configuration.
 *
 * @see org.signserver.test.conf.WorkerConfigBuilder
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class AdESWorkerConfigBuilder extends WorkerConfigBuilder {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends WorkerConfigBuilder.Builder<Builder> {

        private String signatureFormat;
        private String signatureLevel;
        private String signatureAlgorithm;
        private String digestAlgorithm;
        private String tsaWorker;
        private String tsaUrl;
        private String addContentTimestamp;
        private String trustAnchors;
        private String signaturePackaging;
        private String extraSignatureSpace;

        public Builder withSignatureFormat(final String signatureFormat) {
            this.signatureFormat = signatureFormat;
            return this;
        }

        public Builder withSignatureLevel(final String signatureLevel) {
            this.signatureLevel = signatureLevel;
            return this;
        }

        public Builder withSignatureAlgorithm(final String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public Builder withDigestAlgorithm(final String digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
            return this;
        }

        public Builder withTsaWorker(final String tsaWorker) {
            this.tsaWorker = tsaWorker;
            return this;
        }

        public Builder withTsaUrl(final String tsaUrl) {
            this.tsaUrl = tsaUrl;
            return this;
        }

        public Builder withAddContentTimestamp(final String addContentTimestamp) {
            this.addContentTimestamp = addContentTimestamp;
            return this;
        }

        public Builder withTrustAnchors(final String trustAnchors) {
            this.trustAnchors = trustAnchors;
            return this;
        }

        public Builder withSignaturePackaging(final String signaturePackaging) {
            this.signaturePackaging = signaturePackaging;
            return this;
        }

        public Builder withExtraSignatureSpace(final String extraSignatureSpace) {
            this.extraSignatureSpace = extraSignatureSpace;
            return this;
        }

        @Override
        public Builder getThis() {
            return this;
        }

        public WorkerConfig build() {
            final WorkerConfig config = super.build();
            if(signatureFormat != null) {
                config.setProperty(AdESWorkerConfigProperty.SIGNATURE_FORMAT, signatureFormat);
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
                config.setProperty("TSA_WORKER", tsaWorker);
            }
            if(tsaUrl !=  null) {
                config.setProperty("TSA_URL", tsaUrl);
            }
            if(addContentTimestamp != null) {
                config.setProperty("ADD_CONTENT_TIMESTAMP", addContentTimestamp);
            }
            if (trustAnchors != null) {
                config.setProperty("TRUSTANCHORS", trustAnchors);
            }
            if(signaturePackaging != null) {
                config.setProperty(AdESWorkerConfigProperty.SIGNATURE_PACKAGING, signaturePackaging);
            }
            if (extraSignatureSpace != null) {
                config.setProperty("EXTRA_SIGNATURE_SPACE", extraSignatureSpace);
            }

            return config;
        }
    }
}
