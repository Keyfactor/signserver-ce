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
package org.signserver.module.tsa.conf;

import java.io.File;
import java.io.FileNotFoundException;

import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PathUtil;
import org.signserver.test.conf.WorkerConfigBuilder;

/**
 * This is a help class to define a WorkerConfig for TSA tests. It contains withXYZ methods to chain
 * the configuration.
 *
 * @see org.signserver.test.conf.WorkerConfigBuilder
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class TSAWorkerConfigBuilder extends WorkerConfigBuilder {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends WorkerConfigBuilder.Builder<Builder> {

        private String authType;
        private String defaultTsaPolicyOid;
        private String defaultKey;
        private String acceptedExtensions;
        private String keystorePath;
        private String keystoreType;
        private String keystorePassword;
        private Boolean acceptAnyPolicy;
        private String acceptedPolicies;

        /**
         * Sets the property AUTH_TYPE to value.
         * @param authType authentication type value.
         * @see TSAWorkerConfigProperty#AUTH_TYPE
         * @return Builder
         */
        public Builder withAuthType(final String authType) {
            this.authType = authType;
            return this;
        }

        /**
         * Sets the property AUTH_TYPE to "NOAUTH" value.
         * @see TSAWorkerConfigProperty#AUTH_TYPE
         * @return Builder
         */
        public Builder withNoAuthAuthType() {
            return withAuthType("NOAUTH");
        }

        /**
         * Sets the property DEFAULT_TSA_POLICY_OID value.
         * @param tsaPolicyOid TSA policy OID value.
         * @see TSAWorkerConfigProperty#DEFAULT_TSA_POLICY_OID
         * @return Builder
         */
        public Builder withDefaultTsaPolicyOid(final String tsaPolicyOid) {
            this.defaultTsaPolicyOid = tsaPolicyOid;
            return this;
        }

        /**
         * Sets the property DEFAULT_KEY value.
         * @param defaultKey default key value.
         * @see TSAWorkerConfigProperty#DEFAULT_KEY
         * @return Builder
         */
        public Builder withDefaultKey(final String defaultKey) {
            this.defaultKey = defaultKey;
            return this;
        }

        /**
         * Sets the property ACCEPTED_EXTENSIONS value.
         * @param acceptedExtensions accepted extensions value.
         * @see TSAWorkerConfigProperty#ACCEPTED_EXTENSIONS
         * @return Builder
         */
        public Builder withAcceptedExtensions(final String acceptedExtensions) {
            this.acceptedExtensions = acceptedExtensions;
            return this;
        }

        /**
         * Sets the property KEYSTORE_PATH value.
         * @param keystorePath keystore path value.
         * @see TSAWorkerConfigProperty#KEYSTORE_PATH
         * @return Builder
         */
        public Builder withKeystorePath(final String keystorePath) {
            this.keystorePath = keystorePath;
            return this;
        }

        /**
         * Sets the property KEYSTORE_TYPE value.
         * @param keystoreType keystore type value.
         * @see TSAWorkerConfigProperty#KEYSTORE_TYPE
         * @return Builder
         */
        public Builder withKeystoreType(final String keystoreType) {
            this.keystoreType = keystoreType;
            return this;
        }

        /**
         * Sets the property KEYSTORE_PASSWORD value.
         * @param keystorePassword keystore password value.
         * @see TSAWorkerConfigProperty#KEYSTORE_PASSWORD
         * @return Builder
         */
        public Builder withKeystorePassword(final String keystorePassword) {
            this.keystorePassword = keystorePassword;
            return this;
        }

        /**
         * Initialises default key and keystore as:
         * <ul>
         *     <li>DEFAULTKEY: ts00001;</li>
         *     <li>KeystorePath: [SignServer_Home_Dir]/res/test/dss10/dss10_keystore.p12;</li>
         *     <li>KeystoreType: PKCS12;</li>
         *     <li>KeystorePassword: foo123.</li>
         * </ul>
         * @return Builder
         * @throws FileNotFoundException in case of SignServer home allocation.
         */
        public Builder withDss10p12Keystore() throws FileNotFoundException {
            return withDefaultKey("ts00001")
                    .withKeystorePath(
                            PathUtil.getAppHome() + File.separator +
                            "res" + File.separator +
                            "test" + File.separator +
                            "dss10" + File.separator + "dss10_keystore.p12")
                    .withKeystoreType("PKCS12")
                    .withKeystorePassword("foo123");
        }

        /**
         * Sets the property ACCEPT_ANY_POLICY flag.
         * @param acceptAnyPolicy accept any policy flag.
         * @see TSAWorkerConfigProperty#ACCEPT_ANY_POLICY
         * @return Builder
         */
        public Builder withAcceptAnyPolicy(final boolean acceptAnyPolicy) {
            this.acceptAnyPolicy = acceptAnyPolicy;
            return this;
        }

        /**
         * Sets the property ACCEPTED_POLICIES value.
         * @param acceptedPolicies accepted policies value.
         * @see TSAWorkerConfigProperty#ACCEPTED_POLICIES
         * @return Builder
         */
        public Builder withAcceptedPolicies(final String acceptedPolicies) {
            this.acceptedPolicies = acceptedPolicies;
            return this;
        }

        @Override
        public Builder getThis() {
            return this;
        }

        public WorkerConfig build() {
            final WorkerConfig config = super.build();
            if (authType != null) {
                config.setProperty(TSAWorkerConfigProperty.AUTH_TYPE, authType);
            }
            if(defaultTsaPolicyOid != null) {
                config.setProperty(TSAWorkerConfigProperty.DEFAULT_TSA_POLICY_OID, defaultTsaPolicyOid);
            }
            if(defaultKey != null) {
                config.setProperty(TSAWorkerConfigProperty.DEFAULT_KEY, defaultKey);
            }
            if(acceptedExtensions != null) {
                config.setProperty(TSAWorkerConfigProperty.ACCEPTED_EXTENSIONS, acceptedExtensions);
            }
            if(keystorePath != null) {
                config.setProperty(TSAWorkerConfigProperty.KEYSTORE_PATH, keystorePath);
            }
            if(keystoreType != null) {
                config.setProperty(TSAWorkerConfigProperty.KEYSTORE_TYPE, keystoreType);
            }
            if(keystorePassword != null) {
                config.setProperty(TSAWorkerConfigProperty.KEYSTORE_PASSWORD, keystorePassword);
            }
            if(acceptAnyPolicy != null) {
                config.setProperty(TSAWorkerConfigProperty.ACCEPT_ANY_POLICY, acceptAnyPolicy.toString());
            }
            if(acceptedPolicies != null) {
                config.setProperty(TSAWorkerConfigProperty.ACCEPTED_POLICIES, acceptedPolicies);
            }
            return config;
        }
    }
}
