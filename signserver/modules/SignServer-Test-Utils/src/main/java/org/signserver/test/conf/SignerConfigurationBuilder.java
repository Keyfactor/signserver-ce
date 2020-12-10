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

import java.io.File;

/**
 * This is a help class to define a configuration for a Signer for tests. It contains getters/setters and withXYZ
 * methods to chain the configuration.
 *
 * @author Andrey Sergeev 09-dec-2020
 * @version $Id$
 */
public class SignerConfigurationBuilder {

    private String className;
    private String cryptoTokenClassName;
    private int signerId;
    private String signerName;
    private File keystore;
    private String keystorePassword;
    private String alias;
    private boolean autoActivate;

    public static SignerConfigurationBuilder builder() {
        return new SignerConfigurationBuilder();
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(final String className) {
        this.className = className;
    }

    public SignerConfigurationBuilder withClassName(final String className) {
        this.className = className;
        return this;
    }

    public String getCryptoTokenClassName() {
        return cryptoTokenClassName;
    }

    public void setCryptoTokenClassName(final String cryptoTokenClassName) {
        this.cryptoTokenClassName = cryptoTokenClassName;
    }

    public SignerConfigurationBuilder withCryptoTokenClassName(final String cryptoTokenClassName) {
        this.cryptoTokenClassName = cryptoTokenClassName;
        return this;
    }

    public int getSignerId() {
        return signerId;
    }

    public void setSignerId(final int signerId) {
        this.signerId = signerId;
    }

    public SignerConfigurationBuilder withSignerId(final int signerId) {
        this.signerId = signerId;
        return this;
    }

    public String getSignerName() {
        return signerName;
    }

    public void setSignerName(final String signerName) {
        this.signerName = signerName;
    }

    public SignerConfigurationBuilder withSignerName(final String signerName) {
        this.signerName = signerName;
        return this;
    }

    public File getKeystore() {
        return keystore;
    }

    public void setKeystore(final File keystore) {
        this.keystore = keystore;
    }

    public SignerConfigurationBuilder withKeystore(final File keystore) {
        this.keystore = keystore;
        return this;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(final String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public SignerConfigurationBuilder withKeystorePassword(final String keystorePassword) {
        this.keystorePassword = keystorePassword;
        return this;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(final String alias) {
        this.alias = alias;
    }

    public SignerConfigurationBuilder withAlias(final String alias) {
        this.alias = alias;
        return this;
    }

    public boolean isAutoActivate() {
        return autoActivate;
    }

    public void setAutoActivate(boolean autoActivate) {
        this.autoActivate = autoActivate;
    }

    public SignerConfigurationBuilder withAutoActivate(boolean autoActivate) {
        this.autoActivate = autoActivate;
        return this;
    }
}
