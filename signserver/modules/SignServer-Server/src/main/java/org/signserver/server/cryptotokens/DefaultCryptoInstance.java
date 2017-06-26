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
package org.signserver.server.cryptotokens;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;
import javax.crypto.SecretKey;
import org.signserver.common.RequestContext;

/**
 * Default implementation of a crypto instance.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DefaultCryptoInstance implements ICryptoInstance {

    private final String alias;
    private final RequestContext context;
    private final Provider provider;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Certificate certificate;
    private final List<Certificate> certificateChain;
    private final SecretKey secretKey;
    private boolean invalid;

    public DefaultCryptoInstance(String alias, RequestContext context, Provider provider, PrivateKey privateKey, List<Certificate> certificateChain, PublicKey publicKey) {
        this.alias = alias;
        this.context = context;
        this.provider = provider;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.certificate = (certificateChain == null || certificateChain.isEmpty()) ? null : certificateChain.get(0);
        this.publicKey = publicKey == null ? (this.certificate == null ? null : this.certificate.getPublicKey()) : publicKey;
        this.secretKey = null;
    }

    public DefaultCryptoInstance(String alias, RequestContext context, Provider provider, PrivateKey privateKey, List<Certificate> certificateChain) {
        this.alias = alias;
        this.context = context;
        this.provider = provider;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.certificate = (certificateChain == null || certificateChain.isEmpty()) ? null : certificateChain.get(0);
        this.publicKey = this.certificate == null ? null : this.certificate.getPublicKey();
        this.secretKey = null;
    }
    
    public DefaultCryptoInstance(String alias, RequestContext context, Provider provider, PrivateKey privateKey, PublicKey publicKey) {
        this.alias = alias;
        this.context = context;
        this.provider = provider;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.certificateChain = null;
        this.certificate = null;
        this.secretKey = null;
    }
    
    public DefaultCryptoInstance(String alias, RequestContext context, Provider provider, SecretKey secretKey) {
        this.alias = alias;
        this.context = context;
        this.provider = provider;
        this.privateKey = null;
        this.certificateChain = null;
        this.certificate = null;
        this.publicKey = null;
        this.secretKey = secretKey;
    }

    public String getAlias() {
        return alias;
    }

    public RequestContext getContext() {
        return context;
    }

    @Override
    public PrivateKey getPrivateKey() {
        ensureValid();
        return privateKey;
    }

    @Override
    public List<Certificate> getCertificateChain() {
        ensureValid();
        return certificateChain;
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public PublicKey getPublicKey() {
        ensureValid();
        return publicKey;
    }

    @Override
    public SecretKey getSecretKey() {
        ensureValid();
        return secretKey;
    }

    @Override
    public Provider getProvider() {
        ensureValid();
        return provider;
    }
    
    public void invalidate() {
        invalid = true;
    }
    
    private void ensureValid() {
        if (invalid) {
            throw new IllegalStateException("Instance has been closed");
        }
    }
    
    @Override
    public String toString() {
        return "CryptoInstanceImpl{ alias: " + alias + " }";
    }

}
