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
package org.signserver.module.xades.signer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.verification.UnexpectedJCAException;

/**
 * An implementation of {@code KeyingDataProvider} that allows direct 
 * specification of the signing key and certificate chain.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CertificateAndChainKeyingDataProvider implements KeyingDataProvider {

    private final List<X509Certificate> certificates;
    private final PrivateKey key;

    public CertificateAndChainKeyingDataProvider(final List<X509Certificate> certificates, final PrivateKey key) {
        this.certificates = certificates;
        this.key = key;
    }
    
    @Override
    public List<X509Certificate> getSigningCertificateChain() throws SigningCertChainException, UnexpectedJCAException {
        return certificates;
    }

    @Override
    public PrivateKey getSigningKey(final X509Certificate signingCert) throws SigningKeyException, UnexpectedJCAException {
        return key;
    }
    
}
