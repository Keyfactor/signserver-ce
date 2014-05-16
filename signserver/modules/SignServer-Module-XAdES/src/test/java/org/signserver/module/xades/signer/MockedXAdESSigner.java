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

import java.security.cert.Certificate;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Mocked version of the XAdESSigner using a MockedCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedXAdESSigner extends XAdESSigner {
    private final MockedCryptoToken mockedToken;

    public MockedXAdESSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }
    
    @Override
    public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
        return mockedToken.getCertificate(ICryptoToken.PURPOSE_SIGN);
    }

    @Override
    public List<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
        return mockedToken.getCertificateChain(ICryptoToken.PURPOSE_SIGN);
    }

    @Override
    public ICryptoToken getCryptoToken() {
        return mockedToken;
    }
    
}
