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
package org.signserver.module.cmssigner;

import java.security.cert.Certificate;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Mocked version of the PlainSigner using a MockedCryptoToken.
 * @author Markus Kilås
 * @version $Id: MockedPlainSigner.java 7052 2016-02-18 11:59:37Z netmackan $
 */
public class MockedPlainSigner extends PlainSigner {
    private final MockedCryptoToken mockedToken;

    public MockedPlainSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }
    
    @Override
    public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
        return mockedToken.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
    }

    @Override
    public List<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
        return mockedToken.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN);
    }

    @Override
    public ICryptoToken getCryptoToken(services) {
        return mockedToken;
    }
}
