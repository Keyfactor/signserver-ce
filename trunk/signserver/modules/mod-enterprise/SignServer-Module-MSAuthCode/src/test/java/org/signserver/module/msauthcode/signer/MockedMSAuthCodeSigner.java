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

import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Mocked version of the AuthenticodeSigner using a MockedCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedMSAuthCodeSigner extends MSAuthCodeSigner {
    private final MockedCryptoToken mockedToken;

    public MockedMSAuthCodeSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) {
        return mockedToken;
    }

}