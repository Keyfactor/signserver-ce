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
package org.signserver.module.debiandpkgsig.signer;

import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Mocked version of the DebianDpkgSigSigner using a MockedCryptoToken.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MockedDebianDpkgSigSigner extends DebianDpkgSigSigner {
    private final MockedCryptoToken mockedToken;

    public MockedDebianDpkgSigSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(IServices services) {
        return mockedToken;
    }
}