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
package org.signserver.module.extendedcmssigner;

import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Mocked implementation of ExtendedCMSSigner for unit tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MockedExtendedCMSSigner extends ExtendedCMSSigner {
    private final MockedCryptoToken mockedToken;

    public MockedExtendedCMSSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(IServices services) {
        return mockedToken;
    }
}
