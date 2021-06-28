/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;
/**
 * Mocked AdESSigner class.
 * 
 * Overrides the 'getCryptoToken' method so it will not actually load a 
 * crypto token but just provide the supplied one (which could be null if
 * a crypto token is not actually needed for the test).
 *
 * @author Nima Saboonchi
 * @version $Id: PAdESSignerUnitTest.java 11795 2020-01-29 15:28:36Z $
 */
public class MockedAdESSigner extends AdESSigner {
    private final MockedCryptoToken mockedToken;

    public MockedAdESSigner(final MockedCryptoToken mockedToken) {
        this.mockedToken = mockedToken;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) {
        return mockedToken;
    }

}
