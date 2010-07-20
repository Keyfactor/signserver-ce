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

import org.signserver.common.CryptoTokenOfflineException;


/**
 * Interface that should be implmented by CryptoTokenS supporting key
 * generation.
 *
 * @author markus
 * @version $Id$
 */
public interface IKeyGenerator {

    /**
     * Generate a new keypair.
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     */
    void generateKey(String keyAlgorithm, String keySpec, String alias,
            char[] authCode) throws CryptoTokenOfflineException,
                IllegalArgumentException;
}
