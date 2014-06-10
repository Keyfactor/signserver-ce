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
package org.signserver.server;

import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Supplier of the current crypto token.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface CryptoTokenSupplier {
    /**
     * @return the current crypto token (worker) if configured and available,
     * otherwise null
     * @throws SignServerException in case initialization of the crypto token
     * failed
     */
    ICryptoToken getCurrentCryptoToken() throws SignServerException;
}
