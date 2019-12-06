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

import java.security.PublicKey;

/**
 * Holder for the generated key.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IGeneratedKeyData {

    /** @return Data for the key. */
    byte[] getKeyData();
    
    /** @return Public key (for asymmetric algorithms) otherwise null. */
    PublicKey getPublicKey();
}
