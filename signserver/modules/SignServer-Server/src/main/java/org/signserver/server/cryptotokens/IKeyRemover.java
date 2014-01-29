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

import java.security.KeyStoreException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerException;

/**
 * Interface that should be implemented by CryptoTokenS supporting key
 * removal.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IKeyRemover {

    /**
     * Remove a key from the token (if supported).
     *
     * @param alias of key to remove
     * @return True if the key was successfully removed or false it failed or the token does not support key removal
     * @throws CryptoTokenOfflineException if the token was not activated
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException if the keystore did not contain a key with the specified alias
     */
    boolean removeKey(String alias) throws CryptoTokenOfflineException, 
            KeyStoreException, SignServerException;
}
