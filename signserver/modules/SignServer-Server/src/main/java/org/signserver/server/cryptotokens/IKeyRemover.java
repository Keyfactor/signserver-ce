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
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;

/**
 * Interface that should be implmented by CryptoTokenS supporting key
 * generation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IKeyRemover {

    boolean removeKey(String alias) throws CryptoTokenOfflineException, 
            InvalidWorkerIdException, KeyStoreException, SignServerException;
}
