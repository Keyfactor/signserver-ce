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

import java.util.Properties;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.server.IServices;
import static org.signserver.server.cryptotokens.KeystoreCryptoToken.KEYSTORETYPE;

/**
 * Crypto token storing the keystore in the configuration in the database.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class KeystoreInConfigCryptoToken extends KeystoreCryptoToken {
    @Override
    public void init(final int workerId, final Properties props, IServices services) throws CryptoTokenInitializationFailureException {
        props.setProperty(KEYSTORETYPE, TYPE_INTERNAL);
        super.init(workerId, props, services);
    }
}
