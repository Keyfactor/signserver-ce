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

/**
 * Class that uses a p12 file on the file system for signing. Only one key and purpose is supported
 * the same key for all purposes will be returned.
 * 
 * loads on activation and releases the keys from memory when deactivating
 * 
 * Available properties are:
 * KEYSTOREPATH : The full path to the key store to load. (required)
 * KEYSTOREPASSWORD : The password that locks the key store.
 * 
 * $Id$
 */
public class P12CryptoToken extends KeystoreCryptoToken implements ICryptoToken {

    @Override
    public void init(final int workerId, final Properties props) throws CryptoTokenInitializationFailureException {
        props.setProperty(KEYSTORETYPE, TYPE_PKCS12);
        super.init(workerId, props);
    }
}
