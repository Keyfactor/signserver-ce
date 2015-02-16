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
 * Default implementation of a key data.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DefaultGeneratedKeyDetails implements IGeneratedKeyData {

    private final byte[] keyData;
    private final PublicKey publicKey;

    public DefaultGeneratedKeyDetails(byte[] keyData, PublicKey publicKey) {
        this.keyData = keyData;
        this.publicKey = publicKey;
    }

    @Override
    public byte[] getKeyData() {
        return keyData;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

}
