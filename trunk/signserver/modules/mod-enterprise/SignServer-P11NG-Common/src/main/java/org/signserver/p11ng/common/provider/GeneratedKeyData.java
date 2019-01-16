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
package org.signserver.p11ng.common.provider;

import java.security.PublicKey;

/**
 * Holder for a wrapped key-pair.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class GeneratedKeyData {
    
    private final byte[] wrappedPrivateKey;
    private final PublicKey publicKey;

    public GeneratedKeyData(byte[] wrappedPrivateKey, PublicKey publicKey) {
        this.wrappedPrivateKey = wrappedPrivateKey;
        this.publicKey = publicKey;
    }

    public byte[] getWrappedPrivateKey() {
        return wrappedPrivateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
}
