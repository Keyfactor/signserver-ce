/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
