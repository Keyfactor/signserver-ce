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

import java.security.Key;
import javax.crypto.SecretKey;

/**
 * A SecretKey without a session.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NJI11ReleasebleSessionSecretKey extends NJI11Object implements Key, SecretKey {
    
    private final String algorithm;
    private final String keySpec;
    
    public NJI11ReleasebleSessionSecretKey(long object, String algorithm, String keySpec, CryptokiDevice.Slot slot) {
        super(object, slot);
        this.algorithm = algorithm;
        this.keySpec = keySpec;
    }
    
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
    
    public String getKeySpec() {
        return keySpec;
    }

}
