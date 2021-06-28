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

import java.security.Key;
import java.security.PrivateKey;

/**
 * A PrivateKey without a session.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NJI11ReleasebleSessionPrivateKey extends NJI11Object implements Key, PrivateKey {
    
    public NJI11ReleasebleSessionPrivateKey(long object, CryptokiDevice.Slot slot) {
        super(object, slot);
    }
    
    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

}
