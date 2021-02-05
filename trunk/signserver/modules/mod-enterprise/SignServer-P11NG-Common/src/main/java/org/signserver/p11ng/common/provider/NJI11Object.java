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

/**
 * A PKCS#11 object.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NJI11Object {
    private final long object;
    private final CryptokiDevice.Slot slot;

    protected NJI11Object(long object, CryptokiDevice.Slot slot) {
        this.object = object;
        this.slot = slot;
    }

    protected long getObject() {
        return object;
    }
    
    protected CryptokiDevice.Slot getSlot() {
        return slot;
    }
}
