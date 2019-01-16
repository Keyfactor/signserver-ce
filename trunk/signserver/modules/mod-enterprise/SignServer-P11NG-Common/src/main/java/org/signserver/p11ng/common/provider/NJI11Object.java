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
