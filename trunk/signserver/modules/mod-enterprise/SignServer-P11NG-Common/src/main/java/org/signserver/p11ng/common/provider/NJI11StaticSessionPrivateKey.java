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
import java.security.PrivateKey;

/**
 * A PrivateKey with a reserved session.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NJI11StaticSessionPrivateKey extends NJI11Object implements Key, PrivateKey {

    private final long session;
    
    private final boolean removalOnRelease;

    public NJI11StaticSessionPrivateKey(long session, long object, CryptokiDevice.Slot slot, boolean removalOnRelease) {
        super(object, slot);
        this.session = session;
        this.removalOnRelease = removalOnRelease;
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

    protected long getSession() {
        return session;
    }

    public boolean isRemovalOnRelease() {
        return removalOnRelease;
    }

}
