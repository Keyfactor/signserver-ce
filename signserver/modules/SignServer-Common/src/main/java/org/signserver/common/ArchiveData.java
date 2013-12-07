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
package org.signserver.common;

import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.model.UpgradeableDataHashMap;

/**
 * Class containing the actual archive data.
 * Is responsible for containing the archive data as
 * an byte array or base64 encoded as a String.
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class ArchiveData extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 1L;

    private static final float LATEST_VERSION = 2;
    private static final String ARCHIVEDATA = "ARCHIVEDATA";

    /**
     * Don't use this constructor, should only be used internally
     *
     */
    public ArchiveData() {
    }

    /**
     * Constructor that should be used to create an archive data.
     * @param archiveData
     */
    public ArchiveData(byte[] archiveData) {
        final String b64 = new String(Base64.encode(archiveData));
        data.put(ARCHIVEDATA, b64);
    }
    
    public byte[] getData() {
        final byte[] result;
        final Object object = data.get(ARCHIVEDATA);
        if (object instanceof String) {
            // The new way: Data is base64 encoded
            result = Base64.decode((String) object);
        } else {
            // The old way: Data is an byte array
            result = (byte[]) data.get(ARCHIVEDATA);    
        }
        return result;
    }

    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    public void upgrade() {
    }
}
