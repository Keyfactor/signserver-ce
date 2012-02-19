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
package org.signserver.statusrepo.common;

import java.io.Serializable;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class StatusEntry implements Serializable {

    /** Serialization version ID. */
    private static final long serialVersionUID = 1L;
    
    private long updateTime;

    private String value;

    private long expirationTime;

    public StatusEntry(long updateTime, String value, long expirationTime) {
        this.updateTime = updateTime;
        this.value = value;
        this.expirationTime = expirationTime;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public long getUpdateTime() {
        return updateTime;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "StatusEntry {updateTime: " + updateTime + ", value: " + value + ", expirationTime: " + expirationTime + "}";
    }
    
}
