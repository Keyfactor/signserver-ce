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

import java.io.Serializable;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class StatusRepositoryData implements Serializable {

    /** Serialization version ID. */
    private static final long serialVersionUID = 1L;

    private String value;

    private long expiration;


    public StatusRepositoryData(String value) {
        this.value = value;
    }

    public StatusRepositoryData(String value, long expiration) {
        this.value = value;
        this.expiration = expiration;
    }

    public long getExpiration() {
        return expiration;
    }

    public String getValue() {
        return value;
    }
    
}
