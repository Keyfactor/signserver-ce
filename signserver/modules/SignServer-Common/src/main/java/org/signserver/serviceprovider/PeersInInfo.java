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
package org.signserver.serviceprovider;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ValidityDate;

/**
 * Class representing information from an incoming peer connection from
 * EJBCA.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class PeersInInfo {
    private Integer id;
    private final AuthenticationToken authenticationToken;
    private String remoteAddress = null;
    private long lastUpdate = System.currentTimeMillis();

    public PeersInInfo(final int id,
                       final AuthenticationToken authenticationToken) {
        this.id = id;
        this.authenticationToken = authenticationToken;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    public void setRemoteAddress(final String remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public long getLastUpdate() {
        return lastUpdate;
    }

    public void setLastUpdate(long lastUpdate) {
        this.lastUpdate = lastUpdate;
    }

    public String getLastUpdateString() {
        return ValidityDate.formatAsISO8601ServerTZ(getLastUpdate(), ValidityDate.TIMEZONE_SERVER);
    }
}
