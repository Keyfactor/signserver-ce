/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.io.Serializable;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ValidityDate;

/**
 * Representation of a system that has initiated connection(s) to this system.
 * 
 * @version $Id$
 */
public class PeerIncomingInformation implements Serializable, Comparable<PeerIncomingInformation> {

    private static final long serialVersionUID = 1L;
    private Integer id;
    private final AuthenticationToken authenticationToken;
    private String remoteAddress = null;
    private long lastUpdate = System.currentTimeMillis();

    public PeerIncomingInformation(final int sourceId, final AuthenticationToken authenticationToken) {
        this.id = sourceId;     
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

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 4711). // two randomly chosen prime numbers
                append(id).
                append(authenticationToken).
                toHashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PeerIncomingInformation)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        final PeerIncomingInformation other = (PeerIncomingInformation) obj;
        return new EqualsBuilder().
                append(id, other.getId()).
                append(authenticationToken, other.getAuthenticationToken()).
                isEquals();
    }

    @Override
    public int compareTo(PeerIncomingInformation o) {
        return this.getId().compareTo(o.getId());
    }
}
