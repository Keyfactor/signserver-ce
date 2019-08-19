/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.serviceprovider;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ValidityDate;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class PeersInInfo implements Comparable<PeersInInfo> {
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

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 4711). // two randomly chosen prime numbers
                append(id).
                toHashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PeersInInfo)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        final PeersInInfo other = (PeersInInfo) obj;
        return new EqualsBuilder().
                append(id, other.getId()).
                isEquals();
    }

    @Override
    public int compareTo(PeersInInfo o) {
        return this.getId().compareTo(o.getId());
    }
}
