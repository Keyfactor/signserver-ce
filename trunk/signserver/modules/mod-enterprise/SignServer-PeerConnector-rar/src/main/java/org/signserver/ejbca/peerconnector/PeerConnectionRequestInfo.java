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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import javax.resource.spi.ConnectionRequestInfo;

/**
 * @version $Id$
 */
public class PeerConnectionRequestInfo implements ConnectionRequestInfo {

    private final int peerConnectorId;
    private final URL url;
    private final Integer authenticationKeyBindingId;
    
    public PeerConnectionRequestInfo(final int peerConnectorId, final String url, final Integer authenticationKeyBindingId) throws MalformedURLException {
        this.peerConnectorId = peerConnectorId;
        this.url = new URL(url);
        this.authenticationKeyBindingId = authenticationKeyBindingId;
    }

    public int getPeerConnectorId() { return peerConnectorId; }
    public String getUrl() { return url.toExternalForm(); }
    public Integer getAuthenticationKeyBindingId() { return authenticationKeyBindingId; }

    public URL getURL() { return url; }

    public int getPort() {
        return url.getPort()==-1 ? url.getDefaultPort() : url.getPort();
    }
    public String getProtocol() { return url.getProtocol(); }
    public String getHost() { return url.getHost(); }
    
    @Override
    public boolean equals(final Object obj) {
        if (obj==null || !obj.getClass().equals(this.getClass())) {
            return false;
        }
        final PeerConnectionRequestInfo other = (PeerConnectionRequestInfo) obj;
        if (isEqual(url, other.url) && isEqual(authenticationKeyBindingId, other.authenticationKeyBindingId)) {
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return getHashCode(url.toExternalForm(), authenticationKeyBindingId);
    }

    /** @return true if the two objects are equal (with null checks) */
    private boolean isEqual(final Object o1, final Object o2) {
        if (o1==null && o2==null) {
            return true;
        }
        if ((o1!=null && o2==null) || (o1==null && o2!=null)) {
            return false;
        }
        return o1.equals(o2);
    }

    /* * @return true if the two objects are equal (with null checks) * /
    private boolean isEqual(final List<?> o1, final List<?> o2) {
        if (o1==null && o2==null) {
            return true;
        }
        if ((o1!=null && o2==null) || (o1==null && o2!=null)) {
            return false;
        }
        return Arrays.deepEquals(o1.toArray(), o2.toArray());
    }
    */

    /** @return combined hashcode of the provided objects */
    private int getHashCode(final Object...objects) {
        int hashCode = 42;
        for (Object o : objects) {
            if (o!=null) {
                if (o instanceof List) {
                    for (Object o2 : ((List<?>)o)) {
                        if (o2!=null) {
                            hashCode ^= o2.hashCode();
                        }
                    }
                } else {
                    hashCode ^= o.hashCode();
                }
            }
        }
        return hashCode;
    }
}
