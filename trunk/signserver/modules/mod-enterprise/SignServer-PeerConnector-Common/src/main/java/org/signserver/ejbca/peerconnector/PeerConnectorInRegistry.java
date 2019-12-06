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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Keeps track of incoming connections and the peers that have initiated them.
 * 
 * @version $Id$
 */
public enum PeerConnectorInRegistry {
    INSTANCE;

    //private final Logger log = Logger.getLogger(PeerConnectorInRegistry.class);
    private final ConcurrentHashMap<Integer, PeerIncomingInformation> incomingPeers = new ConcurrentHashMap<Integer,PeerIncomingInformation>();
    
    /** @return all PeerIncomingInformation that has been seen in the last hour */
    public List<PeerIncomingInformation> getPeerIncomingInformations() {
        final List<PeerIncomingInformation> ret = new ArrayList<PeerIncomingInformation>();
        final List<Integer> toRemove = new ArrayList<Integer>();
        final long expireOlderThan = System.currentTimeMillis()-3600000L;
        for (final Integer key : incomingPeers.keySet()) {
            final PeerIncomingInformation peerIncomingInformation = incomingPeers.get(key);
            if (peerIncomingInformation!=null) {
                if (peerIncomingInformation.getLastUpdate()<expireOlderThan) {
                    toRemove.add(key);
                } else {
                    ret.add(peerIncomingInformation);
                }
            }
        }
        for (final Integer key : toRemove) {
            remove(key);
        }
        return ret;
    }
    
    /** @return true if this entry was not registered before */
    public boolean updatePeerIncomingInformation(final int sourceId, final AuthenticationToken authenticationToken) {
        final int key = getKey(sourceId, authenticationToken);
        if (incomingPeers.putIfAbsent(key, new PeerIncomingInformation(sourceId, authenticationToken))!=null) {
            final PeerIncomingInformation peerIncomingInformation = incomingPeers.get(key);
            if (peerIncomingInformation!=null) {
                peerIncomingInformation.setLastUpdate(System.currentTimeMillis());  // Not super-important this is exact
            }
            return false;
        } else {
            return true;
        }
    }

    public void updatePeerIncomingInformation(int sourceId, final AuthenticationToken authenticationToken, final String remoteAddress) {
        final int key = getKey(sourceId, authenticationToken);
        final PeerIncomingInformation peerIncomingInformation = incomingPeers.get(key);
        if (peerIncomingInformation!=null) {
            peerIncomingInformation.setRemoteAddress(remoteAddress);
        }
    }

    public void remove(final int sourceId, final AuthenticationToken authenticationToken) {
        remove(getKey(sourceId, authenticationToken));
    }

    private void remove(final int key) {
        incomingPeers.remove(key);
    }

    public void clear() {
        incomingPeers.clear();
    }
    
    /**
     * Assume that the source Id is unique for each authenticationToken.
     * E.g. two hosts in two clusters publishing to the same VA may share the same "cluster.nodeid" if they have different identities. 
     */
    private int getKey(final int sourceId, final AuthenticationToken authenticationToken) {
        return sourceId ^ authenticationToken.hashCode();
    }
}
