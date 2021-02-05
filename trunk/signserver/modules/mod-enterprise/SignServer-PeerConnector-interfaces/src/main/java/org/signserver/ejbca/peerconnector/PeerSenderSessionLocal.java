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

import javax.ejb.Local;

import org.cesecore.authorization.cache.AccessTreeUpdateData;

/**
 * Local interface for PeerSenderSession.
 * 
 * NOTE: This class is Enterprise only. Any moves of this class have to be mirrored in the permission file of the SVN repository.
 * 
 * @version $Id$
 */
@Local
public interface PeerSenderSessionLocal extends PeerSenderSession {

    /**
     * Local call for sending a peer message from another JVM than the one the connection pool exists in.
     * 
     * @param peerConnectorId the outgoing peer connectors id
     * @param peerMessage the message to send
     * @return a response message or null if the peer did not support or authorize the message
     * @throws PeerConnectionSendException if the sender was unable to connect to the peer
     */
    PeerMessage sendPeerMessage(int peerConnectorId, PeerMessage peerMessage) throws PeerConnectionSendException;

    /**
     * Local call for sending a peer message from another JVM than the one the connection pool exists in.
     * 
     * @param peerOutgoingInformation the outgoing peer connectors
     * @param peerMessage the message to send
     * @return a response message or null if the peer did not support or authorize the message
     * @throws PeerConnectionSendException if the sender was unable to connect to the peer
     */
    PeerMessage sendPeerMessage(PeerOutgoingInformation peerOutgoingInformation, PeerMessage peerMessage) throws PeerConnectionSendException;

    /**
     * Asks all peers to clears their cached AccessSets for authentication tokens.
     * @param accessTreeUpdateNumber Corresponds to {@link AccessTreeUpdateData#getAccessTreeUpdateNumber()}, or may be -1 to force clearing of caches.
     */
    void broadcastClearAuthCaches(int accessTreeUpdateNumber);

}
