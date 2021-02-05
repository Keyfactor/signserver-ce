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

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Remote interface for PeerSenderSession.
 * 
 * NOTE: This class is Enterprise only. Any moves of this class have to be mirrored in the permission file of the SVN repository.
 * 
 * @version $Id$
 *
 */
@Remote
public interface PeerSenderSessionRemote extends PeerSenderSession {

    /**
     * Remote call for sending a peer message from another JVM than the one the connection pool exists in.
     * 
     * @param authenticationToken an authentication token
     * @param peerConnectorId the outgoing peer connectors id
     * @param peerMessage the message to send
     * @return a response message or null if the peer did not support or authorize the message
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     * @throws PeerConnectionSendException if the sender was unable to connect to the peer
     */
    PeerMessage sendPeerMessage(AuthenticationToken authenticationToken, int peerConnectorId, PeerMessage peerMessage)
            throws AuthorizationDeniedException, PeerConnectionSendException;
}
