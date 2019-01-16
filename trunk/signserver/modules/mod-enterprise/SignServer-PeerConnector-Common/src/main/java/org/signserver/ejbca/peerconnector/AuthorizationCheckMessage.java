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

import java.util.List;

/**
 * Check if the sender's credential is authorized to a list of access rules at the peer.
 * 
 * @version $Id$
 */
public class AuthorizationCheckMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;

    private final List<String> requestedResources;

    public AuthorizationCheckMessage(final List<String> requestedResources) {
        super(PeerMessageDefaultType.AUTHORIZATION_CHECK.name());
        this.requestedResources = appendObjectUtf8StringList(requestedResources);
        appendFinished();
    }

    public AuthorizationCheckMessage(final PeerMessage peerMessage) {
        super(PeerMessageDefaultType.AUTHORIZATION_CHECK.name(), peerMessage);
        requestedResources = nextObjectUtf8StringList();
    }

    public List<String> getRequestedResources() { return requestedResources; }
}
