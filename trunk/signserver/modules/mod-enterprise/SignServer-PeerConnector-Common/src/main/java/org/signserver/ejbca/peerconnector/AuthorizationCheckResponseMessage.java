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
 * Response to the AuthorizationCheck peer message.
 * A list of access rules that the requestor's credential is authorized and that was asked for.
 * 
 * @version $Id$
 */
public class AuthorizationCheckResponseMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;

    private final List<String> authorizedResources;

    public AuthorizationCheckResponseMessage(final List<String> authorizedResources) {
        super(PeerMessageDefaultType.AUTHORIZATION_CHECK_RESPONSE.name());
        this.authorizedResources = appendObjectUtf8StringList(authorizedResources);
        appendFinished();
    }

    public AuthorizationCheckResponseMessage(final PeerMessage peerMessage) {
        super(PeerMessageDefaultType.AUTHORIZATION_CHECK_RESPONSE.name(), peerMessage);
        authorizedResources = nextObjectUtf8StringList();
    }

    public List<String> getAuthorizedResources() { return authorizedResources; }
}
