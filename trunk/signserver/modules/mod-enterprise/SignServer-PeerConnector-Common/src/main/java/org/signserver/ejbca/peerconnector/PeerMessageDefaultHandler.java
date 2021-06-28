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
import java.util.Arrays;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;

/**
 * Handler for built in (non plug-in) peer messages.
 * 
 * @version $Id$
 */
public class PeerMessageDefaultHandler implements PeerMessageListener {

    //private static final Logger log = Logger.getLogger(PeerMessageDefaultHandler.class);
    
    @Override
    public List<String> getSupportedMessageTypes() {
        return Arrays.asList(
                PeerMessageDefaultType.PING.name(),
                PeerMessageDefaultType.AUTHORIZATION_CHECK.name()
                );
    }

    @Override
    public PeerMessage receiveAndRespond(final PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession,
            final EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession) {
        final PeerMessageDefaultType messageType = PeerMessageDefaultType.valueOf(peerMessage.getMessageType());
        switch (messageType) {
        case PING:
            return new PeerMessage(PeerMessageDefaultType.PING_RESPONSE.name());
        case AUTHORIZATION_CHECK:
            return handleAuthorizationCheck(new AuthorizationCheckMessage(peerMessage), ejbBridgeSession);
        default:
        }
        return null;
    }

    /**
     * To avoid leaking any kind of information we should never respond which resources are not authorized (e.g. a
     * request for a non-existing and unauthorized id gives the same response).
     */
    private AuthorizationCheckResponseMessage handleAuthorizationCheck(final AuthorizationCheckMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession) {
        final AuthenticationToken authenticationToken = peerMessage.getAuthenticationToken();
        final List<String> requestedResources = peerMessage.getRequestedResources();
        final AuthorizationSessionLocal authorizationSession = ejbBridgeSession.getAuthorizationSession();
        final List<String> authorizedResources = new ArrayList<String>();
        for (final String resource : requestedResources) {
            if (authorizationSession.isAuthorizedNoLogging(authenticationToken, resource)) {
                authorizedResources.add(resource);
            }
        }
        return new AuthorizationCheckResponseMessage(authorizedResources);
    }
}
