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

import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;

/**
 * Instance for dispatching a subset of PeerMessages that is supported by this implementation.
 * 
 * @version $Id$
 */
public interface PeerMessageListener {

	/** @return the names of all message types supported by this implementation. */
    List<String> getSupportedMessageTypes();
    
    /**
     * Process the message (supported by this implementation) and return a response.
     * 
     * @return the defined message response for a given request message or null if this implementation does not support the request.
     */
    PeerMessage receiveAndRespond(PeerMessage peerMessage, EjbBridgeSessionLocal ejbBridgeSession, EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession);
}
