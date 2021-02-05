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

/**
 * Exception when it isn't possible to send a Peer Message.
 * 
 * @version $Id$
 */
public class PeerConnectionSendException extends Exception {

    private static final long serialVersionUID = 1L;

    public PeerConnectionSendException(final String errorMessage, final Exception e) {
        super(errorMessage, e);
    }

    public PeerConnectionSendException(final String errorMessage) {
        super(errorMessage);
    }
}
