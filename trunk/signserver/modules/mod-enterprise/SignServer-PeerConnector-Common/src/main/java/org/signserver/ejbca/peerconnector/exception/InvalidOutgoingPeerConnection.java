/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.exception;

/**
 * @version $Id$
 *
 */
public class InvalidOutgoingPeerConnection extends RuntimeException {

    private static final long serialVersionUID = -8744822405500284991L;

    /**
     * 
     */
    public InvalidOutgoingPeerConnection() {
    }

    /**
     * @param message
     */
    public InvalidOutgoingPeerConnection(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public InvalidOutgoingPeerConnection(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public InvalidOutgoingPeerConnection(String message, Throwable cause) {
        super(message, cause);
    }

}
