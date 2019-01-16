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
 * Built in messages.
 * 
 * @version $Id$
 */
public enum PeerMessageDefaultType {

    /** Standard response if the message is unknown to the remote instance. */
    UNKNOWN_MESSAGE_TYPE_RESPONSE,
    /** The request failed. */
    GENERIC_ERROR_RESPONSE,

    /** Simple check from the client if the other side is there. */
    PING,
    /** Response to simple check from the client if the other side is there. */
    PING_RESPONSE,

    /** Request all authorized resources under the provided AccessRule resources. */
    AUTHORIZATION_CHECK,
    /** Response with all authorized resources under the requested AccessRule resources. */
    AUTHORIZATION_CHECK_RESPONSE,
}
