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
 * Message for responding with an error condition.
 * 
 * @version $Id$
 */
public class GenericErrorResponseMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_TYPE = PeerMessageDefaultType.GENERIC_ERROR_RESPONSE.name();

    private final String type;
    private final String message;

    public GenericErrorResponseMessage(final String type, final String message) {
        super(MESSAGE_TYPE);
        this.type = appendObjectStringUtf8(type);
        this.message = appendObjectStringUtf8(message);
        appendFinished();
    }

    public GenericErrorResponseMessage(final Exception exception) {
        super(MESSAGE_TYPE);
        this.type = appendObjectStringUtf8(exception.getClass().getName());
        this.message = appendObjectStringUtf8(exception.getMessage());
        appendFinished();
    }

    public GenericErrorResponseMessage(final PeerMessage peerMessage) {
        super(MESSAGE_TYPE, peerMessage);
        this.type = nextObjectStringUtf8();
        this.message = nextObjectStringUtf8();
    }

    public String getType() { return type; }
    public String getMessage() { return message; }
}
