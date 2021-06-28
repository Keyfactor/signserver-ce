/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.keybind;

import org.signserver.ejbca.peerconnector.PeerMessage;

/**
 * Message to ask peer to create and respond with a CSR for an InternalKeyBinding.
 * (Optionally performing key renewal.)
 * 
 * @version $Id$
 */
public class InternalKeyBindingPrepareRenewalMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;

    private final int internalKeyBindingId;
    private final boolean renewKeys;
    
    public InternalKeyBindingPrepareRenewalMessage(final int internalKeyBindingId, final boolean renewKeys) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL.name());
        this.internalKeyBindingId = appendPrimitiveInt(internalKeyBindingId);
        this.renewKeys = appendPrimitiveBoolean(renewKeys);
        appendFinished();
    }

    public InternalKeyBindingPrepareRenewalMessage(final PeerMessage peerMessage) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL.name(), peerMessage);
        internalKeyBindingId = nextPrimitiveInt();
        renewKeys = nextPrimitiveBoolean();
    }

    public int getInternalKeyBindingId() { return internalKeyBindingId; }
    public boolean isRenewKeys() { return renewKeys; }
}
