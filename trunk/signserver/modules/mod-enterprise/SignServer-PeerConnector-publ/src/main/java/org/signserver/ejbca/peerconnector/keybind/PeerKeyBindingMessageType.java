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

/**
 * Message types for handling interactions with InternalKeyBindings at peer.
 * 
 * @version $Id$
 */
public enum PeerKeyBindingMessageType {
    /** Query the peer for relevant information about present InternalKeyBindings at peer */
    INTERNAL_KEY_BINDING_STATUS_REQUEST,
    /** Ask peer to optionally perform key generation and return a CSR for the next key to use */
    INTERNAL_KEY_BINDING_PREPARE_RENEWAL,
    /** Ask peer to update the certificate of the specified IKB */
    INTERNAL_KEY_BINDING_UPDATE,
    
    INTERNAL_KEY_BINDING_STATUS_RESPONSE,
    INTERNAL_KEY_BINDING_PREPARE_RENEWAL_RESPONSE,
    INTERNAL_KEY_BINDING_UPDATE_RESPONSE,
}
