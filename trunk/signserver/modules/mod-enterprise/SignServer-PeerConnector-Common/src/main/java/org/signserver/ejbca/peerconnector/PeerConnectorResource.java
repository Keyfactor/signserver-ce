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

import java.io.Serializable;

import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

/**
 * 
 * @version $Id$
 */
public interface PeerConnectorResource extends Serializable {

    /**
     * Send a message synchronously to the specified destination.
     * 
     * @param peer is the destination
     * @param msg is the message to send
     * @throws PeerConnectionSendException if the message could not be sent
     * @return null if the operation failed or a response otherwise
     */
    PeerMessage send(final PeerOutgoingInformation peer, final PeerMessage msg, final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession,
            final CertificateStoreSessionLocal certificateStoreSession, final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) throws PeerConnectionSendException;
}
