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

import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

/**
 * 
 * @version $Id$
 *
 */
public interface PeerConnection {

    /** Send a message */
    PeerMessage send(PeerMessage msg, InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession, CertificateStoreSessionLocal certificateStoreSession,
            CryptoTokenManagementSessionLocal cryptoTokenManagementSession) throws PeerConnectionSendException;

    public boolean isConnectionOk();

    /** Release the connection back to the pool */
    void release();

}
