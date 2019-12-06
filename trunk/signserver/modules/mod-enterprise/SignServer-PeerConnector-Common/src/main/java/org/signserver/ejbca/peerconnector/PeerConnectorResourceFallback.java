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
import org.signserver.ejbca.peerconnector.client.PeerConnectorPool;

/**
 * Fallback implementation that does direct access to the pool of outgoing connections,
 * instead of going via the JCA resource pool
 * 
 * The fallback would be used for application servers without the proper resource adapter configuration.
 * 
 * @version $Id$
 */
public class PeerConnectorResourceFallback implements PeerConnectorResource {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(PeerConnectorResourceFallback.class);

    public PeerConnectorResourceFallback() {
        PeerConnectorPool.INSTANCE.setUseFallbackConfig(true);
    }
    
    @Override
    public PeerMessage send(final PeerOutgoingInformation peer, final PeerMessage msg, final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession,
            final CertificateStoreSessionLocal certificateStoreSession, final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) throws PeerConnectionSendException {
        if (peer==null) {
            throw new PeerConnectionSendException("Cannot send message to undefined target.");
        }
        if (msg==null) {
            throw new PeerConnectionSendException("Cannot send undefined message to target.");
        }
        if (!peer.isEnabled()) {
            throw new PeerConnectionSendException("Refusing to send message to disabled peer " + peer.getName() + " (" + peer.getId() + ").");
        }
        return PeerConnectorPool.INSTANCE.send(peer.getId(), peer.getUrl(), peer.getAuthenticationKeyBindingId(), msg,
                internalKeyBindingMgmtSession, certificateStoreSession, cryptoTokenManagementSession);
    }
}
