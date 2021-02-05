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

import javax.resource.spi.ConnectionEvent;
import javax.resource.spi.ConnectionRequestInfo;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.signserver.ejbca.peerconnector.client.PeerConnectorPool;

/**
 * @version $Id$
 */
public class PeerConnectionImpl implements PeerConnection {

    private static final Logger log = Logger.getLogger(PeerConnectionImpl.class);
    private final PeerManagedConnectionImpl peerManagedConnectionImpl;
    private final PeerConnectionRequestInfo peerConnectionRequestInfo;
    
    PeerConnectionImpl(final PeerManagedConnectionImpl managedConnection, PeerConnectionRequestInfo peerConnectionRequestInfo) {
        if (log.isTraceEnabled()) {
            log.trace("PeerConnectionImpl()");
        }
        this.peerManagedConnectionImpl = managedConnection;
        this.peerConnectionRequestInfo = peerConnectionRequestInfo;
    }
    
    @Override
    public PeerMessage send(final PeerMessage msg, final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession, final CertificateStoreSessionLocal certificateStoreSession,
            final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) throws PeerConnectionSendException {
        if (log.isTraceEnabled()) {
            log.trace("PeerMessage: " + msg);
        }
        peerManagedConnectionImpl.broadcastEvent(this, ConnectionEvent.LOCAL_TRANSACTION_STARTED);
        PeerMessage ret = null;
        try {
            ret = PeerConnectorPool.INSTANCE.send(peerConnectionRequestInfo.getPeerConnectorId(), peerConnectionRequestInfo.getUrl(), peerConnectionRequestInfo.getAuthenticationKeyBindingId(), msg,
                    internalKeyBindingMgmtSession, certificateStoreSession, cryptoTokenManagementSession);
        } finally {
            if (ret!=null) {
                peerManagedConnectionImpl.broadcastEvent(this, ConnectionEvent.LOCAL_TRANSACTION_COMMITTED);
            } else {
                peerManagedConnectionImpl.broadcastEvent(this, ConnectionEvent.LOCAL_TRANSACTION_ROLLEDBACK);
            }
        }
        return ret;
    }

    @Override
    public void release() {
        // ConnectionEvent.CONNECTION_CLOSED means "release back to pool"
        peerManagedConnectionImpl.broadcastEvent(this, ConnectionEvent.CONNECTION_CLOSED);
    }

    @Override
    public boolean isConnectionOk() {
        // Check if pool has been stopped, to avoid auto-starting it through this background validation
        if (PeerConnectorPool.INSTANCE.isPeerConnectorPoolAvailable(peerConnectionRequestInfo.getPeerConnectorId())) {
            return false;
        }
        boolean ret = false;
        final long start = System.currentTimeMillis();
        try {
            // We can send null bean references, since we don't want to start the pool by a background check anyway
            final PeerMessage peerMessageIn = PeerConnectorPool.INSTANCE.send(peerConnectionRequestInfo.getPeerConnectorId(), peerConnectionRequestInfo.getUrl(), peerConnectionRequestInfo.getAuthenticationKeyBindingId(),
                    new PeerMessage(PeerMessageDefaultType.PING.name()), null, null, null);
            ret = peerMessageIn!=null && peerMessageIn.getMessageType().equals(PeerMessageDefaultType.PING_RESPONSE.name());
            if (log.isDebugEnabled()) {
                log.debug("Connection validation ping " + (ret?"succeeded":"failed") + " after " + (System.currentTimeMillis()-start) + " ms.");
            }
        } catch (PeerConnectionSendException e) {
            if (log.isDebugEnabled()) {
                log.debug("Connection validation ping failed: " + e.getMessage());
            }
        }
        return ret;
    }

    public ConnectionRequestInfo getConnectionRequestInfo() {
        return peerConnectionRequestInfo;
    }
}
