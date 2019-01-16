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

import java.net.MalformedURLException;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.resource.Referenceable;
import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ManagedConnectionFactory;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

/**
 * 
 * @version $Id$
 */
public class PeerConnectorResourceImpl implements PeerConnectorResource, Referenceable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(PeerConnectorResourceImpl.class);

    private final PeerManagedConnectionFactory peerManagedConnectionFactory;
    private ConnectionManager connectionManager;
    private Reference reference;

    public PeerConnectorResourceImpl(ManagedConnectionFactory managedConnectionFactory, ConnectionManager connectionManager) {
        this.peerManagedConnectionFactory = (PeerManagedConnectionFactory) managedConnectionFactory;
        this.connectionManager = connectionManager;
    }

    @Override
    public void setReference(Reference reference) { this.reference = reference; }
    @Override
    public Reference getReference() throws NamingException { return reference; }

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
        PeerConnection peerConnection = null;
        PeerMessage ret = null; 
        try {
            peerConnection = (PeerConnection) connectionManager.allocateConnection(peerManagedConnectionFactory, new PeerConnectionRequestInfo(peer.getId(), peer.getUrl(), peer.getAuthenticationKeyBindingId()));
            ret = peerConnection.send(msg, internalKeyBindingMgmtSession, certificateStoreSession, cryptoTokenManagementSession);
        } catch (MalformedURLException e) {
            log.error(e.getMessage());
            throw new PeerConnectionSendException(e.getMessage(), e);
        } catch (ResourceException e) {
            log.error(e.getMessage());
            throw new PeerConnectionSendException(e.getMessage(), e);
        } finally {
            if (peerConnection!=null) {
                peerConnection.release();
            }
        }
        return ret;
    }
}
