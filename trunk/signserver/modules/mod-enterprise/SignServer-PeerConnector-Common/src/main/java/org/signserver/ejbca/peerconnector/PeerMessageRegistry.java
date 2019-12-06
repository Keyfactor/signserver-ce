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

import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;

/**
 * Registry over all known supported messages by this EJBCA instance and each corresponding listener.
 * 
 * @version $Id$
 */
public enum PeerMessageRegistry {
    INSTANCE;
    
    private final Logger log = Logger.getLogger(PeerMessageRegistry.class);
    private final ConcurrentHashMap<String,PeerMessageListener> listeners = new ConcurrentHashMap<String,PeerMessageListener>();
   
    /** Find all org.ejbca.peerconnector.PeerMessageListener interface implementations made available to the ServiceLoader */
    private PeerMessageRegistry() {
        // Automatically register declared PeerMessageListeners
        final ServiceLoader<PeerMessageListener> serviceLoader = ServiceLoader.load(PeerMessageListener.class);
        for (final PeerMessageListener peerMessageListener : serviceLoader) {
            for (final String messageType : peerMessageListener.getSupportedMessageTypes()) {
                listeners.put(messageType, peerMessageListener);
                log.info("Registered " + peerMessageListener.getClass().getName() + " for " + messageType + " messages.");
            }
        }
    }
    
    /** @return a list of non-default registered message types (outgoing only, responses are implied). */
    public Set<String> getRegisteredMessageTypes() {
        final Set<String> ret = new HashSet<String>(listeners.keySet());
        for (final PeerMessageDefaultType defaultType : PeerMessageDefaultType.values()) {
            ret.remove(defaultType.name());
        }
        return ret;
    }
    
    /** Dynamically add a PeerMessageListener, overriding any existing implementation for its supported message types */
    public void register(final PeerMessageListener peerMessageListener) {
        for (final String messageType : peerMessageListener.getSupportedMessageTypes()) {
            listeners.put(messageType, peerMessageListener);
        }
    }

    /** Dynamically remove a PeerMessageListener. If the removed listener overrode message types when added, these are not restored. */
    public void deregister(final PeerMessageListener peerMessageListener) {
        for (final String messageType : peerMessageListener.getSupportedMessageTypes()) {
            listeners.remove(messageType);
        }
    }

    /** Dispatch an incoming message to a supporting implementation (if any) or return null otherwise. */
    public PeerMessage dispatchAndRespond(final PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession,
            final EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession) {
        final PeerMessageListener peerMessageListener = listeners.get(peerMessage.getMessageType());
        if (peerMessageListener==null) {
            if (log.isDebugEnabled()) {
                log.debug("Dropped unknown message type: " + peerMessage.getMessageType());
            }
            // Acknowledge the request and reply that the requested message has no handler on this peer
            return new PeerMessage(PeerMessageDefaultType.UNKNOWN_MESSAGE_TYPE_RESPONSE.name());
        } else {
            return peerMessageListener.receiveAndRespond(peerMessage, ejbBridgeSession, enterpriseEditionEjbBridgeSession);
        }
    }
}
