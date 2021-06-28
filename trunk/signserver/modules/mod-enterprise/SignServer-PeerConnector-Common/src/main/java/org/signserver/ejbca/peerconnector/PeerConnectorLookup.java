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

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

/**
 * Helper class for looking up the peerconnector JCA resource from the JNDI where injection cannot be used or is unsuitable.
 * 
 * @version $Id$
 */
public enum PeerConnectorLookup {
    INSTANCE;

    private final Logger log = Logger.getLogger(PeerConnectorLookup.class);

    /** List of all potential JNDI names that the connector could have. Expecting this list to grow when more application servers are supported. */
    private final String[] jndiNames = {"java:/jca/signserverpeerconnector"};

    private Context context;
    private PeerConnectorResource peerConnectorResource;
    private boolean failFast = false;

    public PeerConnectorResource getResource() {
        if (failFast) {
            // Since we have encountered a fatal error previously, there is no need to spend cycles checking again.
            return null;
        }
        if (peerConnectorResource==null) {
            if (context==null) {
                try {
                    context = new InitialContext();
                } catch (NamingException e) {
                    log.error("Initial context is not available for peer connector lookup.", e);
                }
                if (context==null) {
                    failFast = true;
                    return null;
                }
            }
            for (final String jndiName : jndiNames) {
                try {
                    peerConnectorResource = (PeerConnectorResource) context.lookup(jndiName);
                } catch (ClassCastException e) {
                    log.warn("Unexpected implementation class for peerconnector bound at " + jndiName);
                } catch (NamingException e) {
                    log.debug("Unable to locate peerconnector at " + jndiName);
                }
                if (peerConnectorResource!=null) {
                    break;
                }
            }
            if (peerConnectorResource==null) {
                log.info("PeerConnectorResource cannot be looked up. Falling back to direct pool access implementation.");
                peerConnectorResource = new PeerConnectorResourceFallback();
            }
        }
        return peerConnectorResource;
    }
}
