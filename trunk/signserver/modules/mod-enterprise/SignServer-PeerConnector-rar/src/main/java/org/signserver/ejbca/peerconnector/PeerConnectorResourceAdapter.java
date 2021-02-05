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

import javax.resource.spi.ActivationSpec;
import javax.resource.spi.BootstrapContext;
import javax.resource.spi.ResourceAdapter;
import javax.resource.spi.endpoint.MessageEndpointFactory;
import javax.transaction.xa.XAResource;

import org.apache.log4j.Logger;
import org.signserver.ejbca.peerconnector.client.PeerConnectorPool;


/**
 * @version $Id$
 */
//@Connector(reauthenticationSupport = false, transactionSupport = TransactionSupport.TransactionSupportLevel.LocalTransaction)
public class PeerConnectorResourceAdapter implements ResourceAdapter {

    private static final Logger log = Logger.getLogger(PeerConnectorResourceAdapter.class);
    
    @Override
    public void start(BootstrapContext bootstrapContext) {
        if (log.isDebugEnabled()) {
            log.debug("start()");
        }
    }

    @Override
    public void stop() {
        if (log.isDebugEnabled()) {
            log.debug("stop()");
        }
        // Shutdown connection pool on resource halt
        PeerConnectorPool.INSTANCE.shutdown(30);
    }

    @Override
    public void endpointActivation(MessageEndpointFactory messageEndpointFactory, ActivationSpec activationSpec) {
        if (log.isDebugEnabled()) {
            log.debug("endpointActivation()");
        }
        // NOOP: This is not for JMS
    }

    @Override
    public void endpointDeactivation(MessageEndpointFactory messageEndpointFactory, ActivationSpec activationSpec) {
        if (log.isDebugEnabled()) {
            log.debug("endpointDeactivation()");
        }
        // NOOP: This is not for JMS
    }

    @Override
    public XAResource[] getXAResources(ActivationSpec[] activationSpecs) {
        // NOOP: We don't expose this as an XA transactional resource
        return null;
    }

    /* Section: 19.4.2: Description: A ResourceAdapter must implement a "public boolean equals(Object)" method. */
    @Override
    public boolean equals(Object obj) {
        if (log.isDebugEnabled()) {
            log.debug("equals()");
        }
        return obj.getClass().equals(this.getClass());
    }
    
    /* Section: 19.4.2: Description: A ResourceAdapter must implement a "public int hashCode()" method. */
    @Override
    public int hashCode() {
        if (log.isDebugEnabled()) {
            log.debug("hashCode()");
        }
        return 13;
    }
}
