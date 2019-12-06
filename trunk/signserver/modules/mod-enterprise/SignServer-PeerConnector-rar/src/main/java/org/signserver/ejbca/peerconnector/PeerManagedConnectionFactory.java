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

import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnectionFactory;
import javax.resource.spi.ValidatingManagedConnectionFactory;
import javax.security.auth.Subject;

import org.apache.log4j.Logger;

/**
    @Resource(mappedName = "java:/jca/signserverpeerconnector")
    public PeerConnectorResource peerConnectorResource;
    ...
    if (peerConnectorResource!=null) {
        PeerConnection peerConnection = peerConnectorResource.getConnection("127.0.0.1");
        String ret = peerConnection.send("testing!");
        log.info("Response was: "+ret);
    }
    
    You could also used PeerConnectorLookup.INSTANCE.getResource().
 *
 * @version $Id$
 */
public class PeerManagedConnectionFactory implements ManagedConnectionFactory, Serializable, ValidatingManagedConnectionFactory {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(PeerManagedConnectionFactory.class);
    
    private Random rnd = new Random();

    public PeerManagedConnectionFactory() {}

    /* To inject a value here configured in ra.xml, add the following to the XML and un-comment this method
            <config-property>
               <description>Test how config values work..</description>
               <config-property-name>configValue</config-property-name>
               <config-property-type>java.lang.String</config-property-type>
               <config-property-value>some value</config-property-value>
            </config-property>

    private String configValue;
    
    public void setConfigValue(String configValue) {
        log.info("Example of configuration injected from ra.xml: " + configValue);
        this.configValue = configValue;
    }
    */

    @Override
    public PeerConnectorResource createConnectionFactory() throws ResourceException {
        return createConnectionFactory(null);
    }

    @Override
    public PeerConnectorResource createConnectionFactory(final ConnectionManager connectionManager) throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("createConnectionFactory() connectionManager=" + connectionManager);
        }
        return new PeerConnectorResourceImpl(this, connectionManager);
    }

    @Override
    public PeerManagedConnectionImpl createManagedConnection(final Subject subject, final ConnectionRequestInfo connectionRequestInfo) throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("createManagedConnection: subject="+subject);
        }
        return new PeerManagedConnectionImpl(this);
    }
    
    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Override
    public PeerManagedConnectionImpl matchManagedConnections(Set connections, Subject subject, ConnectionRequestInfo connectionRequestInfoParam) throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("matchManagedConnections() " + connections.size() + " subject="+subject);
        }
        // "A candidate set passed to the matchManagedConnections method should not have any ManagedConnection instances with existing connection handles."
        // This means that any matching connection handle is up for grabs, and we should try to select a random to avoid timeouts on seldom used ones
        final List<PeerManagedConnectionImpl> validChoices = new ArrayList<PeerManagedConnectionImpl>();
        for (final PeerManagedConnectionImpl current : (Set<PeerManagedConnectionImpl>)connections) {
            ConnectionRequestInfo connectionRequestInfoCurrent = current.getPeerConnection().getConnectionRequestInfo();
            if (connectionRequestInfoParam == null || connectionRequestInfoCurrent.equals(connectionRequestInfoParam)) {
                validChoices.add(current);
            }
        }
        if (!validChoices.isEmpty()) {
            return validChoices.get(rnd.nextInt(validChoices.size()));
        }
        return null;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public Set getInvalidConnections(Set allConnections) throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("getInvalidConnections() allConnections.size=" + allConnections.size());
        }
        final Set<PeerManagedConnectionImpl> invalidConnections = new HashSet<PeerManagedConnectionImpl>();
        for (final PeerManagedConnectionImpl current : (Set<PeerManagedConnectionImpl>)allConnections) {
            if (current.getPeerConnection()==null || !current.getPeerConnection().isConnectionOk()) {
                invalidConnections.add(current);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("getInvalidConnections() invalidConnections.size=" + invalidConnections.size());
        }
        return invalidConnections;
    }

    @Override
    public PrintWriter getLogWriter() throws ResourceException { return new PrintWriter(System.out); }
    @Override
    public void setLogWriter(PrintWriter out) throws ResourceException { /* Ignore. */ }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (!this.getClass().equals(obj.getClass())) {
            return false;
        }
        // Nothing else differs at this point
        return true;
    }

    @Override
    public int hashCode() {
        return 42;
    }
}
