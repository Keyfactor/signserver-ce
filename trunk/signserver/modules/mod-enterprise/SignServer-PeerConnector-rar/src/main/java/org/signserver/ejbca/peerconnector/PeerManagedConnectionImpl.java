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

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionEvent;
import javax.resource.spi.ConnectionEventListener;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.LocalTransaction;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionMetaData;
import javax.security.auth.Subject;
import javax.transaction.xa.XAResource;

import org.apache.log4j.Logger;

/**
 * 
 * @version $Id$
 */
public class PeerManagedConnectionImpl implements ManagedConnection, Closeable {

    private static final Logger log = Logger.getLogger(PeerManagedConnectionImpl.class);
    private static final AtomicInteger managedConnectionCounter = new AtomicInteger(0); // For internal debug purposes

    //private final PeerManagedConnectionFactory peerManagedConnectionFactory;
    private List<ConnectionEventListener> listeners = new LinkedList<ConnectionEventListener>();
    
    private int connectionId = managedConnectionCounter.incrementAndGet();
    private PeerConnectionImpl peerConnectionImpl = null;

    public PeerManagedConnectionImpl(final PeerManagedConnectionFactory managedConnectionFactory) {
        if (log.isTraceEnabled()) {
            log.trace("PeerManagedConnectionImpl() connectionId=" + connectionId);
        }
    }

    @Override
    public void close() throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("close() connectionId=" + connectionId);
        }
    }

    @Override
    public void addConnectionEventListener(ConnectionEventListener connectionEventListener) {
        if (log.isTraceEnabled()) {
            log.trace("addConnectionEventListener() connectionId=" + connectionId);
        }
        listeners.add(connectionEventListener);
    }

    @Override
    public void removeConnectionEventListener(ConnectionEventListener connectionEventListener) {
        if (log.isTraceEnabled()) {
            log.trace("removeConnectionEventListener() connectionId=" + connectionId);
        }
        listeners.remove(connectionEventListener);
    }

    @Override
    public void cleanup() throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("cleanup() connectionId=" + connectionId);
        }
    }

    @Override
    public void destroy() throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("destroy() connectionId=" + connectionId);
        }
        peerConnectionImpl = null;
    }

    @Override
    public PeerConnection getConnection(Subject subject, ConnectionRequestInfo connectionRequestInfo) throws ResourceException {
        if (log.isTraceEnabled()) {
            log.trace("getConnection to " + ((PeerConnectionRequestInfo) connectionRequestInfo).getUrl() + " connectionId=" + connectionId);
        }
        if (peerConnectionImpl==null) {
            peerConnectionImpl = new PeerConnectionImpl(this, (PeerConnectionRequestInfo) connectionRequestInfo);
        }
        return peerConnectionImpl;
    }

    /*
     * The resource adapter is required to implement the associateConnection method. The method implementation for a ManagedConnection
     * should dissociate the connection handle (passed as a parameter) from its currently associated ManagedConnection and associate the
     * new connection handle with itself. 
     */
    @Override
    public void associateConnection(Object connection) throws ResourceException {
        PeerConnectionImpl peerConnectionImpl = (PeerConnectionImpl) connection;
        if (log.isTraceEnabled()) {
            log.trace("associateConnection " + peerConnectionImpl + " connectionId=" + connectionId);
        }
        this.peerConnectionImpl = peerConnectionImpl;
    }

    @Override
    public ManagedConnectionMetaData getMetaData() throws ResourceException {
        return new ManagedConnectionMetaData() {
            public String getEISProductName() throws ResourceException { return "PeerConnector JCA"; }
            public String getEISProductVersion() throws ResourceException { return "1.0"; }
            public int getMaxConnections() throws ResourceException { return 10; }
            public String getUserName() throws ResourceException { return null; }
        };
    }

    @Override
    public LocalTransaction getLocalTransaction() throws ResourceException { throw new ResourceException("Resource does not support LocalTransaction."); }
    @Override
    public XAResource getXAResource() throws ResourceException { throw new ResourceException("Resource does not support XA Transactions."); }

    @Override
    public PrintWriter getLogWriter() throws ResourceException { return new PrintWriter(System.out); }
    @Override
    public void setLogWriter(PrintWriter out) throws ResourceException { /* Ignore */ }

    public PeerConnectionImpl getPeerConnection() {
        return peerConnectionImpl;
    }

    /**
     * Broadcast event to application server about the current state of the connection.
     * 
     * @param peerConnectionImpl the connection that is broadcasting
     * @param connectionEvent is defined as one of constants in javax.resource.spi.ConnectionEvent
     */
    void broadcastEvent(final PeerConnectionImpl peerConnectionImpl, final int connectionEvent) {
        final ConnectionEvent connnectionEvent = new ConnectionEvent(this, connectionEvent);
        connnectionEvent.setConnectionHandle(peerConnectionImpl);
        for (final ConnectionEventListener listener : this.listeners) {
            switch (connectionEvent) {
            case ConnectionEvent.LOCAL_TRANSACTION_STARTED:
                if (log.isTraceEnabled()) {
                    log.trace("ConnectionEvent.LOCAL_TRANSACTION_STARTED connectionId=" + connectionId);
                }
                listener.localTransactionStarted(connnectionEvent);
                break;
            case ConnectionEvent.LOCAL_TRANSACTION_COMMITTED:
                if (log.isTraceEnabled()) {
                    log.trace("ConnectionEvent.LOCAL_TRANSACTION_COMMITTED connectionId=" + connectionId);
                }
                listener.localTransactionCommitted(connnectionEvent);
                break;
            case ConnectionEvent.LOCAL_TRANSACTION_ROLLEDBACK:
                if (log.isTraceEnabled()) {
                    log.trace("ConnectionEvent.LOCAL_TRANSACTION_ROLLEDBACK connectionId=" + connectionId);
                }
                listener.localTransactionRolledback(connnectionEvent);
                break;
            case ConnectionEvent.CONNECTION_ERROR_OCCURRED:
                if (log.isTraceEnabled()) {
                    log.trace("ConnectionEvent.CONNECTION_ERROR_OCCURRED connectionId=" + connectionId);
                }
                listener.connectionErrorOccurred(connnectionEvent);
                break;
            case ConnectionEvent.CONNECTION_CLOSED:
                if (log.isTraceEnabled()) {
                    log.trace("ConnectionEvent.CONNECTION_CLOSED connectionId=" + connectionId);
                }
                listener.connectionClosed(connnectionEvent);
                break;
            }
        }
    }
}
