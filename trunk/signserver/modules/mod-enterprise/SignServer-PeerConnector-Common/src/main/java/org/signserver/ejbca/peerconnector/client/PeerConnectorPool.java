/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.client;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NoHttpResponseException;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.pool.PoolStats;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.ClientX509KeyManager;
import org.cesecore.keybind.impl.ClientX509TrustManager;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.EjbcaConfiguration;
import org.signserver.ejbca.peerconnector.PeerConnectionSendException;
import org.signserver.ejbca.peerconnector.PeerMessage;

/**
 * Connection pooling of outgoing connections.
 * Since the implementation obviously has threads pool, this should be used via JEE context that allows it.
 * 
 * @version $Id$
 */
public enum PeerConnectorPool {
    INSTANCE;
    
    /** A connection pool, the connection manager used by the pool and a counter of ongoing traffic. */
    private class OutgoingConnectionPool {
        final CloseableHttpClient httpClient;
        final PoolingHttpClientConnectionManager connectionManager;
        final AtomicInteger ongoingMessages = new AtomicInteger(0);
        final List<X509Certificate> clientCertChain;
        final ClientX509TrustManager x509TrustManager;

        OutgoingConnectionPool(final CloseableHttpClient httpClient, final PoolingHttpClientConnectionManager connectionManager,
                final List<X509Certificate> clientCertChain, final ClientX509TrustManager x509TrustManager) {
            this.httpClient = httpClient;
            this.connectionManager = connectionManager;
            this.clientCertChain = new ArrayList<>(clientCertChain);
            this.x509TrustManager = x509TrustManager;
        }
    }
    
    private class TlsSettings {
        private List<X509Certificate> clientCertChain;
        private PrivateKey sslClientPrivateKey = null;
        private List< Collection<X509Certificate> > trustedCertificates = null;
        private String[] supportedProtocols = {};
        private String[] supportedCipherTextSuites = {};
    }

    private final Logger log = Logger.getLogger(PeerConnectorPool.class);

    private boolean useFallbackConfig = false;    
    private ReentrantLock startStopLock = new ReentrantLock(false);
    private Map<Integer,OutgoingConnectionPool> destinationToHttpClient = new HashMap<>();
    private boolean startAllowed = true;

    /** Init a new connection pool for connections to peer systems. */
    private void start(final int peerConnectorId, final String destinationUrl, final int authenticationKeyBindingId, final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession,
            final CertificateStoreSessionLocal certificateStoreSession, final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) {
        log.info("Starting peer connection pool for outgoing connections to " + destinationUrl);
        try {
            startStopLock.lock();
            final TlsSettings tlsSettings = getAuthenticationKeyBindingTlsSettings(authenticationKeyBindingId, internalKeyBindingMgmtSession, certificateStoreSession, cryptoTokenManagementSession);
            if (tlsSettings.supportedProtocols.length==0) {
                log.info("No protocols are yet available for connections to " + destinationUrl);
                return;
            }
            final OutgoingConnectionPool outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
            if (outgoingConnectionPool==null && isStartAllowed()) {
                final ClientX509TrustManager x509TrustManager = new ClientX509TrustManager(tlsSettings.trustedCertificates);
                final PoolingHttpClientConnectionManager connectionManager = getNewconnectionManager(tlsSettings, x509TrustManager);
                final CloseableHttpClient httpClient = getNewHttpClient(connectionManager);
                final OutgoingConnectionPool newOutgoingConnectionPool = new OutgoingConnectionPool(httpClient, connectionManager, tlsSettings.clientCertChain, x509TrustManager);
                destinationToHttpClient.put(peerConnectorId, newOutgoingConnectionPool);
            }
        } finally {
            startStopLock.unlock();
        }
    }

    /**
     * Shut down the connection pool. Blocks until all connections has terminated or the timeout is reached.
     * @param timeoutSeconds
     */
    public void stop(final int peerConnectorId, final int timeoutSeconds) {
        log.info("Shutting down peer connection pool for outgoing connections for peer connector " + peerConnectorId + ".");
        try {
            startStopLock.lock();
            logStats(peerConnectorId);
            final OutgoingConnectionPool oldOutgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
            if (oldOutgoingConnectionPool==null) {
                return; // Nothing to stop
            }
            destinationToHttpClient.remove(peerConnectorId);
            try {
                // Wait for ongoing message count for currentHttpClient to reach 0
                for (int i=0; i<timeoutSeconds; i++) {
                    if (oldOutgoingConnectionPool.ongoingMessages.get()==0) {
                        break;
                    }
                    if (i%10==5) {
                        log.info("Still waiting for ongoing peer connections to terminate...");
                    }
                    Thread.sleep(1000L);
                }
                oldOutgoingConnectionPool.httpClient.close();
            } catch (IOException | InterruptedException e) {
                log.error("Exception on stop: "+e.getMessage(), e);
            }
        } finally {
            startStopLock.unlock();
        }
    }

    /**
     * Shut down all connection pools. Blocks until all connections has terminated or the timeout is reached.
     * Pools may not be started again after calling this method.
     * @param timeoutSeconds
     */
    public void shutdown(final int timeoutSeconds) {
        log.info("Shutting down peer connection pool for outgoing connections.");
        try {
            startStopLock.lock();
            setStartAllowed(false);
            logStats(null);
            Map<Integer, OutgoingConnectionPool> oldDestinationToHttpClient = this.destinationToHttpClient;
            destinationToHttpClient.clear();
            // Wait for ongoing message count for currentHttpClient to reach 0
            try {
                for (int i=0; i<60; i++) {
                    int ongoingMessagesTotal = 0;
                    for (final Integer peerConnectorId : oldDestinationToHttpClient.keySet()) {
                        ongoingMessagesTotal += oldDestinationToHttpClient.get(peerConnectorId).ongoingMessages.get();
                    }
                    if (ongoingMessagesTotal==0) {
                        break;
                    }
                    if (i%10==5) {
                        log.info("Still waiting for ongoing peer "+ongoingMessagesTotal+" connections to terminate...");
                    }
                    Thread.sleep(1000L);
                }
                for (final Integer peerConnectorId : oldDestinationToHttpClient.keySet()) {
                    oldDestinationToHttpClient.get(peerConnectorId).httpClient.close();
                }
            } catch (IOException | InterruptedException e) {
                log.error("Exception on shutdown: "+e.getMessage(), e);
            }
        } finally {
            startStopLock.unlock();
        }
    }

    private void logStats(final Integer peerConnectorId) {
        if (!log.isDebugEnabled()) {
            return;
        }
        if (peerConnectorId==null) {
            // Log stats for all connection pools
            for (final Integer current : destinationToHttpClient.keySet()) {
                logStats(current);
            }
        } else {
            final PeerConnectorPoolStats stats = getPeerConnectorPoolStats(peerConnectorId);
            if (stats==null) {
                log.debug("Stats for "+peerConnectorId+" n/a");
            } else {
                log.debug("Stats for "+peerConnectorId+" Available: " + stats.getAvailable() + " Leased: " + stats.getLeased() + " Max: " + stats.getMax() + " Pending: " + stats.getPending());
            }
        }
    }
    
    public PeerConnectorPoolStats getPeerConnectorPoolStats(final Integer peerConnectorId) {
        final OutgoingConnectionPool outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
        if (outgoingConnectionPool==null) {
            return null;
        } else {
            final PoolStats poolStatsTotal = outgoingConnectionPool.connectionManager.getTotalStats();
            return new PeerConnectorPoolStats(poolStatsTotal.getAvailable(), poolStatsTotal.getLeased(), poolStatsTotal.getMax(), poolStatsTotal.getPending());
        }
    }

    /** @return the SSL client certificate that was used to initiate this connection pool */
    public X509Certificate getUsedClientCertificateForConnection(final Integer peerConnectorId) {
        final OutgoingConnectionPool outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
        if (outgoingConnectionPool==null) {
            return null;
        }
        if (outgoingConnectionPool.clientCertChain.isEmpty()) {
            return null;
        }
        return outgoingConnectionPool.clientCertChain.get(0);
    }

    /** @return the SSL client certificate that was used to initiate this connection pool */
    public X509Certificate getUsedServerCertificateForConnection(final Integer peerConnectorId) {
        final OutgoingConnectionPool outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
        if (outgoingConnectionPool==null) {
            return null;
        }
        final List<X509Certificate> serverCertChain = outgoingConnectionPool.x509TrustManager.getEncounteredServerCertificateChain();
        if (serverCertChain==null || serverCertChain.isEmpty()) {
            return null;
        }
        return serverCertChain.get(0);
    }

    /** @return true if an outgoing pool exists for this destination. */
    public boolean isPeerConnectorPoolAvailable(final Integer peerConnectorId) {
        return destinationToHttpClient.get(peerConnectorId)!=null;
    }
    
    /**
     * Send a PeerMessage to the requested destination, starting the outgoing connection pool if needed.
     * 
     * @return the reply, or null if message could not be sent.
     */
    public PeerMessage send(final Integer peerConnectorId, final String destinationUrl, final Integer authenticationKeyBindingId, final PeerMessage msg,
            final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession, final CertificateStoreSessionLocal certificateStoreSession,
            final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) throws PeerConnectionSendException {
        if (log.isTraceEnabled()) {
            log.trace("sending PeerMessage: " + msg);
        }
        OutgoingConnectionPool outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
        if (outgoingConnectionPool==null) {
            if (log.isTraceEnabled()) {
                log.trace("Need to startup connection pool.");
            }
            if (authenticationKeyBindingId==null || internalKeyBindingMgmtSession==null || certificateStoreSession==null || cryptoTokenManagementSession==null) {
                throw new PeerConnectionSendException("Unable to start connection pool.");
            }
            start(peerConnectorId, destinationUrl, authenticationKeyBindingId, internalKeyBindingMgmtSession, certificateStoreSession, cryptoTokenManagementSession);
        }
        outgoingConnectionPool = destinationToHttpClient.get(peerConnectorId);
        if (outgoingConnectionPool==null) {
            log.warn("Unable to start connection pool.");
            throw new PeerConnectionSendException("Unable to start connection pool.");
        }
        final HttpPost httpPost;
        try {
            httpPost = new HttpPost(destinationUrl);
        } catch (IllegalArgumentException e) {
            throw new PeerConnectionSendException(e.getMessage(), e);
        }
        final byte[] bytes = msg.getAsByteArray();
        httpPost.setEntity(new ByteArrayEntity(bytes));
        httpPost.setProtocolVersion(HttpVersion.HTTP_1_1);
        try {
            outgoingConnectionPool.ongoingMessages.incrementAndGet();
            PeerMessage ret = null;
            PeerConnectionSendException peerConnectionSendException = null;
            // Since we don't check for stale connections just before the request, we want to retry failures at least once
            int retriesLeft = 1;
            while (ret==null && retriesLeft>=0) {
                try {
                    ret = outgoingConnectionPool.httpClient.execute(httpPost, new PeerMessageResponseHandler(outgoingConnectionPool));
                } catch (NoRouteToHostException | ConnectException e) {
                    // Fail fast if the IP cannot be reached or there is a firewall block or nothing is listening on the port.
                    retriesLeft = 0;
                    log.error("Failed connection to " + destinationUrl + ": " + e.getMessage());
                    outgoingConnectionPool.connectionManager.closeIdleConnections(0, TimeUnit.MILLISECONDS);
                    peerConnectionSendException = new PeerConnectionSendException(e.getMessage(), e);
                } catch (HttpResponseException | SSLHandshakeException | NoHttpResponseException e) {
                    if (retriesLeft>0) {
                        if (log.isDebugEnabled()) {
                            log.debug("Failed connection to " + destinationUrl + " ("+retriesLeft+" retries left): " + e.getMessage());
                        }
                    } else {
                        log.error("Failed connection to " + destinationUrl + ": " + e.getMessage());
                    }
                    outgoingConnectionPool.connectionManager.closeIdleConnections(0, TimeUnit.MILLISECONDS);
                    peerConnectionSendException = new PeerConnectionSendException(e.getMessage(), e);
                } catch (IOException | IllegalArgumentException e) {
                    log.error("Exception on send: "+e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.error(e.getMessage(), e);
                    }
                    peerConnectionSendException = new PeerConnectionSendException(e.getMessage(), e);
                }
                retriesLeft--;
            }
            if (ret==null && peerConnectionSendException!=null) {
                throw peerConnectionSendException;
            }
            return ret;
        } finally {
            httpPost.releaseConnection();
            outgoingConnectionPool.ongoingMessages.decrementAndGet();
        }
    }
    
    /** Response handler for result of peer connection request. */
    private class PeerMessageResponseHandler implements ResponseHandler<PeerMessage> {

        final OutgoingConnectionPool outgoingConnectionPool;

        public PeerMessageResponseHandler(final OutgoingConnectionPool outgoingConnectionPool) {
            this.outgoingConnectionPool = outgoingConnectionPool;
        }

        @Override
        public PeerMessage handleResponse(final HttpResponse response) throws IOException {
            final StatusLine statusLine = response.getStatusLine();
            final HttpEntity entity = response.getEntity();
            if (statusLine.getStatusCode() >= 300) {
                throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
            }
            if (entity == null) {
                throw new ClientProtocolException("Response contains no content");
            }
            if (log.isTraceEnabled())  {
                for (final Header header : response.getAllHeaders()) {
                    log.trace("Peer connection response header: " + header.getName() + " = " + header.getValue());
                }
            }
            final byte[] entityBytes = EntityUtils.toByteArray(entity);
            final List<X509Certificate> serverCertificateChain = outgoingConnectionPool.x509TrustManager.getEncounteredServerCertificateChain();
            final AuthenticationToken authenticationToken;
            if (serverCertificateChain==null || serverCertificateChain.isEmpty()) {
                authenticationToken = null;
            } else {
                authenticationToken = new X509CertificateAuthenticationToken(serverCertificateChain.get(0));
            }
            return new PeerMessage(entityBytes, authenticationToken);
        }
    }

    private PoolingHttpClientConnectionManager getNewconnectionManager(final TlsSettings tlsSettings, final X509TrustManager x509TrustManager) {
        final List<X509Certificate> clientCertChain = tlsSettings.clientCertChain;
        final SSLSocketFactory sslSocketFactory = getSocketFactory(clientCertChain, tlsSettings.sslClientPrivateKey, x509TrustManager);
        final HostnameVerifier hostnameVerifier = new DefaultHostnameVerifier(); // recommended upgrade path from the previously used SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER
        final LayeredConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslSocketFactory, tlsSettings.supportedProtocols,
                tlsSettings.supportedCipherTextSuites, hostnameVerifier);
        final Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", sslsf)
                .build();
        final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(registry);
        final ConnectionConfig defaultConnectionConfig = ConnectionConfig.copy(ConnectionConfig.DEFAULT)
                .build();
        connectionManager.setDefaultConnectionConfig(defaultConnectionConfig);
        @SuppressWarnings("deprecation")
        final SocketConfig socketConfig = SocketConfig.copy(SocketConfig.DEFAULT)
                .setSoKeepAlive(EjbcaConfiguration.isPeerSoKeepAlive())
                // true = if a local port is busy (in the TIME_WAIT state), go ahead and reuse it anyway
                .setSoReuseAddress(false)
                // true = Disable Nagle's algorithm
                .setTcpNoDelay(EjbcaConfiguration.isPeerTcpNoDelay())
                // 20 s timeout (Default for Tomcat on the server side)
                .setSoTimeout(EjbcaConfiguration.getPeerSoTimeoutMillis())
                .build();
        connectionManager.setDefaultSocketConfig(socketConfig);
        @SuppressWarnings("deprecation")
        final int maxPoolSize = EjbcaConfiguration.getPeerMaxPoolSize();
        connectionManager.setMaxTotal(maxPoolSize);
        connectionManager.setDefaultMaxPerRoute(maxPoolSize);   // Since we use one pool per outgoing destination
        return connectionManager;
    }
    
    private CloseableHttpClient getNewHttpClient(final PoolingHttpClientConnectionManager connectionManager) {
        // Don't check for stale connections before doing a request (since JCA provides background validation)
        final boolean staleConnectionCheckEnabled = !useFallbackConfig;
        @SuppressWarnings("deprecation")
        final RequestConfig requestConfig = RequestConfig.copy(RequestConfig.DEFAULT)
                .setStaleConnectionCheckEnabled(staleConnectionCheckEnabled) // no non-deprecated alternative seems to exist
                .build();
        final HttpRequestRetryHandler retryHandler = new HttpRequestRetryHandler() {
            @Override
            public boolean retryRequest(IOException exception, int executionCount, HttpContext context) {
                // Never retry failed requests in the HttpClient, so control is returned between attempts
                return false;
            }
        }; 
        return HttpClients.custom()
                .setRetryHandler(retryHandler)
                .disableConnectionState()
                .disableCookieManagement()
                .setConnectionManager(connectionManager)
                .setDefaultSocketConfig(connectionManager.getDefaultSocketConfig())
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    private SSLSocketFactory getSocketFactory(final List<X509Certificate> clientCertChain, final PrivateKey sslClientPrivateKey, final X509TrustManager x509TrustManager) {
        try {
            final KeyManager[] keyManagers = new X509KeyManager[] { new ClientX509KeyManager("alias", sslClientPrivateKey, clientCertChain) };
            final TrustManager[] trustManagers = new X509TrustManager[] { x509TrustManager };
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            log.error("Exception on getSocketFactory: "+e.getMessage(), e);
        }
        return null;
    }

    public boolean isStartAllowed() { return startAllowed; }
    public void setStartAllowed(boolean startAllowed) { this.startAllowed = startAllowed; }

    public void setUseFallbackConfig(final boolean useFallbackConfig) {
        this.useFallbackConfig = useFallbackConfig;
    }

    /** @return TLS settings from the first usable AuthenticationKeyBinding */
    public TlsSettings getAuthenticationKeyBindingTlsSettings(final int authenticationKeyBindingId, final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession,
            final CertificateStoreSessionLocal certificateStoreSession, final CryptoTokenManagementSessionLocal cryptoTokenManagementSession) {
        final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Peer connection pool init"));
        // Initiate the outgoing connection pool if an authenticationKeyBinding is available
        PrivateKey clientPrivateKey = null;
        List<Collection<X509Certificate>> trustAnchors = null;
        AuthenticationKeyBinding akb = null;
        try {
            akb = (AuthenticationKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, authenticationKeyBindingId);
            if (akb==null) {
                log.warn("AuthenticationKeyBinding with id " + authenticationKeyBindingId + " does not exist. Unable to configure TLS for connection pool.");
            } else if (!akb.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                log.warn("AuthenticationKeyBinding '" + akb.getName() + "' is not active. Unable to configure TLS for connection pool.");
                akb = null;
            } else {
                try {
                    clientPrivateKey = cryptoTokenManagementSession.getCryptoToken(akb.getCryptoTokenId()).getPrivateKey(akb.getKeyPairAlias());
                } catch (CryptoTokenOfflineException e) {
                    log.warn("AuthenticationKeyBinding '" + akb.getName() + "' is marked as active, but key pair '" + akb.getKeyPairAlias()
                            + "' in CryptoToken " + akb.getCryptoTokenId() + " is not usable.");
                    akb = null;
                }
            }
        } catch (AuthorizationDeniedException e) {
            // Will never happen, since the AlwaysAllowLocalAuthenticationToken is used
            log.error(e.getMessage(), e);
        }
        final String[] supportedProtocols;
        final String[] supportedCipherTextSuites;
        ArrayList<X509Certificate> clientCertChain = new ArrayList<>();
        if (akb!=null) {
            try {
                trustAnchors = internalKeyBindingMgmtSession.getListOfTrustedCertificates(akb);
            } catch (CADoesntExistsException e1) {
                log.error(e1.getMessage(), e1);
            }
            final CertificateInfo clientCertificateInfo = certificateStoreSession.getCertificateInfo(akb.getCertificateId());
            final List<Certificate> clientCertChainGeneric = certificateStoreSession.getCertificateChain(clientCertificateInfo);
            for (Certificate cert : clientCertChainGeneric) {
                clientCertChain.add((X509Certificate) cert);
            }
            supportedProtocols = akb.getSupportedProtocols();
            supportedCipherTextSuites = akb.getSupportedCipherTextSuites();
        } else {
            supportedProtocols = new String[0];
            supportedCipherTextSuites = new String[0];
        }
        if (clientCertChain.isEmpty()) {
            log.info("No identity configured for outgoing peer connections.");
        } else {
            log.info("Staging the following identity for outgoing peer connections: " + CertTools.getSubjectDN(clientCertChain.get(0)));
        }
        final TlsSettings tlsSettings = new TlsSettings();
        tlsSettings.clientCertChain = clientCertChain;
        tlsSettings.sslClientPrivateKey = clientPrivateKey;
        tlsSettings.trustedCertificates = trustAnchors;
        tlsSettings.supportedProtocols = supportedProtocols;
        tlsSettings.supportedCipherTextSuites = supportedCipherTextSuites;
        return tlsSettings;
    }
}
