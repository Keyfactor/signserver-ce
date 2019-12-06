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

import java.io.IOException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.common.GlobalConfiguration;
import org.signserver.ejbca.peerconnector.client.PeerConnectorPool;
import org.signserver.ejbca.peerconnector.common.PeersGlobalProperties;

/**
 * @version $Id$
 */
public class PeerConnectorServlet extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(PeerConnectorServlet.class);
    private static final long serialVersionUID = 1L;
    @SuppressWarnings("deprecation")
    private static final long AUTHENTICATION_TOKEN_CACHE_TIME = EjbcaConfiguration.getPeerIncomingAuthCacheTimeMillis();
    @SuppressWarnings("deprecation")
    private static final int MAX_INCOMING_MESSAGE_SIZE = EjbcaConfiguration.getPeerIncomingMaxMessageSize();

    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EjbBridgeSessionLocal ejbBridgeSession;
    @EJB
    private EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    @Override
    public void destroy() {
        PeerConnectorPool.INSTANCE.shutdown(30);    // Make sure we shutdown the pool, in the fallback case where the RAR is not deployed.
        super.destroy();
    }

    private boolean isIncomingConnectionsAllowed() {
        return Boolean.TRUE.toString().equalsIgnoreCase(globalConfigurationSession.getGlobalConfiguration().getProperty(GlobalConfiguration.SCOPE_GLOBAL, PeersGlobalProperties.PEERS_INCOMING_ENABLED));
    }

    // Use HTTP POST for sending and receiving messages
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        // We have not performed any authentication of this client, we expect this to be a HelloMsg
        final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        final AuthenticationToken authenticationToken;
        if (certificates==null || certificates[0]==null) {
            authenticationToken = null;
        } else {
            authenticationToken = getAuthenticationToken(request, certificates[0]);
        }
        if (authenticationToken==null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Peer Systems incoming connections not allowed. Denied access from " + request.getRemoteAddr());
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You are not authorized to this resource.");
            return;
        }
        if (LOG.isTraceEnabled()) {
            final Enumeration<String> headerNameEnumeration = request.getHeaderNames();
            while (headerNameEnumeration.hasMoreElements()) {
                final String headerName = headerNameEnumeration.nextElement();
                LOG.trace("Incoming peer connection header: " + headerName + " = " + request.getHeader(headerName));
            }
        }
        final byte[] requestBytes = readContent(request);
        // Parse message
        final PeerMessage peerMessageIn = new PeerMessage(requestBytes, authenticationToken);
        if (LOG.isDebugEnabled()) {
            LOG.debug("peerMessageIn: " + peerMessageIn);
        }
        final int sourceId = peerMessageIn.getSourceId();
        if (PeerConnectorInRegistry.INSTANCE.updatePeerIncomingInformation(sourceId, authenticationToken)) {
            // Since this is a new entry we spend some time looking up and storing the remote address
            final String remoteAddress = request.getRemoteAddr();
            PeerConnectorInRegistry.INSTANCE.updatePeerIncomingInformation(sourceId, authenticationToken, remoteAddress);
            if (LOG.isDebugEnabled()) {
                LOG.debug("New connection from " + remoteAddress + " authenticationToken=" + authenticationToken);
            }
        }
        PeerMessage peerMessageOut;
        // Check that this authentication token is intended for connection to this peer
        if (!new AdminAuthHelper(globalConfigurationSession).isPeerAuthorizedNoLogging(certificates[0], PeerAccessRules.INCOMING.getResource())) {
            LOG.info("Denied peer access to " + certificates[0].getSerialNumber().toString(16) + " issuer: '" + certificates[0].getIssuerDN() + "'.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            peerMessageOut = PeerMessageRegistry.INSTANCE.dispatchAndRespond(peerMessageIn, ejbBridgeSession, enterpriseEditionEjbBridgeSession);
            if (peerMessageOut == null) {
                // Server side should always acknowledge the transfer, if the client want confirmation that the
                // sent message was handled correctly the handler should have provided a message for this.
                peerMessageOut = new GenericErrorResponseMessage(null, null);
            }
            // Invoke handlers that subscribe to this message
            writeResponse(response, peerMessageOut.getAsByteArray());
        }
    }

    @SuppressWarnings("resource") // ServletInputStream does not have to be closed, container handles this
    private byte[] readContent(final HttpServletRequest request) throws IOException {
        final ServletInputStream servletInputStream = request.getInputStream();
        final int contentLength = request.getContentLength();
        if (contentLength > MAX_INCOMING_MESSAGE_SIZE) {
            throw new IOException("Request to large.");
        }
        final ReadableByteChannel readableByteChannel = Channels.newChannel(servletInputStream);
        final ByteBuffer byteBuffer = ByteBuffer.allocate(contentLength);
        int readBytes = 0;
        int readBytesTotal = 0;
        while (readBytes != -1 && readBytesTotal < contentLength) {
            readBytes = readableByteChannel.read(byteBuffer);
            readBytesTotal += readBytes;
        }
        return byteBuffer.array();
    }

    private void writeResponse(final HttpServletResponse response, final byte[] buf) throws IOException {
        response.setContentType("application/octet-stream");
        // Enables keep-alive (as long as its HTTP1.1 and chunked encoding isn't used)
        response.setContentLength(buf.length);
        final ServletOutputStream os = response.getOutputStream();
        os.write(buf);
        //os.flush();   // Might mess up keep-alive
        //os.close();
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType("text/plain");
        try (Writer out = response.getWriter()) {
            out.write("ALLOK");
            out.flush();
        } catch (IOException e) {
            LOG.error("Error writing to Servlet Response.", e);
        }
    }

    /**
     * @return a cached authentication token (by certificate fingerprint)
     */
    private AuthenticationToken getAuthenticationToken(final HttpServletRequest request, X509Certificate certificate) throws IOException {
        final String key = AuthenticationSessionCache.generateKey(certificate);
        AuthenticationToken authenticationToken = null; // Disable "cache" AuthenticationSessionCache.INSTANCE.getAuthenticationTokenByFingerprint(key, AUTHENTICATION_TOKEN_CACHE_TIME);
        if (authenticationToken == null) {
            // Loading the GlobalConfiguration for checking if incoming connections are expensive, so only do it for new connection sets
            if (!isIncomingConnectionsAllowed()) {
                return null;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("SSL/TLS cipher_suite=" + request.getAttribute("javax.servlet.request.cipher_suite")
                        + " key_size=" + request.getAttribute("javax.servlet.request.key_size"));
            }
            final Set<X509Certificate> credentials = new HashSet<>();
            credentials.add(certificate);
            final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
            authenticationToken = webAuthenticationProviderSession.authenticate(subject);
            AuthenticationSessionCache.INSTANCE.updateAuthenticationTokenByFingerprint(key, authenticationToken, AUTHENTICATION_TOKEN_CACHE_TIME);
        }
        return authenticationToken;
    }
}
