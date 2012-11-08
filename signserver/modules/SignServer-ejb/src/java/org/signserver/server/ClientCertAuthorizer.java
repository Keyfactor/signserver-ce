/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * Client certificate authorizer.
 *
 * @author Philip Vendil 24 nov 2007
 * @version $Id$
 */
public class ClientCertAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientCertAuthorizer.class);
    
    private int workerId;
    private ProcessableConfig config = null;

    /**
     * @see org.signserver.server.IAuthorizer#init(int,
     * org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)  throws SignServerException {
        this.config = new ProcessableConfig(config);
        this.workerId = workerId;
    }
    
    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }

    /**
     * Performing SignServer 2.x client certificate authentication.
     *
     * @see org.signserver.server.IAuthorizer#isAuthorized(ProcessRequest,
     * RequestContext)
     */
    public void isAuthorized(final ProcessRequest request,
            final RequestContext requestContext)
            throws SignServerException, IllegalRequestException {
        final X509Certificate clientCert = (X509Certificate)
                requestContext.get(RequestContext.CLIENT_CERTIFICATE);
        if (clientCert == null) {
            throw new IllegalRequestException(
                    "Error, client authentication is required.");
        } else {
            if (!authorizedToRequestSignature(clientCert,
                    config.getAuthorizedClients())) {
                throw new IllegalRequestException("Worker " + workerId + ": "
                        + "Client is not authorized: "
                        + "\"" + clientCert.getSubjectDN().toString() + "\", "
                        + "\"" + clientCert.getSerialNumber().toString(16)
                        + ", " + clientCert.getIssuerDN().toString() + "\"");
            }
        }
    }

    private boolean authorizedToRequestSignature(
            final X509Certificate clientCert,
            final Collection<AuthorizedClient> authorizedClients) {

        boolean isAuthorized = false;
        final Iterator<AuthorizedClient> iter = authorizedClients.iterator();
        final String clientDN = CertTools.stringToBCDNString(
                clientCert.getIssuerDN().toString());

        while (iter.hasNext() && !isAuthorized) {
            final AuthorizedClient next = (AuthorizedClient) iter.next();
            try {
                // If both authorized clients Issuer DN And Cert Serial match,
                // the client is authorized.
                isAuthorized = clientDN.equals(next.getIssuerDN())
                        && clientCert.getSerialNumber()
                        .equals(new BigInteger(next.getCertSN(), 16));
            } catch (IllegalArgumentException e) {
                LOG.warn(e.getMessage() + " for athorized client");
            }
        }
        return isAuthorized;
    }
}
