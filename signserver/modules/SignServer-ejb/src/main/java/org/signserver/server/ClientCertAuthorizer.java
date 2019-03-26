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
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.AuthorizedClientEntry;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;

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

    private Set<AuthorizedClientEntry> authorizedClients;
    
    /**
     * Initialize a ClientCertAuthorizer.
     * 
     * @param workerConfig Worker configuration
     * @throws org.signserver.common.SignServerException
     * @see org.signserver.server.IAuthorizer#init(int,
     * org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    @Override
    public void init(final int workerId, final WorkerConfig workerConfig,
            final EntityManager em)  throws SignServerException {
        this.workerId = workerId;
        this.authorizedClients =
                AuthorizedClientEntry.clientEntriesFromAuthClients(workerConfig.getAuthorizedClientsGen2());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Configured clients: " + authorizedClients);
        }
    }
    
    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }

    /**
     * Performing SignServer 2.x client certificate authentication.
     *
     * @throws org.signserver.common.SignServerException
     * @throws org.signserver.common.IllegalRequestException
     * @see org.signserver.server.IAuthorizer#isAuthorized(ProcessRequest,
     * RequestContext)
     */
    @Override
    public void isAuthorized(final Request request,
            final RequestContext requestContext)
            throws SignServerException, IllegalRequestException {
        final X509Certificate clientCert = (X509Certificate)
                requestContext.get(RequestContext.CLIENT_CERTIFICATE);
        if (clientCert == null) {
            throw new IllegalRequestException(
                    "Error, client authentication is required.");
        } else {
            if (!authorizedToRequestSignature(clientCert)) {
                throw new IllegalRequestException("Worker " + workerId + ": "
                        + "Client is not authorized: "
                        + "\"" + CertTools.stringToBCDNString(clientCert.getSubjectX500Principal().getName()) + "\", "
                        + "\"" + clientCert.getSerialNumber().toString(16)
                        + ", " + CertTools.stringToBCDNString(clientCert.getIssuerX500Principal().getName()) + "\"");
            }
        }
    }

    private boolean authorizedToRequestSignature(final X509Certificate clientCert) {
        boolean ruleMatched = false;

        // Only one MatchIssuerType is supported now
        MatchIssuerWithType matchIssuerWithType = MatchIssuerWithType.ISSUER_DN_BCSTYLE;
        final String clientIssuerDN = CertTools.stringToBCDNString(clientCert.getIssuerX500Principal().getName());

        for (final AuthorizedClientEntry authClient : authorizedClients) {
            MatchSubjectWithType matchSubjectWithType = authClient.getMatchSubjectWithType();
            switch (matchSubjectWithType) {
                case CERTIFICATE_SERIALNO:
                    final BigInteger sn = clientCert.getSerialNumber();
                    String matchSubjectwithValueToBeUsed = sn.toString(16);
                    final AuthorizedClientEntry client
                            = new AuthorizedClientEntry(matchSubjectwithValueToBeUsed, clientIssuerDN, MatchSubjectWithType.CERTIFICATE_SERIALNO, matchIssuerWithType);
                    if (authorizedClients.contains(client)) {
                        ruleMatched = true;
                        break;
                    }
                case SUBJECT_RDN_CN:
                    break;
                case SUBJECT_RDN_SERIALNO:
                    break;
                default:
                    throw new AssertionError(matchSubjectWithType.name());
            }

        }

        return ruleMatched;
    }
}
