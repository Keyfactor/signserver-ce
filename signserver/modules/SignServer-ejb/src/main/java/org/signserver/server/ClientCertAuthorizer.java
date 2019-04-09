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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DNFieldExtractor;
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

    private static final Pattern SERIAL_PATTERN = Pattern.compile("\\bSERIALNUMBER=", Pattern.CASE_INSENSITIVE);
    
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
        String matchSubjectwithValue;
        AuthorizedClientEntry client;

        // Only one MatchIssuerType is supported now
        MatchIssuerWithType matchIssuerWithType = MatchIssuerWithType.ISSUER_DN_BCSTYLE;
        final String clientIssuerDN = CertTools.stringToBCDNString(clientCert.getIssuerX500Principal().getName());
        
        for (final AuthorizedClientEntry authClient : authorizedClients) {
            MatchSubjectWithType matchSubjectWithType = authClient.getMatchSubjectWithType();

            if (matchSubjectWithType == MatchSubjectWithType.CERTIFICATE_SERIALNO) {
                final BigInteger sn = clientCert.getSerialNumber();
                matchSubjectwithValue = sn.toString(16);
                client = new AuthorizedClientEntry(matchSubjectwithValue, clientIssuerDN, MatchSubjectWithType.CERTIFICATE_SERIALNO, matchIssuerWithType);
                
                if (authorizedClients.contains(client)) {
                    ruleMatched = true;
                    break;
                }
            } else {
                // See X509CertificateAuthenticationToken in EJBCA/CESeCore
                String certstring = CertTools.getSubjectDN(clientCert);
                certstring = SERIAL_PATTERN.matcher(certstring).replaceAll("SN=");
                final String altNameString = CertTools.getSubjectAlternativeName(clientCert);
                DNFieldExtractor dnExtractor = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);
                DNFieldExtractor anExtractor = new DNFieldExtractor(altNameString, DNFieldExtractor.TYPE_SUBJECTALTNAME);
                int parameter = DNFieldExtractor.CN;
                DNFieldExtractor usedExtractor = dnExtractor;
                
                switch (matchSubjectWithType) {
                    case SUBJECT_RDN_CN:
                        parameter = DNFieldExtractor.CN;
                        break;
                    case SUBJECT_RDN_SERIALNO:
                        parameter = DNFieldExtractor.SN;
                        break;
                    case SUBJECT_RDN_DC:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_ST:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_L:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_O:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_OU:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_TITLE:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_UID:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_RDN_E:
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_ALTNAME_RFC822NAME:
                        usedExtractor = anExtractor;
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    case SUBJECT_ALTNAME_MSUPN:
                        usedExtractor = anExtractor;
                        // TODO: Implement
                        throw new UnsupportedOperationException("MatchSubjectWithType not supported yet: " + matchSubjectWithType);
                    default: // It should not happen though
                        throw new AssertionError(matchSubjectWithType.name());
                }
                
                int size = usedExtractor.getNumberOfFields(parameter);
                AuthorizedClientEntry[] clientstrings = new AuthorizedClientEntry[size];
                for (int i = 0; i < size; i++) {
                    String value = usedExtractor.getField(parameter, i);
                    clientstrings[i] = new AuthorizedClientEntry(value, clientIssuerDN, matchSubjectWithType, matchIssuerWithType);
                    
                    if (authorizedClients.contains(clientstrings[i])) {
                        ruleMatched = true;
                        break;
                    }
                }
            }
        }

        return ruleMatched;
    }
    
    private String getDNAttributeValueByProperty(String property, String completeDN) {
        Map<String, String> dnValueByField = new HashMap<>();
        List<String> dnFields = Arrays.asList(completeDN.split(","));
        dnFields.stream().map((dnField) -> dnField.split("=")).forEachOrdered((pairs) -> {
            dnValueByField.put(pairs[0], pairs[1]);
        });

        return dnValueByField.get(property);
    }
}
