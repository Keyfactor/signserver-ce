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
package org.signserver.validationservice.server;

import java.net.ConnectException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.Validation;

/**
 * Dummy validator used for testing and demonstration purposes.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class DummyValidator extends BaseValidator {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(DummyValidator.class);

    /** Waiting time to simulate work. */
    private transient long waitTime = 0;

    /** Map with revoked certificates. */
    private static Map<String, Validation.Status> revokedMap =
            new HashMap<String, Validation.Status>();

    /**
     *
     * @param workerId
     * @param validatorId
     * @param props
     * @param entityManager
     * @param cryptoToken
     * @throws SignServerException
     * @see org.signserver.validationservice.server.IValidator#init(int, int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.ICryptoToken)
     */
    @Override
    public void init(final int workerId, final int validatorId,
            final Properties props, final EntityManager entityManager,
            final ICryptoToken cryptoToken) throws SignServerException {
        super.init(workerId, validatorId, props, em, ct);

        if (props.getProperty("TESTPROP") == null) {
            throw new SignServerException(
                    "Error property 'TESTPROP' is not set for validator " +
                    validatorId + " in worker " + workerId);
        }

        if (props.getProperty("WAITTIME") != null) {
            waitTime = Long.parseLong(props.getProperty("WAITTIME"));
        }

        revokedMap.clear();
        if (props.getProperty("REVOKED") != null) {
            for (String dn : props.getProperty("REVOKED").split(";")) {
                revokedMap.put(dn, Validation.Status.REVOKED);
            }
        }

    }

    /**
     * @param cert
     * @see org.signserver.validationservice.server.IValidator#validate(org.signserver.validationservice.common.ICertificate)
     */
    @Override
    public Validation validate(final Certificate cert)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        LOG.trace(">validate");

        Validation result = null;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validate certificate: " + CertTools.getSubjectDN(cert));
        }

        // Simulate work
        try {
            Thread.sleep(waitTime);
        } catch (InterruptedException ignored) {}

        if (getCertificateChain(cert) != null ||
                ((X509Certificate) cert).getBasicConstraints() != -1) {
            
            final X509Certificate xcert = (X509Certificate) cert;

            // First check this validator's own revocation list
            final Validation.Status status = revokedMap.get(CertTools.getSubjectDN(xcert));
            if (status != null) {
                result = new Validation(cert, getCertificateChain(cert), status,
                        "Not valid: " + status.toString());
            }
            // Then some special cases
            else if(CertTools.getIssuerDN(xcert).equals("CN=cert1")) {
                result = new Validation(cert,
                        getCertificateChain(cert),
                        Validation.Status.REVOKED,
                        "This certificate is revoced",
                        new Date(), 3);
            } else if(CertTools.getSubjectDN(xcert).equals("CN=revocedRootCA1")){
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.REVOKED,
                        "This certificate is revoced", new Date(), 3);
            } else if (CertTools.getSubjectDN(xcert).equals("CN=revocedRootCA1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.REVOKED,
                        "This certificate is revoced", new Date(), 3);
            } else if (CertTools.getIssuerDN(xcert).equals("CN=revocedRootCA1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.CAREVOKED,
                        "This certificate is valid", new Date(), 3);
            } else if (CertTools.getSubjectDN(cert).equals("CN=revokedCert1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.REVOKED,
                        "This certificate is revoced", new Date(), 3);
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidRootCA1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidSubCA1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getIssuerDN(cert).equals("CN=ValidSubCA1")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidSubCA2")
                    && validatorId == 2) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidSubSubCA2")
                    && validatorId == 2) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidSubSubSubCA2")
                    && validatorId == 2) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=ValidSubSubSubSubCA2")
                    && validatorId == 2) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getIssuerDN(cert).equals("CN=ValidSubSubSubSubCA2")
                    && validatorId == 2) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals(
                    "CN=xmlsigner2,O=SignServer Test,C=SE")
                    || CertTools.getSubjectDN(cert).equals(
                    "CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals(
                    "CN=FirstCA,O=EJBCA Testing,C=SE")
                    || CertTools.getSubjectDN(cert).equals(
                    "CN=endentity1,O=EJBCA Testing,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            } else if (CertTools.getSubjectDN(cert).equals("CN=pdfsigner,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            }
            // All other certificates issued by DemoRootCA1 is OK
            else if (CertTools.getIssuerDN(cert).equals(
                    "CN=DemoRootCA1,OU=EJBCA,O=SignServer Sample,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            }
            // All other certificates issued by DemoRootCA2 is OK
            else if (CertTools.getIssuerDN(cert).equals(
                    "CN=DemoRootCA2,OU=EJBCA,O=SignServer Sample,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            }
            // All other certificates issued by DSSRootCA10 is OK
            else if (CertTools.getIssuerDN(cert).equals(
                    "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE")) {
                result = new Validation(cert, getCertificateChain(cert),
                        Validation.Status.VALID, "This certificate is valid");
            }
        }

        LOG.trace("<validate");
        return result;
    }

    /**
     * @see org.signserver.validationservice.server.IValidator#testConnection()
     */
    public void testConnection() throws ConnectException, SignServerException {
        // Do nothing
    }
}
