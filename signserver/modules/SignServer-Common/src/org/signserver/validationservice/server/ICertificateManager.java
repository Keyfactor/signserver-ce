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

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.common.Validation;

/**
 * 
 * Factory class transforming different certficates to a ICertificate.
 * 
 * @author Philip Vendil 30 nov 2007
 * @version $Id$
 */
public class ICertificateManager {

    /**
     * Method in charge of verifying and checking the validity (not revocation status)
     * of a ICertificate against a set of CA certificates. 
     * @param cert the end user cert
     * @param cAChain list of CA certificates
     * @return a Validation object
     * @throws SignServerException
     */
    public static Validation verifyCertAndChain(Certificate cert, List<Certificate> cAChain) throws SignServerException {
        if (cert instanceof X509Certificate) {
            return verifyX509CertAndChain((X509Certificate) cert, cAChain);
        } else {
            throw new SignServerException("Error certificate of type " + cert.getClass().getName() + " isn't supported by the ICertificateManager");
        }
    }

    private static Validation verifyX509CertAndChain(X509Certificate icert,
            List<Certificate> chain) throws SignServerException {
        try {


            try {
                icert.verify(((X509Certificate) chain.get(0)).getPublicKey(), "BC");
            } catch (InvalidKeyException e6) {
                return new Validation(icert, chain, Validation.Status.DONTVERIFY, "Error certificates signature doesn't verify with CA certificates public key.");
            } catch (SignatureException e6) {
                return new Validation(icert, chain, Validation.Status.DONTVERIFY, "Error certificates signature doesn't verify with CA certificates public key.");
            }

            try {
                icert.checkValidity();
            } catch (CertificateExpiredException e5) {
                return new Validation(icert, chain, Validation.Status.EXPIRED, "Error certificate have expired.");
            } catch (CertificateNotYetValidException e5) {
                return new Validation(icert, chain, Validation.Status.NOTYETVALID, "Error certificate is not yet valid.");
            }

            for (Certificate cacert : chain) {
                try {
                    ((X509Certificate) cacert).checkValidity();
                } catch (CertificateExpiredException e5) {
                    return new Validation(icert, chain, Validation.Status.CAEXPIRED, "Error CA Certificate or the requested certificate have expired.");
                } catch (CertificateNotYetValidException e5) {
                    return new Validation(icert, chain, Validation.Status.CANOTYETVALID, "Error CA Certificate or the requested certificate is not yet valid.");
                }
            }

            ArrayList<java.security.cert.X509Certificate> rootCerts = new ArrayList<java.security.cert.X509Certificate>();
            rootCerts.add((X509Certificate) chain.get(chain.size() - 1));


            //validating path
            List<Certificate> certchain = new ArrayList<Certificate>();
            for (int i = chain.size() - 1; i >= 0; i--) {
                certchain.add((Certificate) chain.get(i));
            }
            certchain.add((Certificate) icert);

            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);

            Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
            Iterator<java.security.cert.X509Certificate> iter = rootCerts.iterator();
            while (iter.hasNext()) {
                trust.add(new TrustAnchor(iter.next(), null));
            }
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");

            PKIXParameters param = new PKIXParameters(trust);

            List<Object> list = new ArrayList<Object>();
            list.addAll(certchain);
            CertStore store = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(list));

            param.addCertStore(store);
            param.setDate(new Date());
            param.setRevocationEnabled(false);
            try {
                cpv.validate(cp, param);
            } catch (CertPathValidatorException e) {
                return new Validation(icert, chain, Validation.Status.DONTVERIFY, e.getMessage());
            }
        } catch (NoSuchAlgorithmException e1) {
            throw new SignServerException("Error verifying certificate chain ", e1);
        } catch (NoSuchProviderException e1) {
            throw new SignServerException("Error verifying certificate chain ", e1);
        } catch (InvalidAlgorithmParameterException e1) {
            throw new SignServerException("Error verifying certificate chain ", e1);
        } catch (CertificateException e1) {
            throw new SignServerException("Error verifying certificate chain ", e1);
        }

        return new Validation(icert, chain, Validation.Status.VALID, "Certificate is valid");
    }
}
