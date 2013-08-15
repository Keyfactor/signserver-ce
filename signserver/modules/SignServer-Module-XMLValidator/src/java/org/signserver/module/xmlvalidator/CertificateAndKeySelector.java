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
package org.signserver.module.xmlvalidator;

import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.apache.log4j.Logger;

/**
 * KeySelector that selects a key from an X509Certificate in the document  and
 * also holds the selected certificate.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
class CertificateAndKeySelector extends KeySelector {

    /** Logger for this class. */
    private static Logger log = Logger.getLogger(CertificateAndKeySelector.class);
    
    private int requestId;
    private X509Certificate choosenCert;
    private List<? extends Certificate> certificates;

    /**
     * Addional signature methods not yet covered by
     * javax.xml.dsig.SignatureMethod
     * 
     * Defined in RFC 4051 {@link http://www.ietf.org/rfc/rfc4051.txt}
     */
    private static final String SIGNATURE_METHOD_RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SIGNATURE_METHOD_RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    private static final String SIGNATURE_METHOD_RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private static final String SIGNATURE_METHOD_ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    
    public CertificateAndKeySelector() {
        this(-1);
    }

    public CertificateAndKeySelector(int requestId) {
        this.requestId = requestId;
    }

    @Override
    public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

        if (log.isDebugEnabled()) {
            log.debug("Request " + requestId + ":  select(\"" + keyInfo + ", \"" + purpose + ", \"" + method + ", \"" + context + "\")");
        }

        SignatureMethod signatureMethod = (SignatureMethod) method;

        List<X509Certificate> foundCerts = new LinkedList<X509Certificate>();

        for (Object o1 : keyInfo.getContent()) {
            log.trace("o1: " + o1);
            if (o1 instanceof X509Data) {
                X509Data data = (X509Data) o1;
                for (Object o2 : data.getContent()) {
                    if (o2 instanceof X509Certificate) {
                        X509Certificate cert = (X509Certificate) o2;
                        if (matchingAlgorithms(cert.getPublicKey().getAlgorithm(), signatureMethod.getAlgorithm())) {
                            foundCerts.add(cert);
                        }
                    }
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Request " + requestId + ": foundCerts.size = " + foundCerts.size());
        }

        if (foundCerts.isEmpty()) {
            throw new KeySelectorException("No suitable certificate found");
        }

        try {
            CertificateFactory cf;
            cf = CertificateFactory.getInstance("X.509", "BC");


            CertPath cp = cf.generateCertPath(foundCerts);

            // X.509 certificates are by convention returned ordered with the signer certificate first
            certificates = cp.getCertificates();

            if (log.isDebugEnabled()) {
                int i = 0;
                for (Certificate cert : certificates) {
                    if (cert instanceof X509Certificate) {
                        log.debug("Cert " + i++ + " = " + ((X509Certificate) cert).getSubjectDN().toString());
                    }
                }
            }
            choosenCert = (X509Certificate) certificates.get(0);
        } catch (CertificateException ex) {
            throw new KeySelectorException("Certificate path error", ex);
        } catch (NoSuchProviderException ex) {
            throw new KeySelectorException("BouncyCastle not loaded", ex);
        }


        return new KeySelectorResult() {

            public Key getKey() {
                return choosenCert.getPublicKey();
            }
        };
    }

    private boolean matchingAlgorithms(String keyAlg, String signAlg) {
        if ("RSA".equalsIgnoreCase(keyAlg)) {
            return SignatureMethod.RSA_SHA1.equalsIgnoreCase(signAlg) ||
                    SIGNATURE_METHOD_RSA_SHA256.equals(signAlg) ||
                    SIGNATURE_METHOD_RSA_SHA384.equals(signAlg) ||
                    SIGNATURE_METHOD_RSA_SHA512.equals(signAlg);
        } else if ("DSA".equalsIgnoreCase(keyAlg)) {
            return SignatureMethod.DSA_SHA1.equalsIgnoreCase(signAlg);
        } else if ("ECDSA".equalsIgnoreCase(keyAlg)) {
            return SIGNATURE_METHOD_ECDSA_SHA1.equals(signAlg);
        }
        return false;
    }

    public X509Certificate getChoosenCert() {
        return choosenCert;
    }

    public List<? extends Certificate> getCertificates() {
        return certificates;
    }
}
