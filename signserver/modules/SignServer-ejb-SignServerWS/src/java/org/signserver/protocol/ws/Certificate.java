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
package org.signserver.protocol.ws;

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.xml.bind.annotation.XmlTransient;

import org.ejbca.util.Base64;
import org.signserver.validationservice.common.ICertificate;

/**
 * Class representing a certificate sent through WebService in
 * Base64 format.
 *
 * @author Philip Vendil 29 okt 2007
 * @version $Id$
 */
public class Certificate {

    private String certificateBase64;
    private String certType = defaultCertType;
    private String provider = defaultProvider;
    private transient static String defaultCertType = "X.509"; // Default certificate type
    private transient static String defaultProvider = "BC";// Default provider

    public Certificate() {
    }

    /**
     * Constructor containing the regular certificate
     * @param cert
     * @throws CertificateEncodingException 
     */
    public Certificate(java.security.cert.Certificate cert) throws CertificateEncodingException {
        setCertificate(cert);
    }

    /**
     * Constructor from  generated object
     * @param cert an ICertificate
     * @throws CertificateEncodingException 
     */
    public Certificate(ICertificate cert) throws CertificateEncodingException {
        setCertificateBase64(new String(Base64.encode(cert.getEncoded())));
    }

    /**
     * 
     * @return the certificate in Base64 format.
     */
    public String getCertificateBase64() {
        return certificateBase64;
    }

    /**
     * 
     * @param certificateBase64   certificate in Base64 format.
     */
    public void setCertificateBase64(String certificateBase64) {
        this.certificateBase64 = certificateBase64;
    }

    /**
     * Help method used to retrieve the signerCertificate in Certificate format
     * instead of String
     * 
     * @return the signer certificate or null if no signer certificate was set in the call.
     * @throws CertificateException 
     * @throws NoSuchProviderException 
     */
    @XmlTransient
    public java.security.cert.Certificate getCertificate() throws CertificateException, NoSuchProviderException {
        String cType = defaultCertType;
        String prov = defaultProvider;
        if (certType != null) {
            cType = certType;
        }
        if (prov != null) {
            prov = provider;
        }

        return getCertificate(cType, prov);
    }

    public java.security.cert.Certificate getCertificate(String certType, String provider) throws CertificateException, NoSuchProviderException {
        if (certificateBase64 == null) {
            return null;
        }

        CertificateFactory cf = CertificateFactory.getInstance(certType, provider);
        return cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certificateBase64.getBytes())));

    }

    /**
     * Help method used to set the certificate in java.security.cert.Certificate from
     * @param certificate the certificate to set.
     * @throws CertificateEncodingException
     */
    public void setCertificate(java.security.cert.Certificate certificate) throws CertificateEncodingException {
        if (certificate != null) {
            certificateBase64 = new String(Base64.encode(certificate.getEncoded()));
        }
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
}
