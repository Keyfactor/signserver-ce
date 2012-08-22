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
package org.signserver.test.utils.builders;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Builds a certificate based on the specified information and using default 
 * values for everything else.
 *
 *
 * @version $Id$
 */
public class CertBuilder implements Cloneable {
    
    private Random random = new SecureRandom();
    private static final BigInteger LOWEST = new BigInteger("0080000000000000", 16);

    private static final BigInteger HIGHEST = new BigInteger("7FFFFFFFFFFFFFFF", 16);
    
    private Date notBefore;
    private Date notAfter;
    private BigInteger serialNumber;
    private PrivateKey issuerPrivateKey;
    private PublicKey subjectPublicKey;
    private X509Name subject;
    private X509Name issuer;
    private String signatureAlgorithm;
    
    private KeyPair _subjectKeyPair;
    private boolean version3 = true;
    private Set<CertExt> extensions = new HashSet<CertExt>();
    private boolean[] issuerUniqueId;
    private boolean[] subjectUniqueId;

    public Date getNotAfter() {
        if (notAfter == null) {
            notAfter = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365));
        }
        return notAfter;
    }

    public CertBuilder setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
        return this;
    }

    public Date getNotBefore() {
        if (notBefore == null) {
            notBefore = new Date();
        }
        return notBefore;
    }

    public CertBuilder setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public BigInteger getSerialNumber() {
        if (serialNumber == null) {
            serialNumber = generateSerialNumber();
        }
        return serialNumber;
    }

    public CertBuilder setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public PrivateKey getIssuerPrivateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (issuerPrivateKey == null) {
            if (_subjectKeyPair == null) {
                _subjectKeyPair = CryptoUtils.generateRSA(1024);
            }
            issuerPrivateKey = _subjectKeyPair.getPrivate();
        }
        return issuerPrivateKey;
    }

    public CertBuilder setIssuerPrivateKey(PrivateKey issuerPrivateKey) {
        this.issuerPrivateKey = issuerPrivateKey;
        return this;
    }

    public PublicKey getSubjectPublicKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (subjectPublicKey == null) {
            if (_subjectKeyPair == null) {
                _subjectKeyPair = CryptoUtils.generateRSA(1024);
            }
            subjectPublicKey = _subjectKeyPair.getPublic();
        }
        return subjectPublicKey;
    }

    public CertBuilder setSubjectPublicKey(PublicKey subjectPublicKey) {
        this.subjectPublicKey = subjectPublicKey;
        return this;
    }

    public X509Name getIssuer() {
        if (issuer == null) {
            issuer = getSubject();
        }
        return issuer;
    }

    public CertBuilder setIssuer(X509Name issuer) {
        this.issuer = issuer;
        return this;
    }
    
    public CertBuilder setIssuer(String issuer) {
        this.issuer = new X509Name(issuer);
        return this;
    }

    public X509Name getSubject() {
        if (subject == null) {
            subject = new X509Name("CN=Anyone");
        }
        return subject;
    }

    public CertBuilder setSubject(X509Name subject) {
        this.subject = subject;
        return this;
    }
    
    public CertBuilder setSubject(String subject) {
        this.subject = new X509Name(subject);
        return this;
    }

    public String getSignatureAlgorithm() {
        if (signatureAlgorithm == null) {
            signatureAlgorithm = "SHA1withRSA";
        }
        return signatureAlgorithm;
    }

    public CertBuilder setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }
    
    /**
     * Builds a certificate based on the specified values and default values 
     * for everything not specified but required.
     * @return a new certificate
     * @throws CertBuilderException in case anything failed
     */
    public X509Certificate build() throws CertBuilderException, CertificateEncodingException, IllegalStateException, SignatureException, InvalidKeyException {
        try {
            if (isVersion3()) {
                X509V3CertificateGenerator builder = new X509V3CertificateGenerator();
                builder.setIssuerDN(getIssuer());
                builder.setSerialNumber(getSerialNumber());
                builder.setNotAfter(getNotAfter());
                builder.setNotBefore(getNotBefore());
                builder.setSubjectDN(getSubject());
                builder.setPublicKey(getSubjectPublicKey());
                builder.setSignatureAlgorithm(getSignatureAlgorithm());
                
                for (CertExt ext : extensions) {
                    builder.addExtension(ext.getOid(), ext.isIsCritical(), ext.getValue());
                }
                if (getIssuerUniqueId() != null) {
                    builder.setIssuerUniqueID(getIssuerUniqueId());
                }
                if (getSubjectUniqueId() != null) {
                    builder.setSubjectUniqueID(getSubjectUniqueId());
                }
                
                return builder.generate(getIssuerPrivateKey(), "BC");
            } else {
                X509V1CertificateGenerator builder = new X509V1CertificateGenerator();
                builder.setIssuerDN(getIssuer());
                builder.setSerialNumber(getSerialNumber());
                builder.setNotAfter(getNotAfter());
                builder.setNotBefore(getNotBefore());
                builder.setSubjectDN(getSubject());
                builder.setPublicKey(getSubjectPublicKey());

                return builder.generate(getIssuerPrivateKey(), getSignatureAlgorithm());
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CertBuilderException(ex);
        } catch (NoSuchProviderException ex) {
            throw new CertBuilderException(ex);
        }
    }
    
    /**
     * Generates a number of serial number bytes. The number returned should
     * be a positive number.
     *
     * @return a BigInteger with a new random serial number.
     */
    public BigInteger generateSerialNumber() {
        final byte[] sernobytes = new byte[8];
        boolean ok = false;
        BigInteger serno = null;
        while (!ok) {
            random.nextBytes(sernobytes);
            serno = new BigInteger(sernobytes).abs();

            // Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
            if ((serno.compareTo(LOWEST) >= 0)
                    && (serno.compareTo(HIGHEST) <= 0)) {
                ok = true;
            }
        }
        return serno;
    }

    public CertBuilder setSelfSignKeyPair(KeyPair keyPair) {
        this.issuerPrivateKey = keyPair.getPrivate();
        this.subjectPublicKey = keyPair.getPublic();
        return this;
    }
    
    public CertBuilder addExtension(CertExt extension) {
        this.extensions.add(extension);
        return this;
    }

    @Override
    public CertBuilder clone() {
        try {
            return (CertBuilder) super.clone();
        } catch (CloneNotSupportedException ex) {
            throw new RuntimeException(ex);
        }
    }

    public CertBuilder setVersion3(boolean b) {
        this.version3 = b;
        return this;
    }

    public boolean isVersion3() {
        return version3;
    }

    public CertBuilder setIssuerUniqueId(boolean[] id) {
        this.issuerUniqueId = id;
        return this;
    }
    
    public CertBuilder setSubjectUniqueId(boolean[] id) {
        this.subjectUniqueId = id;
        return this;
    }

    public boolean[] getIssuerUniqueId() {
        return issuerUniqueId;
    }

    public boolean[] getSubjectUniqueId() {
        return subjectUniqueId;
    }
    
}
