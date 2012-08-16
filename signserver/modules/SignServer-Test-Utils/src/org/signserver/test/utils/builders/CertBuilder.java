/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.Date;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds a certificate based on the specified information and using default 
 * values for everything else.
 *
 *
 * @version $Id: CertBuilder.java 15189 2012-08-03 10:05:26Z netmackan $
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
    private X500Name subject;
    private X500Name issuer;
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

    public X500Name getIssuer() {
        if (issuer == null) {
            issuer = getSubject();
        }
        return issuer;
    }

    public CertBuilder setIssuer(X500Name issuer) {
        this.issuer = issuer;
        return this;
    }
    
    public CertBuilder setIssuer(String issuer) {
        this.issuer = new X500Name(issuer);
        return this;
    }

    public X500Name getSubject() {
        if (subject == null) {
            subject = new X500Name("CN=Anyone");
        }
        return subject;
    }

    public CertBuilder setSubject(X500Name subject) {
        this.subject = subject;
        return this;
    }
    
    public CertBuilder setSubject(String subject) {
        this.subject = new X500Name(subject);
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
    public X509CertificateHolder build() throws CertBuilderException {
        try {
            if (isVersion3()) {
                JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(getIssuer(), getSerialNumber(), getNotBefore(), getNotAfter(), getSubject(), getSubjectPublicKey());
                
                for (CertExt ext : extensions) {
                    builder.addExtension(ext.getOid(), ext.isIsCritical(), ext.getValue());
                }
                if (getIssuerUniqueId() != null) {
                    builder.setIssuerUniqueID(getIssuerUniqueId());
                }
                if (getSubjectUniqueId() != null) {
                    builder.setSubjectUniqueID(getSubjectUniqueId());
                }
                
                ContentSigner contentSigner = new JcaContentSignerBuilder(getSignatureAlgorithm()).setProvider("BC").build(getIssuerPrivateKey());
                return builder.build(contentSigner);
            } else {
                JcaX509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(getIssuer(), getSerialNumber(), getNotBefore(), getNotAfter(), getSubject(), getSubjectPublicKey());
                ContentSigner contentSigner = new JcaContentSignerBuilder(getSignatureAlgorithm()).setProvider("BC").build(getIssuerPrivateKey());
                return builder.build(contentSigner);
            }
        } catch (OperatorCreationException ex) {
            throw new CertBuilderException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new CertBuilderException(ex);
        } catch (NoSuchProviderException ex) {
            throw new CertBuilderException(ex);
        } catch (CertIOException ex) {
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
