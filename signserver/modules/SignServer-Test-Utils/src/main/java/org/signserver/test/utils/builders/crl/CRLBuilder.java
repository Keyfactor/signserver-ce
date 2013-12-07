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
package org.signserver.test.utils.builders.crl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * Builds a CRL based on the specified information and using default 
 * values for everything else.
 *
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CRLBuilder {
    
    private Date thisUpdate;
    private Date nextUpdate;
    private PrivateKey issuerPrivateKey;

    private X500Name issuer;
    private String signatureAlgorithm;
    
    private Set<CertExt> extensions = new HashSet<CertExt>();
//    private boolean[] issuerUniqueId;
    
    private LinkedList<CRLEntry> entries = new LinkedList<CRLEntry>();

    public Date getNextUpdate() {
        if (nextUpdate == null) {
            nextUpdate = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(7));
        }
        return nextUpdate;
    }

    public CRLBuilder setNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
        return this;
    }

    public Date getThisUpdate() {
        if (thisUpdate == null) {
            thisUpdate = new Date();
        }
        return thisUpdate;
    }

    public CRLBuilder setThisUpdate(Date notBefore) {
        this.thisUpdate = notBefore;
        return this;
    }

    public PrivateKey getIssuerPrivateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (issuerPrivateKey == null) {
            KeyPair kp = CryptoUtils.generateRSA(1024);
            issuerPrivateKey = kp.getPrivate();
        }
        return issuerPrivateKey;
    }

    public CRLBuilder setIssuerPrivateKey(PrivateKey issuerPrivateKey) {
        this.issuerPrivateKey = issuerPrivateKey;
        return this;
    }

    public X500Name getIssuer() {
        return issuer;
    }

    public CRLBuilder setIssuer(X500Name issuer) {
        this.issuer = issuer;
        return this;
    }
    
    public CRLBuilder setIssuer(String issuer) {
        this.issuer = new X500Name(issuer);
        return this;
    }

    public String getSignatureAlgorithm() {
        if (signatureAlgorithm == null) {
            signatureAlgorithm = "SHA1withRSA";
        }
        return signatureAlgorithm;
    }

    public CRLBuilder setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }
    
    public CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date date, int reason) {
        entries.add(new CRLEntry(userCertificateSerial, date, reason));
        return this;
    }

    public CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, int reason, Date invalidityDate) {
        entries.add(new CRLEntry(userCertificateSerial, revocationDate, reason, invalidityDate));
        return this;
    }

    public CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, Extensions extensions) {
        entries.add(new CRLEntry(userCertificateSerial, revocationDate, extensions));
        return this;
    }
    
    /**
     * Builds a CRL based on the specified values and default values 
     * for everything not specified but required.
     * @return a new CRL
     * @throws CertBuilderException in case anything failed
     */
    public X509CRLHolder build() throws CertBuilderException {
        try {
            X509v2CRLBuilder builder = new X509v2CRLBuilder(getIssuer(), getThisUpdate());
            builder.setNextUpdate(getNextUpdate());
            
            for (CertExt ext : extensions) {
                builder.addExtension(ext.getOid(), ext.isIsCritical(), ext.getValue());
            }
            for (CRLEntry entry : entries) {
                if (entry.getExtensions() != null) {
                    builder.addCRLEntry(entry.getUserCertificateSerial(), entry.getDate(), entry.getExtensions());
                } else if (entry.getInvalidityDate() != null) {
                    builder.addCRLEntry(entry.getUserCertificateSerial(), entry.getDate(), entry.getReason(), entry.getInvalidityDate());
                } else {
                    builder.addCRLEntry(entry.getUserCertificateSerial(), entry.getDate(), entry.getReason());
                }
            }
//            if (getIssuerUniqueId() != null) {
//                builder.setIssuerUniqueID(getIssuerUniqueId());
//            }
            
            ContentSigner contentSigner = new JcaContentSignerBuilder(getSignatureAlgorithm()).setProvider("BC").build(getIssuerPrivateKey());
            return builder.build(contentSigner);
        } catch (OperatorCreationException ex) {
            throw new CertBuilderException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new CertBuilderException(ex);
        } catch (NoSuchProviderException ex) {
            throw new CertBuilderException(ex);
        } catch (CertIOException ex) {
            throw new CertBuilderException(ex);
        } catch (IOException ex) {
            throw new CertBuilderException(ex);
        }
    }

    public CRLBuilder addExtension(CertExt extension) {
        this.extensions.add(extension);
        return this;
    }

    @Override
    public CRLBuilder clone() {
        try {
            return (CRLBuilder) super.clone();
        } catch (CloneNotSupportedException ex) {
            throw new RuntimeException(ex);
        }
    }

//    public CRLBuilder setIssuerUniqueId(boolean[] id) {
//        this.issuerUniqueId = id;
//        return this;
//    }
//
//    public boolean[] getIssuerUniqueId() {
//        return issuerUniqueId;
//    }

}
