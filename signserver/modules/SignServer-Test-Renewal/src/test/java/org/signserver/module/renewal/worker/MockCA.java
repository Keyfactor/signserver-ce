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
package org.signserver.module.renewal.worker;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Mock implementation of a CA.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MockCA {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MockCA.class);
    
    private X509Certificate caCertificate;
    private KeyPair keyPair;
    private String subjectDN;

    public MockCA() {
    }

    private MockCA(final String subjectDN) {
        this.subjectDN = subjectDN;
        try {
            // Generate the RSA Keypair
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA",
                    "BC");
            kpg.initialize(2048);
            LOG.debug("generating...");
            keyPair = kpg.generateKeyPair();

            caCertificate = createCertificate(subjectDN, subjectDN, 10,
                    "SHA1withRSA", keyPair.getPublic(), keyPair.getPrivate());

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static MockCA createMockCA(final String subjectDN) {
        return new MockCA(subjectDN);
    }

    private static X509Certificate createCertificate(String subject,
            String issuer,
            long validity,
            String sigAlg,
            PublicKey pubKey,
            PrivateKey caPrivateKey)
            throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);

        if (LOG.isDebugEnabled()) {
            LOG.debug("keystore signing algorithm " + sigAlg);
        }

        if (pubKey == null) {
            throw new Exception("Public key is null");
        }
        
        final JcaX509v3CertificateBuilder cb =
                new JcaX509v3CertificateBuilder(new X500Name(issuer),
                                             BigInteger.valueOf(firstDate.getTime()),
                                             firstDate, lastDate,
                                             new X500Name(subject), pubKey);

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        return new JcaX509CertificateConverter().getCertificate(cb.build(contentSigner));
    }

    public X509Certificate issueCertificate(String subject,
            long validity,
            String sigAlg,
            PublicKey pubKey) throws Exception {
        return createCertificate(subject, subjectDN, validity, sigAlg, pubKey,
                keyPair.getPrivate());
    }

    public byte[] createPKCS7(final X509Certificate cert,
            final boolean includeChain) {

        final Collection<?> certs = includeChain
                ? Arrays.asList(cert, caCertificate) : Arrays.asList(cert);

        try {
            final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            final ContentSigner contentSigner =
                    new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
            
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                     .build(contentSigner, cert));
            gen.addCertificates(new JcaCertStore(certs));
            
            final CMSTypedData content =
                    new CMSProcessableByteArray("EJBCA".getBytes());
            final CMSSignedData s = gen.generate(content);
            
            return s.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
