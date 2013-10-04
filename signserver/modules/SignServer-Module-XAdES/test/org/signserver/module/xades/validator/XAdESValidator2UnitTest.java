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
package org.signserver.module.xades.validator;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.util.CertTools;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.module.xades.signer.MockedCryptoToken;
import org.signserver.module.xades.signer.MockedTimeStampTokenProvider;
import org.signserver.module.xades.signer.MockedXAdESSigner;
import org.signserver.module.xades.signer.XAdESSigner;
import org.signserver.module.xades.signer.XAdESSignerUnitTest;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.builders.crl.CRLBuilder;
import org.signserver.validationservice.common.Validation;

/**
 * Additional unit tests for the XAdESValidator class.
 * 
 * This class set ups new certificate chains and signs and verifies a document
 * using it.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XAdESValidator2UnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerUnitTest.class);
    
    private static X509CertificateHolder rootcaCert;
    private static X509CertificateHolder subcaCert;
    private static X509CRLHolder rootcaCRLEmpty;
    private static X509CRLHolder subcaCRLEmpty;
    private static X509CRLHolder rootcaCRLSubCAAndSigner1Revoked;
    private static X509CRLHolder subcaCRLSigner2Revoked;
    private static X509CRLHolder otherCRL;
    private static File rootcaCRLFile;
    private static File subcaCRLFile;
    
    // Signer 1: Root CA, Signer
    private static MockedCryptoToken token1;
    private static String signedXml1;
    
    // Signer 2: Root CA, Sub CA, Signer
    private static MockedCryptoToken token2;
    private static String signedXml2;

    // Signer 3: Root CA, Signer including OCSP URI
    private static MockedCryptoToken token3;
    private static String signedXml3;

    private static String signedXmlFormT;
    
    
    /**
     * Setting up key-pairs, mocked crypto tokens, certificates and CRLs used
     * by the tests.
     */
    @BeforeClass
    public static void setUpClass() throws Exception {       
        Security.addProvider(new BouncyCastleProvider());
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
        
        // Root CA, sub CA
        rootcaCRLFile = File.createTempFile("xadestest-", "-rootca.crl");
        LOG.debug("rootcaCRLFile: " + rootcaCRLFile);
        subcaCRLFile = File.createTempFile("xadestest-", "-subca.crl");
        LOG.debug("subcaCRLFile: " + subcaCRLFile);
        final KeyPair rootcaKeyPair = CryptoUtils.generateRSA(1024);
        rootcaCert = new CertBuilder()
                .setSelfSignKeyPair(rootcaKeyPair)
                .setSubject("CN=Root, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();
        final KeyPair subcaKeyPair = CryptoUtils.generateRSA(1024);
        subcaCert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(subcaKeyPair.getPublic())
                .addCDPURI(rootcaCRLFile.toURI().toURL().toExternalForm())
                .setSubject("CN=Sub, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();
        
        // Signer 1 is issued directly by the root CA
        final KeyPair signer1KeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder signer1Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(signer1KeyPair.getPublic())
                .setSubject("CN=Signer 1, O=XAdES Test, C=SE")
                .addCDPURI(rootcaCRLFile.toURI().toURL().toExternalForm())
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain1 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer1Cert),
                    conv.getCertificate(rootcaCert)
                );
        token1 = new MockedCryptoToken(
                signer1KeyPair.getPrivate(),
                signer1KeyPair.getPublic(), 
                conv.getCertificate(signer1Cert), 
                chain1, 
                "BC");
        LOG.debug("Chain 1: \n" + new String(CertTools.getPEMFromCerts(chain1)) + "\n");
        
        // Sign a document by signer 1
        XAdESSigner instance = new MockedXAdESSigner(token1);
        WorkerConfig config = new WorkerConfig();
        instance.init(4712, config, null, null);
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-201-1");
        GenericSignRequest request = new GenericSignRequest(201, "<test201/>".getBytes("UTF-8"));
        GenericSignResponse response = (GenericSignResponse) instance.processData(request, requestContext);
        byte[] data = response.getProcessedData();
        signedXml1 = new String(data);
        LOG.debug("Signed document by signer 1:\n\n" + signedXml1 + "\n");
        
        
        // Signer 2 is issued by the sub CA
        final KeyPair signer2KeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder signer2Cert = new CertBuilder()
                .setIssuerPrivateKey(subcaKeyPair.getPrivate())
                .setIssuer(subcaCert.getSubject())
                .setSubjectPublicKey(signer2KeyPair.getPublic())
                .setSubject("CN=Signer 2, O=XAdES Test, C=SE")
                .addCDPURI(subcaCRLFile.toURI().toURL().toExternalForm())
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain2 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer2Cert),
                    conv.getCertificate(subcaCert),
                    conv.getCertificate(rootcaCert)
                );
        token2 = new MockedCryptoToken(
                signer2KeyPair.getPrivate(),
                signer2KeyPair.getPublic(), 
                conv.getCertificate(signer2Cert), 
                chain2, 
                "BC");
        LOG.debug("Chain 2: \n" + new String(CertTools.getPEMFromCerts(chain2)) + "\n");
        
        // Sign a document by signer 2
        instance = new MockedXAdESSigner(token2);
        config = new WorkerConfig();
        instance.init(4713, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-202-1");
        request = new GenericSignRequest(202, "<test202/>".getBytes("UTF-8"));
        response = (GenericSignResponse) instance.processData(request, requestContext);
        data = response.getProcessedData();
        signedXml2 = new String(data);
        LOG.debug("Signed document by signer 2:\n\n" + signedXml2 + "\n");
        
        // CRL with all active (empty CRL)
        rootcaCRLEmpty = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .build();
        subcaCRLEmpty = new CRLBuilder()
                .setIssuerPrivateKey(subcaKeyPair.getPrivate())
                .setIssuer(subcaCert.getSubject())
                .build();
        rootcaCRLSubCAAndSigner1Revoked = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .addCRLEntry(subcaCert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .addCRLEntry(signer1Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .build();
        subcaCRLSigner2Revoked = new CRLBuilder()
                .setIssuerPrivateKey(subcaKeyPair.getPrivate())
                .setIssuer(subcaCert.getSubject())
                .addCRLEntry(signer2Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .build();
        otherCRL = new CRLBuilder()
                .setIssuer(subcaCert.getSubject()) // Setting Sub CA DN all though an other key will be used
                .build();
        
        // signer 3, issued by the root CA with an OCSP authority information access in the cert
        final KeyPair signer3KeyPair = CryptoUtils.generateRSA(1024);
        final GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, "http://dummyocsp");
        final X509CertificateHolder signer3Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(signer3KeyPair.getPublic())
                .setSubject("CN=Signer 1, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, gn)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain3 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer3Cert),
                    conv.getCertificate(rootcaCert)
                );
        token3 = new MockedCryptoToken(
                signer3KeyPair.getPrivate(),
                signer3KeyPair.getPublic(), 
                conv.getCertificate(signer3Cert), 
                chain3, 
                "BC");
        LOG.debug("Chain 3: \n" + new String(CertTools.getPEMFromCerts(chain3)) + "\n");
        
        // Sign a document by signer 2
        instance = new MockedXAdESSigner(token3);
        config = new WorkerConfig();
        instance.init(4714, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-203-1");
        request = new GenericSignRequest(202, "<test203/>".getBytes("UTF-8"));
        response = (GenericSignResponse) instance.processData(request, requestContext);
        data = response.getProcessedData();
        signedXml3 = new String(data);
        LOG.debug("Signed document by signer 3:\n\n" + signedXml3 + "\n");
        
        // Sign a document by signer 1, using form T
        instance = new MockedXAdESSigner(token1);
        config = new WorkerConfig();
        config.setProperty("XADESFORM", "T");
        config.setProperty("TSA_URL", "http://example.com/?test=5");
        instance.init(4715, config, null, null);
        instance.setTimeStampTokenProviderImplementation(MockedTimeStampTokenProvider.class);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-204-1");
        request = new GenericSignRequest(204, "<test204/>".getBytes("UTF-8"));
        response = (GenericSignResponse) instance.processData(request, requestContext);
        data = response.getProcessedData();
        signedXmlFormT = new String(data);
        LOG.debug("Signed document by signer 1, form T:\n\n" + signedXmlFormT + "\n");
        
    }
    
    /**
     * Test validation of document signed by signer1 without revocation checking.
     */
    @Test
    public void testSigner1_noRevocationChecking() throws Exception {
        LOG.info("signer1");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-300-0");
        GenericValidationRequest request = new GenericValidationRequest(300, signedXml1.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getSignerCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer1 with CRL where no
     * cert is revoked.
     */
    @Test
    public void testSigner1_crlNoRevoked() throws Exception {
        LOG.info("signer1");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        updateCRLs(rootcaCRLEmpty, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-301-1");
        GenericValidationRequest request = new GenericValidationRequest(301, signedXml1.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getSignerCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer1 with CRL where the signer
     * certificate is revoked.
     */
    @Test
    public void testSigner1_crlSignerRevoked() throws Exception {
        LOG.info("testSigner1_crlSignerRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        updateCRLs(rootcaCRLSubCAAndSigner1Revoked, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-302-1");
        GenericValidationRequest request = new GenericValidationRequest(302, signedXml1.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 without revocation checking.
     */
    @Test
    public void testSigner2_noRevocationChecking() throws Exception {
        LOG.info("signer2");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subcaCert)))));
        
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-303-1");
        GenericValidationRequest request = new GenericValidationRequest(303, signedXml2.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getSignerCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where no
     * cert is revoked.
     */
    @Test
    public void testSigner2_crlNoRevoked() throws Exception {
        LOG.info("testSigner2_crlNoRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subcaCert)))));
        
        updateCRLs(rootcaCRLEmpty, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-304-1");
        GenericValidationRequest request = new GenericValidationRequest(304, signedXml2.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getSignerCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where the signer
     * certificate is revoked.
     */
    @Test
    public void testSigner2_crlSignerRevoked() throws Exception {
        LOG.info("testSigner2_crlSignerRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subcaCert)))));
        
        updateCRLs(rootcaCRLEmpty, subcaCRLSigner2Revoked);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-305-1");
        GenericValidationRequest request = new GenericValidationRequest(305, signedXml2.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where the sub CA
     * certificate is revoked.
     */
    @Test
    public void testSigner2_crlCARevoked() throws Exception {
        LOG.info("testSigner2_crlCARevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subcaCert)))));
        
        updateCRLs(rootcaCRLSubCAAndSigner1Revoked, subcaCRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-305-1");
        GenericValidationRequest request = new GenericValidationRequest(305, signedXml2.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 where the sub CA CRL is
     * signed by an other CA and thus not trusted.
     */
    @Test
    public void testSigner2_badCRL() throws Exception {
        LOG.info("testSigner2_badCRL");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subcaCert)))));
        
        updateCRLs(rootcaCRLEmpty, otherCRL);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-306-1");
        GenericValidationRequest request = new GenericValidationRequest(306, signedXml2.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    @Test
    public void testSigner3_withOCSP() throws Exception {
        LOG.info("testSigner2_badCRL");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPEMFromCerts(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        GenericValidationRequest request = new GenericValidationRequest(307, signedXml3.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        // TODO: verify OCSP etc..
        //assertFalse("valid document", response.isValid());
        //assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
    /**
     * Updating the CRL files with the values specified.
     * @param rootcaCRL value for the the Root CA CRL
     * @param subcaCRL value for the Sub CA CRL
     * @throws Exception in case of IO errors
     */
    private void updateCRLs(final X509CRLHolder rootcaCRL, final X509CRLHolder subcaCRL) throws IOException {
        FileUtils.writeByteArrayToFile(rootcaCRLFile, rootcaCRL.getEncoded());
        FileUtils.writeByteArrayToFile(subcaCRLFile, subcaCRL.getEncoded());
    }

}