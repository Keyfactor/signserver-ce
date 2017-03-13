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
package org.signserver.module.masterlist.signer;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertificateHolderSelector;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.cesecore.util.CertTools;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the MasterListSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MasterListSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MasterListSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenRSANoSKID;
    private static MockedCryptoToken tokenRSANoCerts;
    private static Certificate[] certChain;
    private static Certificate signerCertificate;
    private static Certificate[] certChainNoSKID;
    private static Certificate signerCertificateNoSKID;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final String signatureAlgorithm = "SHA256withRSAandMGF1";

        final KeyPair caKeyPair = CryptoUtils.generateRSA(1024);
        final String caDN = "CN=CSCA Test Country";

        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final String signerDN = "CN=MLS Test Country 1";

        long currentTime = System.currentTimeMillis();

        certChain =
                new Certificate[] {
                    // Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPair.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject(signerDN)
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPair.getPublic())))
                        .build()),

                    // CA
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setSelfSignKeyPair(signerKeyPair)
                        .setNotBefore(new Date(currentTime - 120000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject(caDN)
                        .build())};
        signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
        tokenRSANoCerts = new MockedCryptoToken(signerKeyPair.getPrivate(),
                                                signerKeyPair.getPublic(), null,
                                                null, "BC");
        
        certChainNoSKID =
                new Certificate[] {
                    // Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPair.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject(signerDN)
                        .build()),

                    // CA
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setSelfSignKeyPair(signerKeyPair)
                        .setNotBefore(new Date(currentTime - 120000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject(caDN)
                        .build())};
        signerCertificateNoSKID = certChainNoSKID[0];
        tokenRSANoSKID = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificateNoSKID, Arrays.asList(certChainNoSKID), "BC");
    }

    /**
     * Tests that setting INCLUDE_CERTIFICATE_LEVELS gives a fatal error.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetFatalErrorsIncludeCertificateLevels() throws Exception {
        LOG.info("testNoProcessOnFatalErrors");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("INCLUDE_CERTIFICATE_LEVELS", "1"); // Not supported
        MasterListSigner instance = new MockedMasterListSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("fatalErrors: " + instance.getFatalErrors(null).toString(), instance.getFatalErrors(null).toString().contains("INCLUDE_CERTIFICATE_LEVELS"));
    }

    /**
     * Test signing with RSA keys and the certificate chain stored in the
     * (mocked) token.
     * 
     * @throws Exception 
     */
    @Test
    public void testNormalSigning() throws Exception {
        LOG.info("testNormalSigning");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
        MasterListSigner instance = new MockedMasterListSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final List<Certificate> inputCertificates = createCertificates(2, true);

        final byte[] data = CertTools.getPemFromCertificateChain(inputCertificates);

        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        SignatureResponse res;
        byte[] cms;
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            res = (SignatureResponse) instance.processData(request, requestContext);

            cms = responseData.toReadableData().getAsByteArray();
        }
        CMSSignedData signedData = new CMSSignedData(cms);

        assertEquals("eContentType id-icao-cscaMasterList", ICAOObjectIdentifiers.id_icao_cscaMasterList.toString(), signedData.getSignedContentTypeOID());

        assertEquals("crl field MUST NOT be populated", 0, signedData.getCRLs().getMatches(new Selector() {

            @Override
            public boolean match(Object o) {
                return true;
            }

            @Override
            public Object clone() {
                return this;
            }
        }).size());

        assertEquals("It is RECOMMENDED that States only provide 1 signerinfo within this field.", 1, signedData.getSignerInfos().size());
        SignerInformation signerInfo = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
        assertNotNull("subjectKeyIdentifier: It is RECOMMENDED that States support this field over issuerndSerialNumber", signerInfo.getSID().getSubjectKeyIdentifier());
        assertEquals("RFC3852: If the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.", 3, signerInfo.getVersion());

        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] content = (byte[]) signedContent.getContent();

        CscaMasterList ml = CscaMasterList.getInstance(new ASN1InputStream(content).readObject());
        if (LOG.isDebugEnabled()) {
            LOG.debug("ASN.1:\n" + ASN1Dump.dumpAsString(ml));
        }

        assertEquals("Number of certs in response", 2, ml.getCertStructs().length);

        // Check that we got back the same certificates
        // Notice that they are stored as a set, so might be in any order
        final Set<Certificate> actual = new HashSet<>();
        for (org.bouncycastle.asn1.x509.Certificate bcCert : ml.getCertStructs()) {
            actual.add(CertTools.getCertfromByteArray(bcCert.getEncoded()));
        }
        assertEquals("certs", new HashSet<>(inputCertificates), actual);

        assertEquals("CscaMasterListVersion", 0, ml.getVersion());

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        final X509Certificate configuredSignerCert = (X509Certificate) tokenRSA.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
        assertNotNull("Signer certificate", signercert);
        assertEquals("same cert returned", signercert, configuredSignerCert);

        // Verify using the signer's certificate (the configured one)
        assertTrue("Verification using signer certificate",
                signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(configuredSignerCert)));

        // Check that the signer's certificate is included
        Store certs = signedData.getCertificates();
        Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
        assertEquals("should match the configured certificate: " + matches, 1, matches.size());

        // Check that the CSCA certificate is included
        final X509Certificate configuredCACert = (X509Certificate) tokenRSA.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN).get(1);
        matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredCACert));
        assertEquals("should match the configured certificate: " + matches, 1, matches.size());

        // Testing that the SID works
        Collection certCollection = certs.getMatches(signerInfo.getSID());
        assertTrue("Matched signer cert", signerInfo.getSID().match(new X509CertificateHolder(configuredSignerCert.getEncoded())));
        X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
        assertArrayEquals("same cert returned", certHolder.getEncoded(), configuredSignerCert.getEncoded());

        // Check the signature algorithm
        assertEquals("Digest algorithm", CMSAlgorithm.SHA256.toString(), signerInfo.getDigestAlgorithmID().getAlgorithm().toString());
        assertEquals("Encryption algorithm", PKCSObjectIdentifiers.id_RSASSA_PSS.toString(), signerInfo.getEncryptionAlgOID());

        Attribute signingTime = signerInfo.getSignedAttributes().get(CMSAttributes.signingTime);
        assertNotNull("signedAttrs MUST include signing time (ref. PKCS#9)", signingTime);

        // All CSCA Master Lists MUST be produced in DER format
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertArrayEquals("expects DER format", der, cms);
    }

    @Test
    public void testSigningErrorNoSKID() throws Exception {
        LOG.info("testGetFatalErrorsNoSKID");
        WorkerConfig config = new WorkerConfig();
        MasterListSigner instance = new MockedMasterListSigner(tokenRSANoSKID);
        instance.init(1, config, new SignServerContext(), null);
        
        final List<Certificate> inputCertificates = createCertificates(2, true);

        final byte[] data = CertTools.getPemFromCertificateChain(inputCertificates);

        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        SignatureResponse res;
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            res = (SignatureResponse) instance.processData(request, requestContext);
            fail("Should throw SignServerException");
        } catch (SignServerException e) {
            assertEquals("Error message",
                         "Subject Key Identifier is mandatory in Master List Signer Certificate",
                         e.getMessage());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test signing with RSA keys and the certificate chain stored in the
     * configuration of the worker.
     * 
     * @throws Exception 
     */
    @Test
    public void testNormalSigningNoCertInToken() throws Exception {
        LOG.info("testNormalSigning");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
        config.setProperty("SIGNERCERTCHAIN",
                new String(CertTools.getPemFromCertificateChain(Arrays.asList(certChain))));
        config.setProperty("SIGNERCERT",
                new String(CertTools.getPemFromCertificateChain(Arrays.asList(signerCertificate))));
                
        MasterListSigner instance = new MockedMasterListSigner(tokenRSANoCerts);
        instance.init(1, config, new SignServerContext(), null);

        final List<Certificate> inputCertificates = createCertificates(2, true);

        final byte[] data = CertTools.getPemFromCertificateChain(inputCertificates);

        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        SignatureResponse res;
        byte[] cms;
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            res = (SignatureResponse) instance.processData(request, requestContext);

            cms = responseData.toReadableData().getAsByteArray();
        }
        CMSSignedData signedData = new CMSSignedData(cms);

        assertEquals("eContentType id-icao-cscaMasterList", ICAOObjectIdentifiers.id_icao_cscaMasterList.toString(), signedData.getSignedContentTypeOID());

        assertEquals("crl field MUST NOT be populated", 0, signedData.getCRLs().getMatches(new Selector() {

            @Override
            public boolean match(Object o) {
                return true;
            }

            @Override
            public Object clone() {
                return this;
            }
        }).size());

        assertEquals("It is RECOMMENDED that States only provide 1 signerinfo within this field.", 1, signedData.getSignerInfos().size());
        SignerInformation signerInfo = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
        assertNotNull("subjectKeyIdentifier: It is RECOMMENDED that States support this field over issuerndSerialNumber", signerInfo.getSID().getSubjectKeyIdentifier());
        assertEquals("RFC3852: If the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.", 3, signerInfo.getVersion());

        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] content = (byte[]) signedContent.getContent();

        CscaMasterList ml = CscaMasterList.getInstance(new ASN1InputStream(content).readObject());
        if (LOG.isDebugEnabled()) {
            LOG.debug("ASN.1:\n" + ASN1Dump.dumpAsString(ml));
        }

        assertEquals("Number of certs in response", 2, ml.getCertStructs().length);

        // Check that we got back the same certificates
        // Notice that they are stored as a set, so might be in any order
        final Set<Certificate> actual = new HashSet<>();
        for (org.bouncycastle.asn1.x509.Certificate bcCert : ml.getCertStructs()) {
            actual.add(CertTools.getCertfromByteArray(bcCert.getEncoded()));
        }
        assertEquals("certs", new HashSet<>(inputCertificates), actual);

        assertEquals("CscaMasterListVersion", 0, ml.getVersion());

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        final X509Certificate configuredSignerCert = (X509Certificate) tokenRSA.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
        assertNotNull("Signer certificate", signercert);
        assertEquals("same cert returned", signercert, configuredSignerCert);

        // Verify using the signer's certificate (the configured one)
        assertTrue("Verification using signer certificate",
                signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(configuredSignerCert)));

        // Check that the signer's certificate is included
        Store certs = signedData.getCertificates();
        Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
        assertEquals("should match the configured certificate: " + matches, 1, matches.size());

        // Check that the CSCA certificate is included
        final X509Certificate configuredCACert = (X509Certificate) tokenRSA.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN).get(1);
        matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredCACert));
        assertEquals("should match the configured certificate: " + matches, 1, matches.size());

        // Testing that the SID works
        Collection certCollection = certs.getMatches(signerInfo.getSID());
        assertTrue("Matched signer cert", signerInfo.getSID().match(new X509CertificateHolder(configuredSignerCert.getEncoded())));
        X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
        assertArrayEquals("same cert returned", certHolder.getEncoded(), configuredSignerCert.getEncoded());

        // Check the signature algorithm
        assertEquals("Digest algorithm", CMSAlgorithm.SHA256.toString(), signerInfo.getDigestAlgorithmID().getAlgorithm().toString());
        assertEquals("Encryption algorithm", PKCSObjectIdentifiers.id_RSASSA_PSS.toString(), signerInfo.getEncryptionAlgOID());

        Attribute signingTime = signerInfo.getSignedAttributes().get(CMSAttributes.signingTime);
        assertNotNull("signedAttrs MUST include signing time (ref. PKCS#9)", signingTime);

        // All CSCA Master Lists MUST be produced in DER format
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertArrayEquals("expects DER format", der, cms);
    }

    /**
     * Creates a number of certificates, optionally all with different keys.
     * @param number of certificates to generate
     * @param differentKeys if each certificate should be signed/contain a different key
     * @return list of certificates
     * @throws CertificateException
     * @throws CertBuilderException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private List<Certificate> createCertificates(int number, boolean differentKeys) throws CertificateException, CertBuilderException, NoSuchAlgorithmException, NoSuchProviderException {
        final List<Certificate> result = new LinkedList<>();
        final String signatureAlgorithm = "SHA256withRSAandMGF1";

        KeyPair signerKeyPair = null;

        for (int i = 0; i < number; i++) {
            // Generate key
            if (signerKeyPair == null || differentKeys) {
                signerKeyPair = CryptoUtils.generateRSA(1024);
            }
            final String dn = "CN=CSCA " + i;
            result.add(new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(new CertBuilder()
                            .setSelfSignKeyPair(signerKeyPair)
                            .setNotBefore(new Date())
                            .setSignatureAlgorithm(signatureAlgorithm)
                            .setIssuer(dn).setSubject(dn)
                            .build()));
        }

        return result;
    }
}
