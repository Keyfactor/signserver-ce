/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.jarchive.signer;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.Assert;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the JArchiveCMSSigner class.
 *
 * For system tests see JArchiveSignerTest and the JArchiveJarsignerComplianceTest.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JArchiveCMSSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveCMSSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final String signatureAlgorithm = "SHA256withRSA";

        // Create CA
        final KeyPair caKeyPair = CryptoUtils.generateRSA(1024);
        final String caDN = "CN=Test CA";
        long currentTime = System.currentTimeMillis();
        final X509Certificate caCertificate
                = new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setSelfSignKeyPair(caKeyPair)
                        .setNotBefore(new Date(currentTime - 120000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject(caDN)
                        .build());

        // Create signer key-pair (RSA) and issue certificate
        final KeyPair signerKeyPairRSA = CryptoUtils.generateRSA(1024);
        final Certificate[] certChainRSA =
                new Certificate[] {
                    // Code Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPairRSA.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject("CN=Code Signer RSA 1")
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairRSA.getPublic())))
                        .addExtension(new CertExt(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenRSA = new MockedCryptoToken(signerKeyPairRSA.getPrivate(), signerKeyPairRSA.getPublic(), certChainRSA[0], Arrays.asList(certChainRSA), "BC");
    }

    /**
     * Tests that with DIRECTSIGNATURE=true, no signed attributes are included.
     * @throws Exception
     */
    @Test
    public void testDirectSignatureTrue() throws Exception {
        LOG.info("testDirectSignatureTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", "true");
        CMSSigner instance = new MockedJArchiveCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        assertNull("no signed attributes", signedAttributes);
    }

    /**
     * Tests that with DIRECTSIGNATURE=false, there are some signed attributes included.
     * @throws Exception 
     */
    @Test
    public void testDirectSignatureFalse() throws Exception {
        LOG.info("testDirectSignatureFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", "false");
        CMSSigner instance = new MockedJArchiveCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        Assert.assertTrue("signed attributes expected", signedAttributes.size() > 0);
    }
    
    /**
     * Tests that with an empty (or with blank space actually) value for DIRECTSIGNATURE the default is true
     * and thus no signed attributes are included for the JArchiveCMSSigner.
     * @throws Exception 
     */
    @Test
    public void testDirectSignatureEmptySlashDefault() throws Exception {
        LOG.info("testDirectSignatureFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", " ");
        MockedJArchiveCMSSigner instance = new MockedJArchiveCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        assertNull("no signed attributes", signedAttributes);
    }
    
    private SimplifiedResponse signAndVerify(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean detached) throws Exception {
        return signAndVerify(data, data, token, config, requestContext, detached);
    }

    /**
     * Helper method signing the given data (either the actual data to be signed
     * or if the signer or request implies client-side hashing, the pre-computed
     * hash) and the original data. When detached mode is assumed, the originalData
     * is used to verify the signature.
     * 
     * @param data Data (data to be signed, or pre-computed hash)
     * @param originalData Original data (either the actual data or the data that was pre-hashed)
     * @param token
     * @param config
     * @param requestContext
     * @param detached If true, assume detached
     * @return
     * @throws Exception 
     */
    private SimplifiedResponse signAndVerify(final byte[] data, final byte[] originalData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean detached) throws Exception {
        final JArchiveCMSSigner instance = new MockedJArchiveCMSSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) instance.processData(request, requestContext);

            byte[] signedBytes = responseData.toReadableData().getAsByteArray();
            Certificate signerCertificate = response.getSignerCertificate();
            
            final CMSSignedData signedData;
            if (detached) {
                signedData = new CMSSignedData(new CMSProcessableByteArray(originalData), signedBytes);
            } else {
                signedData = new CMSSignedData(signedBytes);
            }
            int verified = 0;
            
            Store                   certStore = signedData.getCertificates();
            SignerInformationStore  signers = signedData.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext()) {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certStore.getMatches(signer.getSID());

                Iterator              certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
                {
                    verified++;
                }   
            }
            
            assertNotEquals("verified", verified > 0);
            
            return new SimplifiedResponse(signedBytes, signerCertificate);
        }
    }
}
