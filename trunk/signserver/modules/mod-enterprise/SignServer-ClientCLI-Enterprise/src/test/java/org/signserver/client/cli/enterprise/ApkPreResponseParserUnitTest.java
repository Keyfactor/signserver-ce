/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.ByteArrayDataSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Unit tests for the APK pre-response parser.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkPreResponseParserUnitTest {
    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenRSANew;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair signerKeyPair;
        final String signatureAlgorithm;
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA256withRSA";
        Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        Certificate signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    
        signerKeyPair = CryptoUtils.generateRSA(1024);
        certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        signerCertificate = certChain[0];
        tokenRSANew = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");

    }

    /**
     * Test with no other signers.
     *
     * @throws Exception 
     */
    @Test
    public void testNoOtherSigners() throws Exception {
        final String response =
                createResponse(tokenRSA.getCertificateChain(0), null, false);
        final ApkPreResponseParser parser =
                new ApkPreResponseParser(response.getBytes(StandardCharsets.UTF_8));

        assertEquals("Number of other signers", 0,
                     parser.getNumberOfOtherSigners());
        assertEquals("Number of certs in signer chain", 1,
                     parser.getSignerCertificateChain().size());
        assertEquals("Signer certificate", tokenRSA.getCertificate(0),
                     parser.getSignerCertificateChain().get(0));
        assertNull("No lineage", parser.getLineageFileContent());
    }

    /**
     * Test with no other signers. With an included signing certificate lineage.
     *
     * @throws Exception 
     */
    @Test
    public void testNoOtherSignersWithLineage() throws Exception {
        final String response =
                createResponse(tokenRSA.getCertificateChain(0), null, true);
        final ApkPreResponseParser parser =
                new ApkPreResponseParser(response.getBytes(StandardCharsets.UTF_8));

        assertEquals("Number of other signers", 0,
                     parser.getNumberOfOtherSigners());
        assertEquals("Number of certs in signer chain", 1,
                     parser.getSignerCertificateChain().size());
        assertEquals("Signer certificate", tokenRSA.getCertificate(0),
                     parser.getSignerCertificateChain().get(0));

        final SigningCertificateLineage lineage =
                parser.getLineageFileContent();
        assertEquals("Number of certificates in lineage", 2,
                     lineage.size());
        assertTrue("First cert in lineage",
                   lineage.isCertificateInLineage((X509Certificate) tokenRSA.getCertificate(0)));
        assertTrue("Second cert in lineage",
                   lineage.isCertificateInLineage((X509Certificate) tokenRSANew.getCertificate(0)));
    }
    
    /**
     * Test with one other signer.
     *
     * @throws Exception 
     */
    @Test
    public void testOneOtherSigner() throws Exception {
        final String response =
                createResponse(tokenRSA.getCertificateChain(0),
                               Arrays.asList(tokenRSA.getCertificateChain(0)),
                               false);
        final ApkPreResponseParser parser =
                new ApkPreResponseParser(response.getBytes(StandardCharsets.UTF_8));

        assertEquals("Number of other signers", 1,
                     parser.getNumberOfOtherSigners());
        assertEquals("Number of certs in signer chain", 1,
                     parser.getSignerCertificateChain().size());
        assertEquals("Signer certificate", tokenRSA.getCertificate(0),
                     parser.getSignerCertificateChain().get(0));
        assertEquals("Name of other signer 0", "Signer 0",
                     parser.getNameForOtherSigner(0));
        assertNull("Only one other signer name (index 0)", parser.getNameForOtherSigner(1));
        assertEquals("Signer certificate for other signer 0", tokenRSA.getCertificate(0),
                     parser.getCertificateChainForOtherSigner(0).get(0));
        assertNull("No lineage", parser.getLineageFileContent());
    }

    /**
     * Test with two other signers.
     *
     * @throws Exception 
     */
    @Test
    public void testTwoOtherSigners() throws Exception {
        final String response =
                createResponse(tokenRSA.getCertificateChain(0),
                               Arrays.asList(tokenRSA.getCertificateChain(0),
                                             tokenRSANew.getCertificateChain(0)),
                               false);
        final ApkPreResponseParser parser =
                new ApkPreResponseParser(response.getBytes(StandardCharsets.UTF_8));

        assertEquals("Number of other signers", 2,
                     parser.getNumberOfOtherSigners());
        assertEquals("Number of certs in signer chain", 1,
                     parser.getSignerCertificateChain().size());
        assertEquals("Signer certificate", tokenRSA.getCertificate(0),
                     parser.getSignerCertificateChain().get(0));
        assertEquals("Name of other signer 0", "Signer 0",
                     parser.getNameForOtherSigner(0));
        assertEquals("Name of other signer 1", "Signer 1",
                     parser.getNameForOtherSigner(1));
        assertNull("Only two other signer names (index 0 and 1)",
                   parser.getNameForOtherSigner(2));
        assertEquals("Signer certificate for other signer 0",
                     tokenRSA.getCertificate(0),
                     parser.getCertificateChainForOtherSigner(0).get(0));
        assertEquals("Signer certificate for other signer 1",
                     tokenRSANew.getCertificate(0),
                     parser.getCertificateChainForOtherSigner(1).get(0));
        assertNull("No lineage", parser.getLineageFileContent());
    }

    private String createResponse(final List<Certificate> signerCertChain,
                                  final List<List<Certificate>> otherCertChains,
                                  final boolean includeLineage) 
            throws CertificateEncodingException, CryptoTokenOfflineException,
                   IOException, InvalidKeyException, NoSuchAlgorithmException,
                   SignatureException {
        final StringBuilder sb = new StringBuilder();

        sb.append("SIGNER_CERTIFICATE_CHAIN=");
        sb.append(createBase64CertChain(signerCertChain));
        sb.append("\n");

        if (otherCertChains != null) {
            sb.append("NUMBER_OF_OTHER_SIGNERS=").append(otherCertChains.size());
            sb.append("\n");

            for (int i = 0; i < otherCertChains.size(); i++) {
                sb.append("OTHER_SIGNER_").append(i).append(".NAME=Signer ").append(i);
                sb.append("\n");
                sb.append("OTHER_SIGNER_").append(i).append(".CERTIFICATE_CHAIN=");
                sb.append(createBase64CertChain(otherCertChains.get(i)));
                sb.append("\n");
            }
        }

        if (includeLineage) {
            sb.append("LINEAGE_FILE_CONTENT=");
            sb.append(createBase64Lineage());
        }
        
        return sb.toString();
    }
    
    private String createBase64CertChain(final List<Certificate> chain)
            throws CertificateEncodingException {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < chain.size(); i++) {
            if (i != 0) {
                sb.append(";");
            }
            sb.append(Base64.toBase64String(chain.get(i).getEncoded()));
        }

        return sb.toString();
    }
    
    /**
     * Create a test lineage given the two test tokens, old and new.
     * 
     * @return Base64-encoded lineage
     * @throws Exception 
     */
    private String createBase64Lineage()
            throws CryptoTokenOfflineException, CertificateEncodingException,
                   IOException, InvalidKeyException, NoSuchAlgorithmException,
                   SignatureException {
        SigningCertificateLineage.SignerConfig oldSignerConfig =
                createSignerConfig(tokenRSA.getPrivateKey(0),
                                   (X509Certificate) tokenRSA.getCertificate(0));

        SigningCertificateLineage.SignerConfig newSignerConfig =
                createSignerConfig(tokenRSANew.getPrivateKey(0),
                                   (X509Certificate) tokenRSANew.getCertificate(0));

        final SigningCertificateLineage lineage =
                new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig).build();
        final ByteArrayDataSink sink = new ByteArrayDataSink();
        
        lineage.writeToDataSink(sink);
        final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());

        return Base64.toBase64String(buffer.array());
    }

    private SigningCertificateLineage.SignerConfig createSignerConfig(final PrivateKey privateKey,
                                                                      final X509Certificate cert) {
        return new SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).build();
    }
}
