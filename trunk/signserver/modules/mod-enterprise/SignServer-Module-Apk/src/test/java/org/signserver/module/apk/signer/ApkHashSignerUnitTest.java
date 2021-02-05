/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.ByteArrayDataSink;
import com.novell.ldap.util.Base64;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.SignServerContext;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * Unit tests for the ApkHashSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkHashSignerUnitTest {
    private static MockedServicesImpl services;
    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenRSANew;

    @BeforeClass
    public static void setupUpClass() throws Exception {
        // init mock global session
        final GlobalConfigurationSessionMock globalMock =
                new GlobalConfigurationSessionMock();
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalMock);

        // setup mock tokens to create test lineage
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
     * Test that a malformed base64-encoded lineage is not accepted.
     *
     * @throws Exception 
     */
    @Test
    public void testIllegalLineageFileContent() throws Exception {
        final ApkHashSigner instance = new ApkHashSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("LINEAGE_FILE_CONTENT", "====");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
    }

    /**
     * Test that valid base64-encoded, but not valid lineage gives the correct
     * error.
     *
     * @throws Exception 
     */
    @Test
    public void testInvaldLinageLegalBase64FileContent() throws Exception {
        final ApkHashSigner instance = new ApkHashSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("LINEAGE_FILE_CONTENT", "Zm9vMTIzCg==");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Should not contain error: " + errors.toString(),
                   errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Failed to parse lineage: Improper SigningCertificateLineage format: insufficient data for header."));
    }

    /**
     * Test that setting a valid lineage file content does not give an error.
     *
     * @throws Exception 
     */
    @Test
    public void testValidLineage() throws Exception {
        final ApkHashSigner instance = new ApkHashSigner();
        final WorkerConfig config = new WorkerConfig();
        final SigningCertificateLineage lineage = createLineage();
        final ByteArrayDataSink sink = new ByteArrayDataSink();
        
        lineage.writeToDataSink(sink);
        final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());
        
        config.setProperty("LINEAGE_FILE_CONTENT", Base64.encode(buffer.array()));
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Should not contain error: " + errors.toString(),
                    errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
        assertFalse("Should not contain error: " + errors.toString(),
                    errors.toString().contains("Failed to parse lineage"));
    }

    /**
     * Create a test lineage given the two test tokens, old and new.
     * 
     * @return SigningCertificateLineage
     * @throws Exception 
     */
    private SigningCertificateLineage createLineage() throws Exception {
        SigningCertificateLineage.SignerConfig oldSignerConfig =
                createSignerConfig(tokenRSA.getPrivateKey(0),
                                   (X509Certificate) tokenRSA.getCertificate(0));

        SigningCertificateLineage.SignerConfig newSignerConfig =
                createSignerConfig(tokenRSANew.getPrivateKey(0),
                                   (X509Certificate) tokenRSANew.getCertificate(0));

        return new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig).build();
    }

    private SigningCertificateLineage.SignerConfig createSignerConfig(final PrivateKey privateKey,
                                                                      final X509Certificate cert) {
        return new SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).build();
    }
}
