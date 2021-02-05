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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.Arrays;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.signserver.client.cli.defaultimpl.DocumentSigner;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;
import org.signserver.client.cli.defaultimpl.KeyStoreOptions;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand.Protocol;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Unit tests for the ApkProvider.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkProvierUnitTest {

    /**
     * Test with SHA1withRSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA1withRSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA1withRSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expects 15 bytes padding + 20 byte digest
        assertEquals("Bytes sent", 35, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message",
                          Arrays.concatenate(ApkProvider.RSA_SHA1_MODIFIER_BYTES,
                                             expectedDigest),
                          signerFactory.message);
    }

    /**
     * Test with SHA256withRSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA256withRSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA256withRSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expects 19 bytes padding + 32 bytes digest
        assertEquals("Bytes sent", 51, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message",
                          Arrays.concatenate(ApkProvider.RSA_SHA256_MODIFIER_BYTES,
                                             expectedDigest),
                          signerFactory.message);
    }

    /**
     * Test with SHA384withRSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA384withRSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA384withRSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expect 19 bytes padding + 48 bytes digest
        assertEquals("Bytes sent", 67, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-384");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message",
                          Arrays.concatenate(ApkProvider.RSA_SHA384_MODIFIER_BYTES,
                                             expectedDigest),
                          signerFactory.message);
    }

    /**
     * Test with SHA512withRSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA512withRSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA512withRSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expect 19 bytes padding + 64 bytes digest
        assertEquals("Bytes sent", 83, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-512");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message",
                          Arrays.concatenate(ApkProvider.RSA_SHA512_MODIFIER_BYTES,
                                             expectedDigest),
                          signerFactory.message);
    }

    /**
     * Test with SHA1withECDSA.
     * Checks that the provider sends the digest.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA1withECDSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA1withECDSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expects 20 byte digest
        assertEquals("Bytes sent", 20, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message", expectedDigest, signerFactory.message);
    }

    /**
     * Test with SHA256withECDSA.
     * Checks that the provider sends the digest.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA256withECDSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA256withECDSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expects 32 bytes digest
        assertEquals("Bytes sent", 32, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message", expectedDigest, signerFactory.message);
    }

    /**
     * Test with SHA384withECDSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA384withECDSA() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA384withECDSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expect 48 bytes digest
        assertEquals("Bytes sent", 48, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-384");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message", expectedDigest, signerFactory.message);
    }

    /**
     * Test with SHA512withECDSA.
     * Checks that the provider sends the digest prepended with the correct padding.
     *
     * @throws Exception 
     */
    @Test
    public void testSHA512withECDSAs() throws Exception {
        final ApkProvider prov = new ApkProvider();
        final ApkProvider.ApkSignature signature =
                new ApkProvider.ApkSignature(prov, "SHA512withECDSA");
        final MockedDocumentSignerFactory signerFactory =
                new MockedDocumentSignerFactory();
        
        final ApkRsaPrivateKey privKey =
                new ApkRsaPrivateKey("SomeApkHashSigner", signerFactory,
                                     null, null);

        signature.engineInitSign(privKey);
        signature.engineUpdate("foo123".getBytes(StandardCharsets.UTF_8), 0, 6);
        signature.engineSign();

        // expect 64 bytes digest
        assertEquals("Bytes sent", 64, signerFactory.message.length);

        final MessageDigest md = MessageDigest.getInstance("SHA-512");
        final byte[] expectedDigest = md.digest("foo123".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Expected message", expectedDigest, signerFactory.message);
    }

    /**
     * Mocked implementation of DocumentSignerFactory instrumenting the
     * relevant sign method to record sent message.
     */
    private static final class MockedDocumentSignerFactory extends DocumentSignerFactory {

        public byte[] message;
        
        public MockedDocumentSignerFactory() {
            super(Protocol.HTTP, new KeyStoreOptions(), "localhost", "dummy", 8080, null, null,
                  null, null, null, null, 0);
        }

        @Override
        public DocumentSigner createSigner(String workerName, Map<String, String> metadata, boolean clientSide, boolean isSignatureInputHash, String typeId) {
            return new MockedDocumentSigner();
        }

        private final class MockedDocumentSigner implements DocumentSigner {

            @Override
            public void sign(InputStream data, long size, String encoding, OutputStream out, Map<String, Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public void sign(InputStream data, long size, String encoding, Map<String, Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public void sign(InputStream data, long size) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public void sign(InputStream data, long size, OutputStream out, Map<String, Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
                MockedDocumentSignerFactory.this.message = IOUtils.toByteArray(data);
            }

        }   
    }
}
