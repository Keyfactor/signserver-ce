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
package org.signserver.module.xmlsigner;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.xml.sax.SAXParseException;

/**
 * Unit tests for the XMLSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XMLSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        tokenRSA = generateToken(KeyType.RSA);
        tokenDSA = generateToken(KeyType.DSA);
        tokenECDSA = generateToken(KeyType.ECDSA);
    }

    private enum KeyType {
        RSA,
        DSA,
        ECDSA
    };

    private static MockedCryptoToken generateToken(final KeyType keyType) throws Exception {
        final KeyPair signerKeyPair;
        final String signatureAlgorithm;
        final BouncyCastleProvider provider = new BouncyCastleProvider();

        switch (keyType) {
        case RSA:
            signerKeyPair = CryptoUtils.generateRSA(1024, provider);
            signatureAlgorithm = "SHA1withRSA";
            break;
        case DSA:
            signerKeyPair = CryptoUtils.generateDSA(1024, provider);
            signatureAlgorithm = "SHA1withDSA";
            break;
        case ECDSA:
            signerKeyPair = CryptoUtils.generateEcCurve("prime256v1", provider);
            signatureAlgorithm = "SHA1withECDSA";
            break;
        default:
            throw new NoSuchAlgorithmException("Invalid key algorithm");
        }

        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .setProvider(provider)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), provider);
    }

    /**
     * Internal method to perform a signing operation.
     *
     * @param token Crypto token to use
     * @param config Signer configuration to use for the test
     * @param toSign The XML document to sign
     * @param useCertCredential Generate credential for the request from the mocked signer certificate
     * @param username Username to generate a username/password credential in the request context, if null, no credential is passed
     * @return Verification result
     * @throws Exception
     */
    private String signWithXMLSigner(final MockedCryptoToken token, final WorkerConfig config, String toSign, final boolean useCertCredential, final String username) throws Exception {
        XMLSigner instance = new MockedXMLSigner(token);

        instance.init(4711, config, null, null);

        final RequestContext requestContext = new RequestContext();

        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        if (useCertCredential) {
            final CertificateClientCredential cred = new CertificateClientCredential("CN=foo", "123456789abc");

            requestContext.put(RequestContext.CLIENT_CREDENTIAL, cred);
        } else if (username != null) {
            final UsernamePasswordClientCredential cred = new UsernamePasswordClientCredential(username, "foobar");

            requestContext.put(RequestContext.CLIENT_CREDENTIAL, cred);
        }

        byte[] data;
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(toSign.getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            instance.processData(request, requestContext);

            data = responseData.toReadableData().getAsByteArray();
            final String signedXml = new String(data, StandardCharsets.UTF_8);
            LOG.debug("signedXml: " + signedXml);
            assertTrue("Contains signature", signedXml.contains("Signature>"));

            return signedXml;
        }
    }

    /**
     * Run a signing test with default form and varying algorithm.
     *
     * @param keyType Token key type to use
     * @param signatureAlgorithm Signature algorithm property value to test, if null use default
     * @param username Username to pass in via the request context, if null no username is passed in
     * @throws Exception
     */
    private void testProcessData_basicSigningInternal(final KeyType keyType, final String signatureAlgorithm, final boolean useCertCredential, final String username) throws SignServerException, NoSuchAlgorithmException, Exception {
        LOG.info("processData");

        final MockedCryptoToken token;

        switch (keyType) {
        case RSA:
            token = tokenRSA;
            break;
        case DSA:
            token = tokenDSA;
            break;
        case ECDSA:
            token = tokenECDSA;
            break;
        default:
            throw new NoSuchAlgorithmException("Unknown key algorithm");
        }

        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());

        if (signatureAlgorithm != null) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
        }

        signWithXMLSigner(token, config, "<testroot/>", useCertCredential, username);
    }

    /**
     * Test of processData method for basic signing, of class XAdESSigner.
     * Test that by default, no commitment types are included.
     * Also test that the default signature algorithm is SHA256withRSA for an RSA key.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testProcessData_basicSigning() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                null, false, null);
    }

    /**
     * Test signing with signature algorithm SHA1withRSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningRSASHA1() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                "SHA1withRSA", false, null);
    }

    /**
     * Test signing with signature algorithm specified as empty value.
     * @throws Exception
     */
    @Test
    public void testProcessData_SigningEmptyAlgo() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                "   ", false, null);
    }

    /**
     * Test signing with signature algorithm SHA256withRSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningRSASHA256() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                "SHA256withRSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA384withRSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningRSASHA384() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                "SHA384withRSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA512withRSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningRSASHA512() throws Exception {
        testProcessData_basicSigningInternal(KeyType.RSA,
                "SHA512withRSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA1withDSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningDSASHA1() throws Exception {
        testProcessData_basicSigningInternal(KeyType.DSA,
                "SHA1withDSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA1withECDSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningECDSASHA1() throws Exception {
        testProcessData_basicSigningInternal(KeyType.ECDSA,
                "SHA1withECDSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA256withECDSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningECDSASHA256() throws Exception {
        testProcessData_basicSigningInternal(KeyType.ECDSA,
                "SHA256withECDSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA384withECDSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningECDSASHA384() throws Exception {
        testProcessData_basicSigningInternal(KeyType.ECDSA,
                "SHA384withECDSA", false, null);
    }

    /**
     * Test signing with signature algorithm SHA512withECDSA.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningECDSASHA512() throws Exception {
        testProcessData_basicSigningInternal(KeyType.ECDSA,
                "SHA512withECDSA", false, null);
    }

    /**
     * Test that the default signature algorithm works when using DSA keys.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningDefaultDSA() throws Exception {
        testProcessData_basicSigningInternal(KeyType.DSA,
                null, false, null);
    }

    /**
     * Test that the default signature algorithm works when using ECDSA keys.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningDefaultECDSA() throws Exception {
        testProcessData_basicSigningInternal(KeyType.ECDSA,
                null, false, null);
    }

    // TODO: Below fails due to ticket George will register
    /**
     * Test using an illegal signature algorithm.
     *
     * @throws Exception
     */
    /*@Test
    public void testProcessData_basicSigningWrongSigAlg() throws Exception {
        try {
            testProcessData_basicSigningInternal(KeyType.RSA,
                "bogus", false, null);
            fail("Should throw a SignServerException");
        } catch (SignServerException e) { //NOPMD
            // expected
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }*/

    /**
     * Test using a signature algorithm not matching the key.
     *
     * @throws Exception
     */
    @Test
    public void testProcessData_basicSigningMismatchedSigAlg() throws Exception {
        try {
            testProcessData_basicSigningInternal(KeyType.RSA,
                "SHA1withDSA", false, null);
            fail("Should throw a SignServerException");
        } catch (SignServerException e) { //NOPMD
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }

    /**
     * Tests that a document with a DOCTYPE is not allowed.
     * @throws Exception
     */
    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testDTDNotAllowed() throws Exception {
        LOG.info("testDTDNotAllowed");
        final String xmlWithDoctype =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [\n" +
            "  <!ELEMENT foo ANY >\n" +
            "]><foo/>\n";
        try {
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
            signWithXMLSigner(tokenRSA, config, xmlWithDoctype, false, null);
            fail("Should have thrown IllegalRequestException as the document contained a DTD");
        } catch (IllegalRequestException expected) {
            if (expected.getCause() instanceof SAXParseException) {
                if (!expected.getCause().getMessage().contains("DOCTYPE")) {
                    LOG.error("Wrong exception message", expected);
                    fail("Should be error about doctype: " + expected.getMessage());
                }
            } else {
                LOG.error("Wrong exception cause", expected);
                fail("Expected SAXParseException but was: " + expected);
            }
        }
    }
}
