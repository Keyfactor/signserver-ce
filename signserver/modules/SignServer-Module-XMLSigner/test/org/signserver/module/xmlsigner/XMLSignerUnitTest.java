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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.w3c.dom.Document;
import org.xml.sax.SAXParseException;

/**
 * Unit tests for the XMLSigner class.
 *
 * System tests (and other tests) are available in the Test-System project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XMLSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        tokenRSA = generateToken();
    }

    private static MockedCryptoToken generateToken() throws Exception {
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setSignatureAlgorithm("SHA1withRSA")
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test signing with an RSA key using the default signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testBasicXmlSignRSADefaultSigAlg() throws Exception {
        testBasicXmlSign("<testdocument/>", null, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
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
            testBasicXmlSign(xmlWithDoctype, null, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
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

    private void testBasicXmlSign(final String document, final String sigAlg, final String expectedAlgString) throws Exception {
        WorkerConfig config = new WorkerConfig();

        // set signature algorithm for worker if specified
        if (sigAlg != null) {
            config.setProperty("SIGNATUREALGORITHM", sigAlg);
        }

        XMLSigner instance = new MockedXMLSigner(tokenRSA);
        instance.init(4711, config, null, null);
        final RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        GenericSignRequest request = new GenericSignRequest(100, document.getBytes(StandardCharsets.UTF_8));
        GenericSignResponse res = (GenericSignResponse) instance.processData(request, requestContext);

        final byte[] data = res.getProcessedData();

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Check algorithm
        assertTrue("Algorithm", usesAlgorithm(new String(data), expectedAlgString));
    }

    private void checkXmlWellFormed(final InputStream input) {
        try {
            final DocumentBuilderFactory dBF = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = dBF.newDocumentBuilder();

            final Document doc = builder.parse(input);
            doc.toString();
        } catch (Exception e) {
            LOG.error("Not well formed XML", e);
            fail("Not well formed XML: " + e.getMessage());
        }
    }

    /**
     * Returns true if the signed XML document uses the specified algorithm.
     * @param xml
     * @param algorithm
     */
    private boolean usesAlgorithm(final String xml, final String algorithm) {
        return xml.contains("Algorithm=\""+algorithm);
    }
    
}
