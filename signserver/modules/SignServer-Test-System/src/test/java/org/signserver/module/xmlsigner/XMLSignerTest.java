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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.w3c.dom.Document;
import org.junit.Before;
import org.junit.Test;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;

/**
 * Tests for XMLSigner.
 *
 * TODO: Most test cases here can be moved to the unit test in Module-XMSigner.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XMLSignerTest {

    private static final Logger LOG = Logger.getLogger(XMLSignerTest.class);
    private final ModulesTestCase mt = new ModulesTestCase();

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID = 5676;

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID2 = 5679;
    
    private static final int WORKERID3 = 5804;
    
    private static final int DEBUGWORKER = 5805;
    
    private static final int[] WORKERS = new int[] {WORKERID, WORKERID2, WORKERID3, DEBUGWORKER};

    private static final String TESTXML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";

    private final WorkerSession workerSession = mt.getWorkerSession();
    private final ProcessSessionRemote processSession = mt.getProcessSession();

    private static final String DIGEST_METHOD_URI_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final String DIGEST_METHOD_URI_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String DIGEST_METHOD_URI_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String DIGEST_METHOD_URI_RIPEMD160 = "http://www.w3.org/2001/04/xmlenc#ripemd160";
    private static final String DIGEST_METHOD_URI_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        mt.addSigner("org.signserver.module.xmlsigner.XMLSigner", WORKERID, "TestXMLSigner", true);
        
        // Update path to JKS file
        workerSession.setWorkerProperty(WORKERID2, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(WORKERID2, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
        workerSession.setWorkerProperty(WORKERID2, "NAME", "TestXMLSignerDSA");
        workerSession.setWorkerProperty(WORKERID2, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKERID2, "KEYSTOREPATH",
                new File(mt.getSignServerHome() + File.separator + "res" + File.separator + "test" + File.separator + "xmlsigner4.jks").getAbsolutePath());
        workerSession.setWorkerProperty(WORKERID2, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKERID2, "DEFAULTKEY", "xmlsigner4");
        workerSession.reloadConfiguration(WORKERID2);
        
        workerSession.setWorkerProperty(WORKERID3, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(WORKERID3, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.P12CryptoToken");
        workerSession.setWorkerProperty(WORKERID3, "NAME", "TestXMLSignerECDSA");
        workerSession.setWorkerProperty(WORKERID3, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKERID3, "KEYSTOREPATH",
                new File(mt.getSignServerHome() + File.separator + "res" + File.separator + "test" + File.separator + "xmlsignerec.p12").getAbsolutePath());
        workerSession.setWorkerProperty(WORKERID3, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKERID3, "DEFAULTKEY",
                "23b427f763311df918fc10e44e19528634b4193c");
        workerSession.reloadConfiguration(WORKERID3);
        
        mt.addSigner("org.signserver.module.xmlsigner.DebugSigner", DEBUGWORKER, "XMLDebugSigner", false);
    }

    /**
     * Test the XML signer with a given worker and optionally using a supplied signature algorithm to set to the worker.
     * 
     * @param workerId Worker to use.
     * @param sigAlg If set to non-null, set this for the SIGNATUREALGORITHM worker property while running the test.
     * @param digestAlg If set to non-null, set this for the DIGESTALGORITHM worker property while running the test.
     * @param expectedAlgString Expected signature algorithm string in the output XML structure.
     * @param expectedDigestAlgString Expected digest algorithm string in the output XML structure.
     * @throws Exception
     */
    private void testBasicXmlSign(final int workerId, final String sigAlg, final String digestAlg, final String expectedSignatureAlgString, final String expectedDigestAlgString) throws Exception {
        final int reqid = 13;

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, TESTXML1.getBytes());

        // set signature algorithm for worker if specified
        if (sigAlg != null) {
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", sigAlg);
            workerSession.reloadConfiguration(workerId);
        }
        
        if (digestAlg != null) {
            workerSession.setWorkerProperty(workerId, "DIGESTALGORITHM", digestAlg);
            workerSession.reloadConfiguration(workerId);
        }

        final GenericSignResponse res = 
                (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId),
                    signRequest, new RemoteRequestContext());
        final byte[] data = res.getProcessedData();

        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        try ( // Output for manual inspection
                FileOutputStream fos = new FileOutputStream(new File(mt.getSignServerHome()
                        + File.separator
                        + "tmp" + File.separator + "signedxml_" + workerId + "_" + sigAlg + ".xml"))) {
            fos.write((byte[]) data);
        }

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Check signature algorithm
        assertTrue("Algorithm", usesSignatureAlgorithm(new String(data), expectedSignatureAlgString));
        
        // Check digest algorithm
        assertTrue("Algorithm", usesDigestAlgorithm(new String(data), expectedDigestAlgString));
        
        // reset signature algorithm property
        workerSession.removeWorkerProperty(workerId, "SIGNATUREALGORITHM");
        workerSession.reloadConfiguration(workerId);
        
        // reset digest algorithm property
        workerSession.removeWorkerProperty(workerId, "DIGESTALGORITHM");
        workerSession.reloadConfiguration(workerId);
    }
        
    /**
     * Test signing with an RSA key using the default signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test01BasicXmlSignRSADefaultSigAlg() throws Exception {
        testBasicXmlSign(WORKERID, null, null, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    /**
     * Test signing with an RSA key using the Empty signature algorithm.
     *
     * @throws Exception
     */
    @Test
    public void test17BasicXmlSignEmptySigAlg() throws Exception {
        testBasicXmlSign(WORKERID, "   ", null, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    /**
     * Test explicitly setting the signature algorithm to SHA1withRSA.
     * 
     * @throws Exception
     */
    @Test
    public void test02BasicXmlSignRSASHA1() throws Exception {
        testBasicXmlSign(WORKERID, "SHA1withRSA", null, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", DIGEST_METHOD_URI_SHA1);
    }
    
    @Test
    public void test03BasicXmlSignRSASHA256() throws Exception {
        testBasicXmlSign(WORKERID, "SHA256withRSA", null, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    @Test
    public void test04BasicXmlSignRSASHA384() throws Exception {
        testBasicXmlSign(WORKERID, "SHA384withRSA", null, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", DIGEST_METHOD_URI_SHA384);
    }
    
    @Test
    public void test05BasicXmlSignRSASHA512() throws Exception {
        testBasicXmlSign(WORKERID, "SHA512withRSA", null, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", DIGEST_METHOD_URI_SHA512);
    }
    
    @Test
    public void test20BasicXmlSignRSASHA512_Digest_SHA256() throws Exception {
        testBasicXmlSign(WORKERID, "SHA512withRSA", "SHA256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", DIGEST_METHOD_URI_SHA256);
    }
    
    @Test
    public void test21BasicXmlSignRSASHA512_Digest_RIPEMD160() throws Exception {
        testBasicXmlSign(WORKERID, "SHA512withRSA", "RIPEMD160", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", DIGEST_METHOD_URI_RIPEMD160);
    }

    /**
     * Test setting a signature algorithm not corresponding to the key.
     * 
     * @throws Exception
     */
    @Test
    public void test06BasicXmlSignRSAInvalidAlgorithm() throws Exception {
        try {
            testBasicXmlSign(WORKERID, "SHA1withDSA", null, "http://www.w3.org/2000/09/xmldsig#dsa-sha1", DIGEST_METHOD_URI_SHA1);
            fail("Should fail using incorrect signature algorithm for the key");
        } catch (SignServerException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown when using illegal signature algorithm: " + e.getClass().getName());
        }
    }
    
    /**
     * Test setting a invalid digest algorithm.
     *
     * @throws Exception
     */
    @Test
    public void test22BasicXmlSignInvalidDigestAlgorithm() throws Exception {
        try {
            testBasicXmlSign(WORKERID, "SHA256withRSA", "INVALID_DIGEST_ALGORITHM", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DIGEST_METHOD_URI_SHA256);
            fail("Should fail using invalid digest algorithm");
        } catch (SignServerException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown when using invalid digest algorithm: " + e.getClass().getName());
        }
    }
    
    @Test
    public void test07GetStatus() throws Exception {
        final StaticWorkerStatus stat = (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(WORKERID));
        assertSame("Status", stat.getTokenStatus(), WorkerStatus.STATUS_ACTIVE);
    }

    @Test
    public void test08BasicXmlSignDSADefaultSigAlg() throws Exception {
        testBasicXmlSign(WORKERID2, null, null, "http://www.w3.org/2009/xmldsig11#dsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    @Test
    public void test09BasicXmlSignDSASHA1() throws Exception {
        testBasicXmlSign(WORKERID2, "SHA1withDSA", null, "http://www.w3.org/2000/09/xmldsig#dsa-sha1", DIGEST_METHOD_URI_SHA1);
    }

    @Test
    public void test10BasicXmlSignECDSASHA1() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA1withECDSA", null, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", DIGEST_METHOD_URI_SHA1);
    }
 
    @Test
    public void test11BasicXmlSignECDSASHA256() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA256withECDSA", null, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    @Test
    public void test12BasicXmlSignECDSASHA384() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA384withECDSA", null, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", DIGEST_METHOD_URI_SHA384);
    }
    
    @Test
    public void test13BasicXmlSignECDSASHA512() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA512withECDSA", null, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", DIGEST_METHOD_URI_SHA512);
    }
    
    @Test
    public void test18BasicXmlSignECDSASHA512_Digest_SHA256() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA512withECDSA", "SHA256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", DIGEST_METHOD_URI_SHA256);
    }
    
     @Test
    public void test19BasicXmlSignECDSASHA512_Digest_RIPEMD160() throws Exception {
        testBasicXmlSign(WORKERID3, "SHA512withECDSA", "RIPEMD160", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", DIGEST_METHOD_URI_RIPEMD160);
    }
    
    /**
     * Test the default signature algorithm for RSA keys.
     * @throws Exception
     */
    @Test
    public void test14BasicXmlSignECDSADefaultSigAlg() throws Exception {
        testBasicXmlSign(WORKERID3, null, null, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", DIGEST_METHOD_URI_SHA256);
    }
    
    /**
     * Test that that expected version of the XML Security library is used.
     * @throws Exception
     */
    @Test
    public void test15XMLSecVersion() throws Exception {
        checkDebugProperty("xml-sec.version", "2.1.7");
    }
    
    /**
     * Test that that expected version of the Xalan library is used.
     * @throws Exception
     */
    @Test
    public void test16XalanVersion() throws Exception {
        checkDebugProperty("xalan.version", 
                "Xalan Java 2.7.2", // after copy-xmlsec on JBoss 5
                "2.7.2", // after manually copying on JBoss AS 7
                "2.7.1-redhat-7" // on JBoss EAP >= 6.3 or patched
        );
    }

    /**
     * Check the return data from the debug signer for a given property.
     * 
     * @param property
     * @param expected
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     * @throws IOException
     */
    private void checkDebugProperty(final String property, final String... expected)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        final int reqid = 42;

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, "foo".getBytes());

        final GenericSignResponse res = 
                (GenericSignResponse) processSession.process(new WorkerIdentifier(DEBUGWORKER),
                    signRequest, new RemoteRequestContext());
        final byte[] data = res.getProcessedData();

        final Properties props = new Properties();
        props.load(new ByteArrayInputStream(data));
        
        final String value = props.getProperty(property);
        
        assertNotNull("Property not found", value);
        boolean found = false;
        for (String exp : expected) {
            if (value.startsWith(exp)) {
                found = true;
                break;
            }
        }
        assertTrue("Property value: " + value + " not one of the expected " + Arrays.toString(expected), found);
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        for (int workerId : WORKERS) {
            mt.removeWorker(workerId);
        }
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
     * Returns true if the signed XML document uses the specified signature algorithm.
     * @param xml
     * @param algorithm
     */
    private boolean usesSignatureAlgorithm(final String xml, final String signatureAlgorithm) {
        return xml.contains("Algorithm=\"" + signatureAlgorithm);
    }
    
    /**
     * Returns true if the signed XML document uses the specified digest algorithm.
     * @param xml
     * @param algorithm
     */
    private boolean usesDigestAlgorithm(final String xml, final String digestAlgorithm) {
        return xml.contains("Algorithm=\"" + digestAlgorithm);
    }
}
