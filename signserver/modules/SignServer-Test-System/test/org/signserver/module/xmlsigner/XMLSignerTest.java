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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.w3c.dom.Document;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for XMLSigner.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XMLSignerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(XMLSignerTest.class);

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID = 5676;

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID2 = 5679;
    
    private static final int[] WORKERS = new int[] {5676, 5679, 5681, 5682, 5683, 5802, 5803};

    private static final String TESTXML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-XMLSigner/src/conf/junittest-part-config.properties"));
        workerSession.reloadConfiguration(WORKERID);

        // Update path to JKS file
        workerSession.setWorkerProperty(WORKERID2, "KEYSTOREPATH",
                new File(getSignServerHome() + File.separator + "res" + File.separator + "test" + File.separator + "xmlsigner4.jks").getAbsolutePath());
        workerSession.reloadConfiguration(WORKERID2);
    }

    /**
     * Test the XML signer with a given worker and optionally using a supplied signature algorithm to set to the worker.
     * 
     * @param workerId Worker to use.
     * @param sigAlg If set to non-null, set this for the SIGNATUREALGORITHM worker property while running the test.
     * @param expectedAlgString Expected algorithm string in the output XML structure.
     * @throws Exception
     */
    private void testBasicXmlSign(final int workerId, final String sigAlg, final String expectedAlgString) throws Exception {
        final int reqid = 13;

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, TESTXML1.getBytes());

        // set signature algorithm for worker if specified
        if (sigAlg != null) {
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", sigAlg);
            workerSession.reloadConfiguration(workerId);
        }
        
        final GenericSignResponse res = 
                (GenericSignResponse) workerSession.process(workerId,
                    signRequest, new RequestContext());
        final byte[] data = res.getProcessedData();

        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        // Output for manual inspection
        final FileOutputStream fos = new FileOutputStream(new File(getSignServerHome()
                + File.separator
                + "tmp" + File.separator + "signedxml_rsa.xml"));
        fos.write((byte[]) data);
        fos.close();

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Check algorithm
        assertTrue("Algorithm", usesAlgorithm(new String(data), expectedAlgString));
        
        // reset signature algorithm property
        workerSession.removeWorkerProperty(workerId, "SIGNATUREALGORITHM");
        workerSession.reloadConfiguration(workerId);
    }
        
    /**
     * Test signing with an RSA key using the default signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test01BasicXmlSignRSADefaultSigAlg() throws Exception {
        testBasicXmlSign(WORKERID, null, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    }
    
    /**
     * Test explicitly setting the signature algorithm to SHA1withRSA.
     * 
     * @throws Exception
     */
    @Test
    public void test02BasicXmlSignRSASHA1() throws Exception {
        testBasicXmlSign(WORKERID, "SHA1withRSA", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    }
    
    @Test
    public void test03BasicXmlSignRSASHA256() throws Exception {
        testBasicXmlSign(WORKERID, "SHA256withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
    
    @Test
    public void test04BasicXmlSignRSASHA384() throws Exception {
        testBasicXmlSign(WORKERID, "SHA384withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
    }
    
    @Test
    public void test05BasicXmlSignRSASHA512() throws Exception {
        testBasicXmlSign(WORKERID, "SHA512withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    }

    /**
     * Test setting a signature algorithm not corresponding to the key.
     * 
     * @throws Exception
     */
    @Test
    public void test06BasicXmlSignRSAInvalidAlgorithm() throws Exception {
        try {
            testBasicXmlSign(WORKERID, "SHA1withDSA", "http://www.w3.org/2000/09/xmldsig#dsa-sha1");
            fail("Should fail using incorrect signature algorithm for the key");
        } catch (SignServerException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown when using illegal signature algorithm: " + e.getClass().getName());
        }
    }
    
    @Test
    public void test07GetStatus() throws Exception {
        final SignerStatus stat = (SignerStatus) workerSession.getStatus(WORKERID);
        assertSame("Status", stat.getTokenStatus(), SignerStatus.STATUS_ACTIVE);
    }

    @Test
    public void test08BasicXmlSignDSADefaultSigAlg() throws Exception {
        testBasicXmlSign(WORKERID2, null, "http://www.w3.org/2000/09/xmldsig#dsa-sha1");
    }
    
    @Test
    public void test09BasicXmlSignDSASHA1() throws Exception {
        testBasicXmlSign(WORKERID2, "SHA1withDSA", "http://www.w3.org/2000/09/xmldsig#dsa-sha1");
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        for (int workerId : WORKERS) {
            removeWorker(workerId);
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
     * Returns true if the signed XML document uses the specified algorithm.
     * @param xml
     * @param algorithm
     */
    private boolean usesAlgorithm(final String xml, final String algorithm) {
        return xml.contains("Algorithm=\""+algorithm);
    }
}
