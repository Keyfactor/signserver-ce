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
import java.io.InputStream;
import java.security.cert.Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.ServiceLocator;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.w3c.dom.Document;

/**
 * Tests for XMLSigner.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TestXMLSigner extends TestCase {

    private static final Logger LOG = Logger.getLogger(TestXMLSigner.class);

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID = 5676;

    /** WORKERID used in this test case as defined in junittest-part-config.properties */
    private static final int WORKERID2 = 5679;

    private static IWorkerSession.IRemote workerSession;
    private static String signserverhome;
    private static int moduleVersion;
	
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
	
    public void test00SetupDatabase() throws Exception {

        final MARFileParser marFileParser = new MARFileParser(signserverhome
                + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                signserverhome + "/dist-server/xmlsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));

        workerSession.reloadConfiguration(WORKERID);

        // Update path to JKS file
        workerSession.setWorkerProperty(WORKERID2, "KEYSTOREPATH",
                new File(signserverhome + File.separator + "src" + File.separator + "test" + File.separator + "xmlsigner4.jks").getAbsolutePath());
        workerSession.reloadConfiguration(WORKERID2);
    }

    public void test01BasicXmlSignRSA() throws Exception {

        final int reqid = 13;

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, TESTXML1.getBytes());

        final GenericSignResponse res = 
                (GenericSignResponse) workerSession.process(WORKERID,
                    signRequest, new RequestContext());
        final byte[] data = res.getProcessedData();

        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        // Output for manual inspection
        final FileOutputStream fos = new FileOutputStream(new File(signserverhome
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
        assertTrue("Algorithm", usesAlgorithm(new String(data),
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1"));
    }

    public void test02GetStatus() throws Exception {
        final SignerStatus stat = (SignerStatus) workerSession.getStatus(WORKERID);
        assertSame("Status", stat.getTokenStatus(), SignerStatus.STATUS_ACTIVE);
    }

    public void test03BasicXmlSignDSA() throws Exception {
        final int reqid = 15;

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, TESTXML1.getBytes());

        final GenericSignResponse res =
                (GenericSignResponse) workerSession.process(WORKERID2,
                    signRequest,
                    new RequestContext());

        final byte[] data = res.getProcessedData();

        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        // Output for manual inspection
        final FileOutputStream fos = new FileOutputStream(
                new File(signserverhome +
                File.separator + "tmp" +
                File.separator + "signedxml_dsa.xml"));
        fos.write((byte[]) data);
        fos.close();

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Check algorithm
        assertTrue("Algorithm", usesAlgorithm(new String(data),
                "http://www.w3.org/2000/09/xmldsig#dsa-sha1"));
    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workerSession.reloadConfiguration(WORKERID);
        workerSession.reloadConfiguration(WORKERID2);
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

    private static final String TESTXML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";

    /**
     * Returns true if the signed XML document uses the specified algorithm.
     * @param xml
     * @param algorithm
     */
    private boolean usesAlgorithm(final String xml, final String algorithm) {
        return xml.contains("Algorithm=\""+algorithm);
    }
}
