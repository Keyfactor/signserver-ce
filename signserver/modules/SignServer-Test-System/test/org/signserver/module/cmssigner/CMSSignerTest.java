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
package org.signserver.module.cmssigner;

import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.Collection;


import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for CMSSigner.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class CMSSignerTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CMSSignerTest.class);
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
	
    public void test00SetupDatabase() throws Exception {
        addSigner("org.signserver.module.cmssigner.CMSSigner");
    }

    /**
     * Tests that the signer can produce a CMS structure and that it returns
     * the signer's certficate and that it is included in the structure and
     * that it can be used to verify the signature and that the signed content
     * also is included.
     * @throws Exception In case of error.
     */
    public void test01BasicCMSSignRSA() throws Exception {
        LOG.debug(">test01BasicCMSSignRSA");

        final int reqid = 37;

        final String testDocument = "Something to sign...123";

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, testDocument.getBytes());

        final GenericSignResponse res =
                (GenericSignResponse) workerSession.process(getSignerIdDummy1(),
                    signRequest, new RequestContext());
        final byte[] data = res.getProcessedData();

        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        // Output for manual inspection
        final FileOutputStream fos = new FileOutputStream(
                new File(getSignServerHome(),
                "tmp" + File.separator + "signedcms_rsa.p7s"));
        fos.write((byte[]) data);
        fos.close();

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // Check that the signed data contains the document (i.e. not detached)
        final CMSSignedData signedData = new CMSSignedData(data);
        final byte[] content = (byte[]) signedData.getSignedContent()
                .getContent();
        assertEquals("Signed document", testDocument, new String(content));

        // Get signers
        final Collection signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer
                = (SignerInformation) signers.iterator().next();

        // Verify using the signer's certificate
        assertTrue("Verification using signer certificate",
                signer.verify(signercert.getPublicKey(), "BC"));

        // Check that the signer's certificate is included
        CertStore certs = signedData.getCertificatesAndCRLs("Collection", "BC");
        Collection<? extends Certificate> signerCerts
                = certs.getCertificates(signer.getSID());
        assertEquals("One certificate included", 1, signerCerts.size());
        assertEquals(signercert, signerCerts.iterator().next());

        LOG.debug("<test01BasicCMSSignRSA");
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
}
