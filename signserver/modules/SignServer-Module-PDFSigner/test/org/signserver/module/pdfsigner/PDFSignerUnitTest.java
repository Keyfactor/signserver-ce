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
package org.signserver.module.pdfsigner;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 * Unit tests for PDFSigner.
 *
 * This tests uses a mockup and does not require an running application
 * server. Tests that require that can be placed among the system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PDFSignerUnitTest extends TestCase {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(PDFSigner.class);
    
    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;

    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    
    private static final String CRYPTOTOKEN_CLASSNAME = 
            "org.signserver.server.cryptotokens.HardCodedCryptoToken";
    private final String SAMPLE_OWNER123_PASSWORD = "owner123";
    private final String SAMPLE_USER_AAA_PASSWORD = "user\u00e5\u00e4\u00f6";
    
    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    private File sampleOk;
    private File sampleRestricted;

    private File sample;
    private File sampleOpen123;
    private File sampleOpen123Owner123;
    private File sampleOwner123;
    private File sampleUseraao;
//    private File sampleLowprintingOwner123;
    
    public PDFSignerUnitTest() {
        SignServerUtil.installBCProvider();
        File home = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("Environment variable SIGNSERVER_HOME", home.exists());
        sampleOk = new File(home, "res/test/ok.pdf");
        sampleRestricted = new File(home, "res/test/sample-restricted.pdf");
        sample = new File(home, "res/test/pdf/sample.pdf");
        sampleOpen123 = new File(home, "res/test/pdf/sample-open123.pdf");
        sampleOpen123Owner123 = new File(home, "res/test/pdf/sample-open123-owner123.pdf");
        sampleOwner123 = new File(home, "res/test/pdf/sample-owner123.pdf");
        sampleUseraao = new File(home, "res/test/pdf/sample-useraao.pdf");
//        sampleLowprintingOwner123 = new File(home, "res/test/pdf/sample-lowprinting-owner123.pdf");
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();

        setupWorkers();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test signing of a simple PDF. Mostly to test that the mockup and PDF 
     * signing works before doing other tests that are expected to fail.
     * @throws Exception in case of error
     */
    public void test01signOk() throws Exception {
        byte[] data = readFile(sampleOk);

        final GenericSignRequest request = new GenericSignRequest(100,
                data);

        final GenericSignResponse response = (GenericSignResponse)
                workerSession.process(WORKER1, request, new RequestContext());
        assertEquals("requestId", 100, response.getRequestID());

        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
    }

    /**
     * Tries to sign a PDF with document restrictions. As no password is 
     * supplied it throws an IllegalRequestException.
     * @throws Exception in case of error
     */
    public void test02SignWithRestrictionsNoPasswordSupplied() throws Exception { 
        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleRestricted)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOpen123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
    }

        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOpen123Owner123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }
        
        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOwner123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }
    }
    
    public void test02SignWithRestrictionsPasswordSupplied() throws Exception {         
        signProtectedPDF(sampleOpen123, "open123");
        signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
        signProtectedPDF(sampleOpen123Owner123, "owner123");
        signProtectedPDF(sample, null);
        signProtectedPDF(sample, "");
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
    }
    
    public void test03RejectingPermissions() throws Exception {
        
        // First test without any constraints
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
        
        // Test with empty list of constraints
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
        
        // Test with unknown permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "_NON_EXISTING_PERMISSION_");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
        
        // Test with document containing an not allowed permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }
        
        // Test with document containing two not allowed permissions
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING,ALLOW_COPY");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }
        
        // Test with document containing one not allowed permission and 
        // not the other disallowed permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_COPY,ALLOW_MODIFY_CONTENTS");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }
        
        // Test a document where only low-res printing is allowed
        /* TODO: When found such a document
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleLowprintingOwner123, SAMPLE_OWNER123_PASSWORD);
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_DEGRADED_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleLowprintingOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }*/
        
        
    }
    
    private void signProtectedPDF(File file, String password) throws Exception {
        LOG.debug("Tests signing of " + file.getName() + " with password:");
        if (password == null) {
            LOG.debug("null");
        } else {
            LOG.debug("\"" + password + "\" " + Arrays.toString(password.toCharArray()));
        }
        
        RequestContext context = new RequestContext();
        Map<String, String> metadata = new HashMap<String, String>();
        metadata.put(RequestContext.METADATA_PDFPASSWORD, password);
        context.put(RequestContext.REQUEST_METADATA, metadata);
        
        final GenericSignResponse response = 
                (GenericSignResponse) workerSession.process(WORKER1, 
                new GenericSignRequest(200, readFile(file)), 
                context);
        assertNotNull(response);
    }

    private void setupWorkers() {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalMock);
        globalConfig = globalMock;
        workerSession = workerMock;

        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestPDFSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new PDFSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
    }

    private byte[] readFile(File file) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(
                file));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            bout.write(b);
        }
        return bout.toByteArray();
    }
}
