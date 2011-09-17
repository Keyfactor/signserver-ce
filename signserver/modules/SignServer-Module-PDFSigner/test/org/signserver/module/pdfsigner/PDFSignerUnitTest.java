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

import junit.framework.TestCase;

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

    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;

    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    
    private static final String CRYPTOTOKEN_CLASSNAME = 
            "org.signserver.server.cryptotokens.HardCodedCryptoToken";
    
    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    private File sampleOk;
    private File sampleRestricted;

    
    public PDFSignerUnitTest() {
        SignServerUtil.installBCProvider();
        File home = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("Environment variable SIGNSERVER_HOME", home.exists());
        sampleOk = new File(home, "src/test/ok.pdf");
        sampleRestricted = new File(home, "src/test/sample-restricted.pdf");
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
     * Tries to sign a PDF with document restrictions. As this is not (yet?) 
     * supported it throws an IllegalRequestException.
     * @throws Exception in case of error
     */
    public void test02SignWithRestrictions() throws Exception { 
        byte[] data = readFile(sampleRestricted);
        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, data),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

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
