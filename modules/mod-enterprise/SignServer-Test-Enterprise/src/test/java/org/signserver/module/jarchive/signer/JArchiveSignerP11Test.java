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
package org.signserver.module.jarchive.signer;

import java.io.File;
import java.util.Date;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for JArchiveSigner using PKCS#11.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use JArchiveSignerUnitTest instead.
 * 
 * See also JArchiveSignerTest for tests that are not PKCS#11 specific.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JArchiveSignerP11Test extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveSignerP11Test.class);

    private static final int WORKER_ID = 8909;
    private static final String WORKER_NAME = "TestJArchiveSignerP11";
    //private static final int TS_ID = 8908;
    //private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    private static final int CRYPTO_TOKEN_ID = 8907;
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File executableFile;
    
    private final WorkerSession workerSession = getWorkerSession();
    
    public JArchiveSignerP11Test() throws Exception {
        sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
        slot = getConfig().getProperty("test.p11.slot");
        pin = getConfig().getProperty("test.p11.pin");
        existingKey1 = getConfig().getProperty("test.p11.existingkey1");
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloJar.jar");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
    }
    
    private void setJArchiveSignerProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.jarchive.signer.JArchiveSigner");
        workerSession.setWorkerProperty(workerId, "NAME", WORKER_NAME);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    /**
     * Test signing using PKCS#11 token.
     * @throws Exception 
     */
    @Test
    public void testSigningUsingP11() throws Exception {
        LOG.info("testSigningUsingP11");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setJArchiveSignerProperties(WORKER_ID);
            //addMSTimeStampSigner(TS_ID, TS_NAME, true);
            //workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            //workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            //workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            //workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            JArchiveSignerTest.signAndAssertOk(FileUtils.readFileToByteArray(executableFile), WORKER_ID, /*TS_ID*/null, time);
        } finally {
            removeWorker(WORKER_ID);
            //removeWorker(TS_ID);
            removeWorker(CRYPTO_TOKEN_ID);
        }
    }

}
