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
package org.signserver.module.msauthcode.signer;

import java.io.File;
import java.util.Date;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.FixedTimeSource;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for MSAuthCodeSigner using PKCS#11.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use MSAuthCodeSignerUnitTest instead.
 * 
 * See also MSAuthCodeSignerTest for tests that are not PKCS#11 specific.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MSAuthCodeSignerP11Test extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeSignerP11Test.class);

    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestAuthenticodeSignerP11";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    private static final int CRYPTO_TOKEN_ID = 8903;
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File executableFile;
    private final File msiFile;

    private final WorkerSession workerSession = getWorkerSession();
    
    public MSAuthCodeSignerP11Test() throws Exception {
        sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
        slot = getConfig().getProperty("test.p11.slot");
        pin = getConfig().getProperty("test.p11.pin");
        existingKey1 = getConfig().getProperty("test.p11.existingkey1");
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
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
    
    private void setAuthenticodeSignerProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.msauthcode.signer.MSAuthCodeSigner");
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
    public void testSigningPEUsingP11() throws Exception {
        testSigningUsingP11(false);
    }
    
    /**
     * Test signing MSI using PKCS#11 token.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningMSIUsingP11() throws Exception {
        testSigningUsingP11(true);
    }

    private void testSigningUsingP11(final boolean msi) throws Exception {
        File signedBinary = null;
        LOG.info("testSigningUsingP11");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setAuthenticodeSignerProperties(WORKER_ID);
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOkMSI(msiFile, WORKER_ID, TS_ID, time, false);
            } else {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOk(executableFile, WORKER_ID, TS_ID, time, false);
            }
        } finally {
            if (signedBinary != null) {
                signedBinary.delete();
            }
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
            removeWorker(CRYPTO_TOKEN_ID);
        }
    }

}
