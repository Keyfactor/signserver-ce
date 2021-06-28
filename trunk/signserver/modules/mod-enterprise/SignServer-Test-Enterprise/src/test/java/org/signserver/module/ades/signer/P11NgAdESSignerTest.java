/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.p11ng.common.cryptotoken.JackNJI11CryptoToken;

/**
 * AdESSigner tests using P11NG.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11NgAdESSignerTest extends AbstractAdESSignerTestBase {

    private static final Logger LOG = Logger.getLogger(P11NgAdESSignerTest.class);

    private final String existingKey1 = getConfig().getProperty("test.p11.existingkey1");

    @Before
    @Override
    public void setUp() throws Exception {
        LOG.debug(">setUp");
        super.setUp();
        Assume.assumeTrue("P11NG".equalsIgnoreCase(getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();        
    }

    @After
    @Override
    public void cleanUp() {
        super.cleanUp();
    }

    @Override
    protected void setupCryptoToken(int cryptoTokenId, String cryptoTokenName) {
        final String sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
        final String slot = getConfig().getProperty("test.p11.slot");
        final String pin = getConfig().getProperty("test.p11.pin");

        final WorkerSessionRemote workerSession = getWorkerSession();

        workerSession.setWorkerProperty(cryptoTokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(cryptoTokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(cryptoTokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(cryptoTokenId, "NAME", cryptoTokenName);
        workerSession.setWorkerProperty(cryptoTokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(cryptoTokenId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(cryptoTokenId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(cryptoTokenId, "PIN", pin);
        workerSession.setWorkerProperty(cryptoTokenId, "DEFAULTKEY", existingKey1); // Test key
    }

    @Override
    protected String getDefaultKey() {
        return existingKey1;
    }

    @Override
    public void testBasicSigning_SHA256withRSAandMGF1() throws Exception {
        Assume.assumeTrue("Test requires HSM that supports RSASSA-PSS", "true".equalsIgnoreCase(getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        super.testBasicSigning_SHA256withRSAandMGF1();
    }

    @Override
    public void testBasicSigning_SHA384withRSAandMGF1() throws Exception {
        Assume.assumeTrue("Test requires HSM that supports RSASSA-PSS", "true".equalsIgnoreCase(getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        super.testBasicSigning_SHA384withRSAandMGF1();
    }

    @Override
    public void testBasicSigning_SHA512withRSAandMGF1() throws Exception {
        Assume.assumeTrue("Test requires HSM that supports RSASSA-PSS", "true".equalsIgnoreCase(getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        super.testBasicSigning_SHA512withRSAandMGF1();
    }
    
}
