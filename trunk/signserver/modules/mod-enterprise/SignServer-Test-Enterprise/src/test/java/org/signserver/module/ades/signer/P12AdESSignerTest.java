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

import java.io.File;
import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.cryptotokens.P12CryptoToken;

/**
 * System tests for AdESSigner using PKCS#12.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class P12AdESSignerTest extends AbstractAdESSignerTestBase {
    
    private static final Logger LOG = Logger.getLogger(P12AdESSignerTest.class);

    private final static String EXISTING_KEY = "signer00003";

    @Override
    protected void setupCryptoToken(int cryptoTokenId, String cryptoTokenName) throws Exception {
        LOG.debug(">setupCryptoToken");
        File sampleKeystore = new File(PathUtil.getAppHome(),
                                  "res/test/dss10/dss10_keystore.p12");
        if (!sampleKeystore.exists()) {
            throw new Exception("Missing sample P12 keystore: " +
                                sampleKeystore);
        }
        
        WorkerSessionRemote workerSession = getWorkerSession();

        workerSession.setWorkerProperty(cryptoTokenId,
                                        WorkerConfig.IMPLEMENTATION_CLASS,
                                        "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(cryptoTokenId,
                                        WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                                        P12CryptoToken.class.getName());
        workerSession.setWorkerProperty(cryptoTokenId, WorkerConfig.TYPE,
                                        WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(cryptoTokenId,
                                        "NAME", cryptoTokenName);
        workerSession.setWorkerProperty(cryptoTokenId, "KEYSTOREPATH",
                                        sampleKeystore.getAbsolutePath());
        workerSession.setWorkerProperty(cryptoTokenId, "KEYSTOREPASSWORD",
                                        KEYSTORE_PASSWORD);
        workerSession.setWorkerProperty(cryptoTokenId, "DEFAULTKEY",
                                        EXISTING_KEY);
    }

    @Override
    protected String getDefaultKey() {
        return EXISTING_KEY;
    }

    /*@Test
    @Override
    public void testBasicSigning_SHA256withRSA() throws Exception {
        super.testBasicSigning_SHA256withRSA(); //To change body of generated methods, choose Tools | Templates.
    }
    
    @Test
    @Override
    public void testBasicSigning_SHA256withRSAandMGF1() throws Exception {
        super.testBasicSigning_SHA256withRSAandMGF1(); //To change body of generated methods, choose Tools | Templates.
    }*/
    
    

}
