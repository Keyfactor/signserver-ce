/** ***********************************************************************
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
package org.signserver.server.cryptotokens;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing using a ShortLived one time crypto token.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class ShortLivedP11SignTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ShortLivedP11SignTest.class);

    private final ModulesTestCase mt = new ModulesTestCase();
    private final WorkerSession workerSession = mt.getWorkerSession();
    private final ProcessSessionRemote processSession = mt.getProcessSession();

    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private static final String CRYPTO_TOKEN_NAME = "TestShortLivedSourceCryptoTokenP11";
    private static final String ONETIME_CRYPTO_TOKEN_NAME = "TestShortLivedOneTimeCryptoTokenP11";

    private static final int CRYPTO_TOKEN = 40100;
    private static final int ONETIME_CRYPTO_TOKEN = 40200;

    private static final int WORKER_XADES = 40300;

    public ShortLivedP11SignTest() throws FileNotFoundException {
        sharedLibraryName = mt.getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = mt.getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = mt.getConfig().getProperty("test.p11.slot");
        pin = mt.getConfig().getProperty("test.p11.pin");
        existingKey1 = mt.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void setupSourceCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup source crypto token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1);
    }

    private void setupOneTimeCryptoWorkerProperties(final int workerId) throws Exception {
        // Setup one time crypto worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.enterprise.caconnector.OneTimeCryptoWorker");
        workerSession.setWorkerProperty(workerId, "NAME", ONETIME_CRYPTO_TOKEN_NAME);

        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "KEYALG", "RSA");
        workerSession.setWorkerProperty(workerId, "KEYSPEC", "1024");
        workerSession.setWorkerProperty(workerId, "CACONNECTOR_IMPLEMENTATION", "org.signserver.server.enterprise.caconnector.SelfSignedCAConnector");
        workerSession.setWorkerProperty(workerId, "CERTSIGNATUREALGORITHM", "SHA256WithRSA");
    }

    private void setupXAdESSignerPropertiesReferingToken(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xades.signer.XAdESSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "TestXAdESSigner");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", ONETIME_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DISABLEKEYUSAGECOUNTER", "true"); // otherwise signing may fail
    }

    @Test
    public void testXAdesSigner() throws Exception {
        LOG.info("testXAdesSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupXAdESSignerPropertiesReferingToken(WORKER_XADES);
            workerSession.reloadConfiguration(WORKER_XADES);

            xadESSigner(WORKER_XADES);
        } finally {
            mt.removeWorker(WORKER_XADES);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void xadESSigner(final int workerId) throws Exception {
        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        mt.signGenericDocument(workerId, "<sampledata/>".getBytes());
    }

}
