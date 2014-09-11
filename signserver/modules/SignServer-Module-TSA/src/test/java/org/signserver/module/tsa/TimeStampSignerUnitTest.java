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
package org.signserver.module.tsa;

import java.math.BigInteger;
import java.security.Security;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.LocalComputerTimeSource;
import org.signserver.server.cryptotokens.HardCodedCryptoTokenAliases;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 * Unit tests for the TimeStampSigner.
 *
 * System tests can be put in the Test-System project instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStampSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampSignerUnitTest.class);

    private static final int WORKER1 = 8890;
    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME = "org.signserver.server.cryptotokens.HardCodedCryptoToken";

    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    @Before
    public void setUp() throws Exception {
        setupWorkers();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tests that the log contains the TSA_TIMESOURCE entry.
     * @throws Exception
     */
    @Test
    public void testLogTimeSource() throws Exception {
        LOG.info("testLogTimeSource");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER1, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(requestContext);
        assertEquals("timesource", LocalComputerTimeSource.class.getSimpleName(), logMap.get("TSA_TIMESOURCE"));
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
            config.setProperty(NAME, "TestTimeStampSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
    }
}
