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
package org.signserver.module.openpgp.signer;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * Unit tests for the OpenPGPSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPGPSignerUnitTest {
   
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
 
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair signerKeyPair;
        final String signatureAlgorithm;
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA256withRSA";
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }
    
    /**
     * Test that providing an incorrect value for DETACHEDSIGNATURE
     * gives a fatal error.
     * @throws Exception
     */
    /*For DSS-1969: @Test
    public void testInit_incorrectDetachedSignatureValue() throws Exception {
        LOG.info("testInit_incorrectDetachedSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
    }*/
    
    /**
     * Test that providing an incorrect value for DIGEST_ALGORITHM
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDigestAlgorithmValue() throws Exception {
        LOG.info("testInit_incorrectDigestAlgorithmValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DIGEST_ALGORITHM"));
    }
    
    protected OpenPGPSigner createMockSigner(final MockedCryptoToken token) {
        return new MockedOpenPGPSigner(token);
    }
}
