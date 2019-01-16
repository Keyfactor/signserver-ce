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
package org.signserver.module.onetime.cryptoworker;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for OneTimeCryptoWorker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OneTimeCryptoWorkerUnitTest {
    
    private static MockedCryptoToken mockedToken;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        mockedToken = generateToken();
    }
        
    /**
     * Test that missing required properties gives the correct errors.
     * 
     * @throws Exception 
     */
    @Test
    public void test01CheckRequiredProperties() throws Exception {
        final OneTimeCryptoWorker instance = new OneTimeCryptoWorker() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) {
                return mockedToken;
            }
        };
        
        instance.init(4711, new WorkerConfig(), new SignServerContext(), null);
        
        final List<String> errors = instance.getFatalErrors(null);
        
        assertTrue("Contains error about missing KEYALG",
                   errors.contains("Missing required property: KEYALG"));
        assertTrue("Contains error about missing KEYSPEC",
                   errors.contains("Missing required property: KEYSPEC"));
        assertTrue("Contains error about missing CACONNECTOR_IMPLEMENTATION",
                   errors.contains("Missing required property: CACONNECTOR_IMPLEMENTATION"));
    }
    
    /**
     * Test that specifying a non-existing CAConnector implementation class
     * results in an error message.
     * 
     * @throws Exception 
     */
    @Test
    public void test02UnknownCAConnector() throws Exception {
        final OneTimeCryptoWorker instance = new OneTimeCryptoWorker() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) {
                return mockedToken;
            }
        };
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("KEYALG", "RSA");
        config.setProperty("KEYSPEC", "2048");
        config.setProperty("CACONNECTOR_IMPLEMENTATION", "not.a.caconnector.Implementation");
        
        instance.init(4711, config, new SignServerContext(), null);
        
        final String errors = instance.getFatalErrors(null).toString();

        assertTrue("Contains error about unknown CACONNECTOR_IMPLEMENTATION",
                   errors.contains("Class not found: "));
    }
    
    
    private static MockedCryptoToken generateToken() throws Exception {
        final KeyPair signerKeyPair;
        final String signatureAlgorithm;
        
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA1withRSA";
       
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
            
    }

}
