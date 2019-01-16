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
 ************************************************************************ */
package org.signserver.module.onetime.caconnector;

import java.security.KeyPair;
import java.security.Security;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.signserver.common.RequestContext;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * Unit tests for SelfSignedCAConnector.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class SelfSignedCAConnectorUnitTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Test that missing required properties gives the correct errors.
     *
     * @throws Exception
     */
    @Test
    public void test01CheckRequiredProperties() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        final SelfSignedCAConnector instance = new SelfSignedCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertTrue("Contains error about missing CERTSIGNATUREALGORITHM",
                errors.contains("Missing required property: CERTSIGNATUREALGORITHM"));
    }
    
    /**
     * Test that requesting a self-signed certificate with SHA256withRSA
     * signature algorithm works and uses the requested subject.
     * 
     * @throws Exception 
     */
    @Test
    public void test02RequestCertificateSHA256withRSA() throws Exception {
        final WorkerConfig workerConfig = new WorkerConfig();
        
        workerConfig.setProperty("CERTSIGNATUREALGORITHM", "SHA256withRSA");
        
        final SelfSignedCAConnector instance = new SelfSignedCAConnector();
        instance.init(workerConfig, new SignServerContext());
        
        final KeyPair keyPair = CryptoUtils.generateRSA(2048);
        
        final CAResponse resp = instance.requestCertificate(null, "user01",
                                                            keyPair.getPrivate(),
                                                            keyPair.getPublic(),
                                                            "BC",
                                                            new RequestContext());
        final X509CertificateHolder certHolder = resp.getCert();
        final AlgorithmNameFinder anf = new DefaultAlgorithmNameFinder();
        
        assertEquals("Matching signature algorithm",
                     "SHA256WITHRSA",
                     anf.getAlgorithmName(certHolder.getSignatureAlgorithm().getAlgorithm()));
        assertEquals("Matching subject",
                     "CN=user01", certHolder.getSubject().toString());
    }
    
    /**
     * Test that requesting a self-signed certificate with SHA256withECDSA
     * signature algorithm works and uses the requested subject.
     * 
     * @throws Exception 
     */
    @Test
    public void test03RequestCertificateSHA256withECDSA() throws Exception {
        final WorkerConfig workerConfig = new WorkerConfig();
        
        workerConfig.setProperty("CERTSIGNATUREALGORITHM", "SHA256withECDSA");
        
        final SelfSignedCAConnector instance = new SelfSignedCAConnector();
        instance.init(workerConfig, new SignServerContext());
        
        final KeyPair keyPair = CryptoUtils.generateEcCurve("secp256r1");
        
        final CAResponse resp = instance.requestCertificate(null, "user01",
                                                            keyPair.getPrivate(),
                                                            keyPair.getPublic(),
                                                            "BC",
                                                            new RequestContext());
        final X509CertificateHolder certHolder = resp.getCert();
        final AlgorithmNameFinder anf = new DefaultAlgorithmNameFinder();
        
        assertEquals("Matching signature algorithm",
                     "SHA256WITHECDSA",
                     anf.getAlgorithmName(certHolder.getSignatureAlgorithm().getAlgorithm()));
        assertEquals("Matching subject",
                     "CN=user01", certHolder.getSubject().toString());
    }
    
    /**
     * Test that requesting a self-signed certificate with SHA256withECDSA
     * signature algorithm doesn't work with an RSA key pair.
     * 
     * @throws Exception 
     */
    @Test
    public void test04RequestCertificateKeyAlgorithmNotMatchingSignatureAlgorithm()
            throws Exception {
        final WorkerConfig workerConfig = new WorkerConfig();
        
        workerConfig.setProperty("CERTSIGNATUREALGORITHM", "SHA256withECDSA");
        
        final SelfSignedCAConnector instance = new SelfSignedCAConnector();
        instance.init(workerConfig, new SignServerContext());
        
        final KeyPair keyPair = CryptoUtils.generateRSA(2048);
        
        try {
            instance.requestCertificate(null, "user01", keyPair.getPrivate(),
                                        keyPair.getPublic(), "BC",
                                        new RequestContext());
            fail("Should throw CAException");
        } catch (CAException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
}
