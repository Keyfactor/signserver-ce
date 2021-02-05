/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.extendedcmssigner;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;
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
 * Unit tests for the extended CMS signer
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExtendedCMSSignerUnitTest {
    
    private final int workerId = 4711;
    
    private static MockedCryptoToken tokenRSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
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
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }
    
    /**
     * Test that setting both TSA_URL and TSA_WORKER at the same time is not
     * allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void test01BothTsaUrlAndTsaWorkerNotAllowed() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("TSA_URL", "https://some.tsa");
        config.setProperty("TSA_WORKER", "A_TSA_WORKER_NAME");
        instance.init(workerId, config, new SignServerContext(), null);
        
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Can not specify both TSA_URL and TSA_WORKER at the same time."));
    }
    
    /**
     * Test that setting TSA_USERNAME without also setting TSA_PASSWORD is not
     * allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void test02TsaUserNameRequiresTsaPassword() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("TSA_URL", "https://some.tsa");
        config.setProperty("TSA_USERNAME", "user");
        instance.init(workerId, config, new SignServerContext(), null);
        
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Need to specify TSA_PASSWORD if TSA_USERNAME is specified."));
    }
    
    /**
     * Test that the signer is not indicating that the CMSSignedData object
     * should be extended when no TSA is configured. To avoid unnesserary
     * "repacking" of the CMS.
     * 
     * @throws Exception 
     */
    @Test
    public void test03DontExtendCMSDataWhenNoTSA() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        instance.init(workerId, config, new SignServerContext(), null);
        
        assertFalse("should not extend CMS data", instance.extendsCMSData());
    }
    
    /**
     * Test that the signer is indicating that the CMSSignedData object is to be
     * extended when TSA_URL is set.
     * 
     * @throws Exception 
     */
    @Test
    public void test04ExtendCMSDataWithTSAURL() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("TSA_URL", "https://some.tsa");
        instance.init(workerId, config, new SignServerContext(), null);
        
        assertTrue("should extend CMS data", instance.extendsCMSData());
    }
    
    /**
     * Test that the signer is indicating that the CMSSignedData object is to be
     * extended when TSA_WORKER is set.
     * 
     * @throws Exception 
     */
    @Test
    public void test05ExtendCMSDataWithTSAWorker() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("TSA_WORKER", "https://some.tsa");
        instance.init(workerId, config, new SignServerContext(), null);
        
        assertTrue("should extend CMS data", instance.extendsCMSData());
    }
    
    /**
     * Test that setting an illegal timestamping digest algorithm is not allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void test06IllegalTSADigestAlgorithm() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("TSA_DIGESTALGORITHM", "illegal");
        instance.init(workerId, config, new SignServerContext(), null);
        
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Illegal timestamping digest algorithm specified: illegal"));
    }
    
    /**
     * Test that empty values are treated as default values.
     * 
     * @throws Exception 
     */
    @Test
    public void testConfigWithEmptyParams() throws Exception {
        final ExtendedCMSSigner instance = new MockedExtendedCMSSigner(tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("TSA_WORKER", " ");
        config.setProperty("TSA_URL", " ");
        config.setProperty("TSA_POLICYOID", "  ");
        config.setProperty("TSA_USERNAME", " ");
        config.setProperty("TSA_DIGESTALGORITHM", " ");
        instance.init(workerId, config, new SignServerContext(), null);
        
        assertNull("TSA_URL default value", instance.getTsaUrl());
        assertNull("TSA_WORKER default value", instance.getTsaWorker());
        assertNull("TSA_USERNAME default value", instance.getTsaUsername());
        assertNull("TSA_POLICYOID default value", instance.getTsaPolicyOid());
    }
}
