/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.io.File;
import java.io.FileNotFoundException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.xbill.DNS.DNSSEC.Algorithm;

/**
 * System tests for the ZoneFileServerSideSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileServerSideSignerTest extends ZoneFileServerSideSignerTestBase {
   /**
    * Logger for this class.
    */
   private static final Logger LOG = Logger.getLogger(ZoneFileServerSideSignerTest.class);

   private static final int WORKER_ID = 18901;
   private static final String WORKER_NAME = "TestZoneFileServerSideSigner";
   private static final String KEYSTORE_NAME = "testCryptoTokenP12";
   private static final String SAMPLE_ZONE_FILE = "res/test/example.com.zone";

   private File tempKeystoreFile;
   private final File keystore;

   public ZoneFileServerSideSignerTest() throws FileNotFoundException {
       keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_keystore.p12");
   }

   /**
    * Basic test case using two active KSKs.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsks() throws Exception {
       LOG.info("testBasicSigningTwoKsks");
       testSigning(WORKER_ID, WORKER_NAME, 0, null, 18, 2, false, false, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case using one active KSK.
    * @throws Exception 
    */
   @Test
   public void testBasicSigningOneKsk() throws Exception {
       LOG.info("testBasicSigningOneKsk");
       testSigning(WORKER_ID, WORKER_NAME, 0, null, 17, 1, false, false, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case with only one ZSK.
    * Should give a runtime failure when signing.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningOneZsk() throws Exception {
       LOG.info("testBasicSigningOneZsk");
       // deliberatly specify a nonsence expected verified signatures
       testSigning(WORKER_ID, WORKER_NAME, 0, null, -1, 2, true, true, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case using two active KSKs, using SHA1withRSA.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsksSHA1withRSA() throws Exception {
       LOG.info("testBasicSigningTwoKsksSHA1withRSA");
       testSigning(WORKER_ID, WORKER_NAME, 0, null, 18, 2, false, false, "SHA1WithRSA", Algorithm.RSA_NSEC3_SHA1);
   }

   /**
    * Basic test case using two active KSKs, using SHA512withRSA.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsksSHA512withRSA() throws Exception {
       LOG.info("testBasicSigningTwoKsksSHA512withRSA");
       testSigning(WORKER_ID, WORKER_NAME, 0, null, 18, 2, false, false, "SHA512WithRSA", Algorithm.RSASHA512);
   }

    @Override
    protected void setupWorkerProperties(int workerId, int numberKsks, String signatureAlgorithm, String cryptoWorkerName) throws Exception {
        tempKeystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileUtils.copyFile(keystore, tempKeystoreFile);
        helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", tempKeystoreFile.getAbsolutePath());
        helper.getWorkerSession().reloadConfiguration(workerId);
        
        // remove existing KSK and ZSK, if already existing
        helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                            "example.com_K_1");
        helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                            "example.com_K_2");
        helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                            "example.com_Z_1");
        helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                            "example.com_Z_2");
        
        super.setupWorkerProperties(workerId, numberKsks, signatureAlgorithm, cryptoWorkerName);
    }

    @Override
    protected void setupCryptoTokenProperties(int tokenId, boolean cache) throws Exception {
        // do nothing here, as we configure the keystore directly on the worker
    }
}
