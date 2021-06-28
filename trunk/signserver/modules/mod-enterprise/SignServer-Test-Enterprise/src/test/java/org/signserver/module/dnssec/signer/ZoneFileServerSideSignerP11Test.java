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

import java.io.FileNotFoundException;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.xbill.DNS.DNSSEC.Algorithm;

/**
 * System tests for the ZoneFileServerSideSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileServerSideSignerP11Test extends ZoneFileServerSideSignerTestBase {
   /**
    * Logger for this class.
    */
   private static final Logger LOG = Logger.getLogger(ZoneFileServerSideSignerP11Test.class);

   private static final int WORKER_ID = 18901;
   private static final String WORKER_NAME = "TestZoneFileServerSideSigner";
   private static final String SAMPLE_ZONE_FILE = "res/test/example.com.zone";

   private static final int CRYPTO_TOKEN = 13100;
   private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenZoneFileServerSideSignerP11";

   private final WorkerSession workerSession = helper.getWorkerSession();

   private final String sharedLibraryName;
   private final String slot;
   private final String pin;
   private final String existingKey1;
   
   public ZoneFileServerSideSignerP11Test() throws FileNotFoundException {
       sharedLibraryName = helper.getConfig().getProperty("test.p11.sharedLibraryName");
       slot = helper.getConfig().getProperty("test.p11.slot");
       pin = helper.getConfig().getProperty("test.p11.pin");
       existingKey1 = helper.getConfig().getProperty("test.p11.existingkey1");
   }

   @Override
   protected void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

   /**
    * Basic test case using two active KSKs.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsks() throws Exception {
       LOG.info("testBasicSigningTwoKsks");
       testSigning(WORKER_ID, WORKER_NAME, CRYPTO_TOKEN, CRYPTO_TOKEN_NAME,
                   18, 2, false, false, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case using one active KSK.
    * @throws Exception 
    */
   @Test
   public void testBasicSigningOneKsk() throws Exception {
       LOG.info("testBasicSigningOneKsk");
       testSigning(WORKER_ID, WORKER_NAME, CRYPTO_TOKEN, CRYPTO_TOKEN_NAME,
                   17, 1, false, false, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case with only one ZSK.
    * Should give a runtime failure when signing.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningOneZsk() throws Exception {
       LOG.info("testBasicSigningOneKsk");
       // deliberatly specify a nonse expected verified signatures
       testSigning(WORKER_ID, WORKER_NAME, CRYPTO_TOKEN, CRYPTO_TOKEN_NAME,
                   -1, 2, true, true, null, Algorithm.RSASHA256);
   }

   /**
    * Basic test case using two active KSKs, using SHA1withRSA.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsksSHA1withRSA() throws Exception {
       LOG.info("testBasicSigningTwoKsksSHA1withRSA");
       testSigning(WORKER_ID, WORKER_NAME, CRYPTO_TOKEN, CRYPTO_TOKEN_NAME,
                   18, 2, false, false, "SHA1WithRSA", Algorithm.RSA_NSEC3_SHA1);
   }

   /**
    * Basic test case using two active KSKs, using SHA512withRSA.
    * 
    * @throws Exception 
    */
   @Test
   public void testBasicSigningTwoKsksSHA512withRSA() throws Exception {
       LOG.info("testBasicSigningTwoKsksSHA512withRSA");
       testSigning(WORKER_ID, WORKER_NAME, CRYPTO_TOKEN, CRYPTO_TOKEN_NAME,
                   18, 2, false, false, "SHA512WithRSA", Algorithm.RSASHA512);
   }
}
