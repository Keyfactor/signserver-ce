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

package org.signserver.groupkeyservice;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.groupkeyservice.common.DocumentIDRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyResponse;
import org.signserver.groupkeyservice.common.GroupKeyServiceConstants;
import org.signserver.groupkeyservice.common.GroupKeyServiceStatus;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyResponse;
import org.signserver.groupkeyservice.common.TimeRemoveGroupKeyRequest;


public class TestGroupKeyService extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
	private static long startNumOfKeys;
	private static long startNumOfAssKeys;
	private static long startNumOfUnassKeys;
	private static String startEncKeyRef;
	private static long keysToGen = 7;
	private static long rSAkeysToGen = 3;
	private static Random rand = new Random();
	private static Date startDate = new Date();
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
                gCSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
		sSSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
	}
	
	public void test00SetupDatabase() throws Exception{
		   
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER10.CLASSPATH", "org.signserver.groupkeyservice.server.GroupKeyServiceWorker");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER10.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.ExtendedHardCodedCryptoToken");
		  
		  
		  sSSession.setWorkerProperty(10, "AUTHTYPE", "NOAUTH");
		  sSSession.setWorkerProperty(10, GroupKeyServiceConstants.GROUPKEYDATASERVICE_KEYSWITCHTHRESHOLD, "30");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER12.CLASSPATH", "org.signserver.groupkeyservice.server.GroupKeyServiceWorker");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER12.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.ExtendedHardCodedCryptoToken");
		  		  
		  sSSession.setWorkerProperty(12, "AUTHTYPE", "NOAUTH");		  
		  sSSession.setWorkerProperty(12, GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYALG, "RSA");
		  sSSession.setWorkerProperty(12, GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYSPEC, "2048");

		  sSSession.reloadConfiguration(10);		  
		  sSSession.reloadConfiguration(12);
		  
	}




	public void test01GetStatus() throws Exception {
		
		
		GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);	
		startNumOfKeys = stat.getNumOfKeys();
		startNumOfAssKeys = stat.getNumOfAssignedKeys();
		startNumOfUnassKeys = stat.getNumOfUnassignedKeys();
		startEncKeyRef = stat.getCurrentEncKeyRef();
		

	}
	
	public void test02PregenerateKeys() throws Exception{
		
		
		PregenerateKeysRequest req = new PregenerateKeysRequest((int) keysToGen);
		PregenerateKeysResponse res = (PregenerateKeysResponse) sSSession.process(10, req, new RequestContext());
		assertTrue(res.getNumberOfKeysGenerated() == keysToGen);
		GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);	
		assertTrue(stat.getNumOfKeys() == startNumOfKeys + keysToGen);
		assertTrue(stat.getNumOfAssignedKeys() == startNumOfAssKeys);
		assertTrue(stat.getNumOfUnassignedKeys() == startNumOfUnassKeys + keysToGen);
		assertTrue(stat.getCurrentEncKeyRef() != null);
	}
	
	public void test03FetchKey() throws Exception{
		
		long keysToFetch = 7;
		
		for(int i=0;i<keysToFetch;i++){
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
		}
		GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);	
		assertTrue(stat.getNumOfKeys() == startNumOfKeys + keysToGen);
		assertTrue(stat.getNumOfAssignedKeys() == startNumOfAssKeys + keysToFetch);
		assertTrue(stat.getNumOfUnassignedKeys() == startNumOfUnassKeys );
		assertTrue(stat.getCurrentEncKeyRef() != null);
		
		// Run until UnassKeys are 0
		long unAssignedKeys = stat.getNumOfUnassignedKeys();
		while(unAssignedKeys > 0){
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
			unAssignedKeys--;
		}
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(stat.getNumOfUnassignedKeys()==0);
	   
		// Fetch a new key if pregenerated keys are 0
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		long assignedKeys = stat.getNumOfAssignedKeys();
		fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(stat.getNumOfAssignedKeys() == (assignedKeys +1));
		
		try{
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_PRIVATE,true);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		try{
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_PUBLIC,true);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		// test genIfKeyNotExists flag
		try{
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,false);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		String docId = "docId" + Integer.toHexString(rand.nextInt());		
		byte[] keyData = fetchKey(docId, rand, GroupKeyServiceConstants.KEYPART_SYMMETRIC, true);
		byte[] keyData2 = fetchKey(docId, rand, GroupKeyServiceConstants.KEYPART_SYMMETRIC, true);
		assertTrue(Arrays.equals(keyData, keyData2));
		byte[] keyData3 = fetchKey(docId, rand, GroupKeyServiceConstants.KEYPART_SYMMETRIC, false);
		assertTrue(Arrays.equals(keyData, keyData3));
			
	}
	
	public void test04SwitchEncKey() throws Exception{
		// Test key switch manually
		SwitchEncKeyRequest req = new SwitchEncKeyRequest();
		SwitchEncKeyResponse res = (SwitchEncKeyResponse) sSSession.process(10, req, new RequestContext());
		String newKeyIndex = res.getNewKeyIndex();
        assertFalse(newKeyIndex.equals(startEncKeyRef));
        GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
        assertTrue(stat.getCurrentEncKeyRef().equals(newKeyIndex));
        assertTrue(stat.getCurrentEncKeyNumEncryptions() == 0);
        assertTrue(stat.getCurrentEncKeyStartDate().before(new Date()));
        assertTrue(stat.getCurrentEncKeyStartDate().after(new Date(System.currentTimeMillis() - 4000)));

        // Test key switch automatically
		for(int i=0;i<20;i++){
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
		}
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
        assertTrue(stat.getCurrentEncKeyRef().equals(newKeyIndex));
        assertTrue(stat.getCurrentEncKeyNumEncryptions() == 20);
        
		for(int i=0;i<11;i++){
			fetchKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
		}
		
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
        assertFalse(stat.getCurrentEncKeyRef().equals(newKeyIndex));
        assertTrue(stat.getCurrentEncKeyNumEncryptions() == 1);
        assertTrue(stat.getCurrentEncKeyStartDate().before(new Date()));
        assertTrue(stat.getCurrentEncKeyStartDate().after(new Date(System.currentTimeMillis() - 4000)));        
		
	}
	

	public void test05RemoveKeys() throws Exception{
		// test to remove by documentId
		
		String docId1 = "docId" + Integer.toHexString(rand.nextInt());
		String docId2 = "docId" + Integer.toHexString(rand.nextInt());
		fetchKey(docId1, rand, GroupKeyServiceConstants.KEYPART_SYMMETRIC, true);
		fetchKey(docId2, rand, GroupKeyServiceConstants.KEYPART_SYMMETRIC, true);
		
		GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		long numOfKeys = stat.getNumOfKeys();
		
		ArrayList<String> list = new ArrayList<String>();
		list.add(docId1);
		list.add(docId2);
		DocumentIDRemoveGroupKeyRequest req = new DocumentIDRemoveGroupKeyRequest(list);
		RemoveGroupKeyResponse res = (RemoveGroupKeyResponse) sSSession.process(10, req, new RequestContext());
		assertTrue(res.getNumOfKeysRemoved() == 2);
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(numOfKeys-2 == stat.getNumOfKeys());		
		// test to remove by time
		
		TimeRemoveGroupKeyRequest req2 = new TimeRemoveGroupKeyRequest(TimeRemoveGroupKeyRequest.TYPE_CREATIONDATE,startDate,new Date());
		res = (RemoveGroupKeyResponse) sSSession.process(10, req2, new RequestContext());
		assertTrue(res.wasOperationSuccessful());
		assertTrue(res.getNumOfKeysRemoved() > 0);
		stat = (GroupKeyServiceStatus) sSSession.getStatus(10);
		assertTrue(startNumOfKeys == startNumOfKeys);

	}
	
	public void test06PregenerateRSAKeys() throws Exception{
		GroupKeyServiceStatus orgstat = (GroupKeyServiceStatus) sSSession.getStatus(12);
		
		PregenerateKeysRequest req = new PregenerateKeysRequest((int) rSAkeysToGen);
		PregenerateKeysResponse res = (PregenerateKeysResponse) sSSession.process(12, req, new RequestContext());
		assertTrue(res.getNumberOfKeysGenerated() == rSAkeysToGen);
		
		GroupKeyServiceStatus stat = (GroupKeyServiceStatus) sSSession.getStatus(12);
		
		assertTrue(stat.getNumOfKeys() == orgstat.getNumOfKeys() + rSAkeysToGen);
	}
	
	public void test07FetchRSAKeys() throws Exception{
		long keysToFetch = 4;
		
		for(int i=0;i<keysToFetch;i++){
			fetchRSAKey(rand,GroupKeyServiceConstants.KEYPART_PRIVATE,true);
		}
		

		try{
			fetchRSAKey(rand,GroupKeyServiceConstants.KEYPART_SYMMETRIC,true);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		String docId = "docId" + Integer.toHexString(rand.nextInt());		
		byte[] privKeyData = fetchRSAKey(docId, rand, GroupKeyServiceConstants.KEYPART_PRIVATE, true);
		byte[] pubKeyData = fetchRSAKey(docId, rand, GroupKeyServiceConstants.KEYPART_PUBLIC, true);
		
		X509EncodedKeySpec pkKeySpec = new X509EncodedKeySpec(pubKeyData);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(pkKeySpec);
		
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyData);
		keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
		
		byte[] data = new byte[117];
		for (int i = 0; i < data.length; i++) {
			data[i] = 1;			
		}
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] encdata = c.doFinal(data);
		
		assertFalse(Arrays.equals(data, encdata));
		
		c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, privKey);
		byte[] data2 = c.doFinal(encdata);
		
		assertTrue(Arrays.equals(data, data2));
		
	}
	

	public void test99TearDownDatabase() throws Exception{
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER10.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER10.SIGNERTOKEN.CLASSPATH");
		
		  
		  sSSession.removeWorkerProperty(10, "AUTHTYPE");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER12.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER12.SIGNERTOKEN.CLASSPATH");
		  		  
		  sSSession.removeWorkerProperty(12, "AUTHTYPE");		  
		  sSSession.removeWorkerProperty(12, GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYALG);
		  sSSession.removeWorkerProperty(12, GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYSPEC);
		  
		  sSSession.reloadConfiguration(10);
		  sSSession.reloadConfiguration(12);
	}

	private void fetchKey(Random rand, int keyPart, boolean genKeyIfNotExists) throws Exception{
		fetchKey(null,rand,keyPart,genKeyIfNotExists);
		
	}
	private byte[] fetchKey(String documentId, Random rand, int keyPart, boolean genKeyIfNotExists) throws Exception{
		if(documentId == null){
			documentId = "docId" + Integer.toHexString(rand.nextInt());
		}
		FetchKeyRequest req = new FetchKeyRequest(documentId,keyPart,genKeyIfNotExists);
		FetchKeyResponse res = (FetchKeyResponse) sSSession.process(10, req, new RequestContext());
		assertTrue(res.getDocumentId().equals(documentId));
		byte[] orgdata2 = "HELLO2".getBytes();
		SecretKey key = new SecretKeySpec(res.getGroupKey(),"AES");
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, key);
		c.doFinal(orgdata2);
		return res.getGroupKey();
	}
	
	private void fetchRSAKey(Random rand, int keyPart, boolean genKeyIfNotExists) throws Exception{
		fetchRSAKey(null,rand,keyPart,genKeyIfNotExists);
		
	}
	private byte[] fetchRSAKey(String documentId, Random rand, int keyPart, boolean genKeyIfNotExists) throws Exception{
		if(documentId == null){
			documentId = "docId" + Integer.toHexString(rand.nextInt());
		}
		FetchKeyRequest req = new FetchKeyRequest(documentId,keyPart,genKeyIfNotExists);
		FetchKeyResponse res = (FetchKeyResponse) sSSession.process(12, req, new RequestContext());
		assertTrue(res.getDocumentId().equals(documentId));
		if(keyPart == GroupKeyServiceConstants.KEYPART_PRIVATE){
		  PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(res.getGroupKey());
		  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		  keyFactory.generatePrivate(pkKeySpec);
		}
		if(keyPart == GroupKeyServiceConstants.KEYPART_PUBLIC){
			X509EncodedKeySpec pkKeySpec = new X509EncodedKeySpec(res.getGroupKey());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			keyFactory.generatePublic(pkKeySpec);
		}
		return res.getGroupKey();
	}

}
