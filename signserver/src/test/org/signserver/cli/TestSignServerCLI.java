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
 
package org.signserver.cli;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import junit.framework.TestCase;

import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.TimeStampClient;
import org.signserver.testutils.ExitException;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Class used to test the basic aspects of the SignServer CLI such
 * as get status, activate, set properties etc..
 * 
 * 
 * @author Philip Vendil 21 okt 2007
 *
 * @version $Id: TestSignServerCLI.java,v 1.4 2007-12-13 12:49:55 herrvendil Exp $
 */

public class TestSignServerCLI extends TestCase {

	private static final String TESTID = "100";
	private static final String TESTTSID = "1000";
	
	private static String signserverhome;
	protected void setUp() throws Exception {
		super.setUp();
		
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}
	
	public void testBasicSetup() throws Exception{

		assertSuccessfulExecution(new String[] {"noarguments"});
		assertTrue(TestUtils.grepTempOut("Usage: signserver"));
		
				
		assertSuccessfulExecution(new String[] {"setproperty",
                "global",
                "WORKER" + TESTID + ".CLASSPATH",
                "org.signserver.server.signers.TimeStampSigner"});
		
		assertSuccessfulExecution(new String[] {"getconfig",
                "global"});	
		
		assertTrue(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));
		
		assertSuccessfulExecution(new String[] {"setproperty",
                TESTID,
                "TESTKEY",
                "TESTVALUE"});	
		
		assertSuccessfulExecution(new String[] {"getconfig",
        TESTID});
		
		assertTrue(TestUtils.grepTempOut("TESTKEY"));
		
		assertSuccessfulExecution(new String[] {"removeproperty",
                "" + TESTID,
                "TESTKEY"});
		assertSuccessfulExecution(new String[] {"removeproperty",
                "global",
                "WORKER" + TESTID + ".CLASSPATH"});

		assertSuccessfulExecution(new String[] {"getconfig",
		        "global"});
		assertFalse(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));

		assertSuccessfulExecution(new String[] {"getconfig",
		        "" + TESTID});		
		assertFalse(TestUtils.grepTempOut("TESTKEY"));
		
		assertSuccessfulExecution(new String[] {"getconfig", 
				"-host",
				"localhost",
		        "" + TESTID});
		TestingSecurityManager.remove();
	}
	
	public void testSetupTimeStamp() throws Exception{
		assertSuccessfulExecution(new String[] {"reload",
				"all"});
		
		assertTrue(new File(signserverhome +"/src/test/test_add_timestamp_configuration.properties").exists());
		assertSuccessfulExecution(new String[] {"setproperties",
				signserverhome +"/src/test/test_add_timestamp_configuration.properties"});		
	    assertTrue(TestUtils.grepTempOut("Setting the property NAME to timestampSigner1000 for worker 1000"));
		
	    assertSuccessfulExecution(new String[] {"getstatus",
                "complete",
                TESTTSID});	
       
		assertSuccessfulExecution(new String[] {"setproperty",
				TESTTSID,
                "TESTKEY",
                "TESTVALUE"});	
		
	    assertSuccessfulExecution(new String[] {"getstatus",
                "complete",
                TESTTSID});	
	    
		assertSuccessfulExecution(new String[] {"reload",
				TESTTSID});
		assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));
		
		
		assertSuccessfulExecution(new String[] {"getstatus",
		                                        "complete",
		                                        TESTTSID});	
		assertTrue(TestUtils.grepTempOut("NAME=timestampSigner1000"));
		assertTrue(TestUtils.grepTempOut("TESTKEY"));
	    
	    
		assertSuccessfulExecution(new String[] {"reload",
				TESTTSID});
		assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));
		
		
		assertSuccessfulExecution(new String[] {"getstatus",
		                                        "complete",
		                                        TESTTSID});	
		assertTrue(TestUtils.grepTempOut("NAME=timestampSigner1000"));
		
		// Test token operations
		assertFailedExecution(new String[] {"activatesigntoken",
				TESTTSID,
                "9876"});
		assertSuccessfulExecution(new String[] {"activatesigntoken",
				TESTTSID,
                "1234"});
		assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));
		
		
		assertSuccessfulExecution(new String[] {"deactivatesigntoken",
				TESTTSID});
		assertTrue(TestUtils.grepTempOut("Deactivation of worker was successful"));
		
		
        // Test operations by name
		assertSuccessfulExecution(new String[] {"activatecryptotoken",
				"timestampSigner1000",
                "1234"});
		assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));
		assertSuccessfulExecution(new String[] {"activatecryptotoken",
				"TIMESTAMPSIGNER1000",
                "1234"});
		assertFailedExecution(new String[] {"activatecryptotoken",
				"TIMESTAMPSIGNER2000",
                "1234"});
		
		// Test authorized clients
		assertSuccessfulExecution(new String[] {"addauthorizedclient",
				"TIMESTAMPSIGNER1000",
                "EF34242D2324",
                "CN=Test Root CA"});
		assertTrue(TestUtils.grepTempOut("Adding the client certificate with sn EF34242D2324"));
		
		assertSuccessfulExecution(new String[] {"listauthorizedclients",
				"TIMESTAMPSIGNER1000"});
		assertTrue(TestUtils.grepTempOut("ef34242d2324, CN=Test Root CA"));
		
		assertSuccessfulExecution(new String[] {"removeauthorizedclient",
				"TIMESTAMPSIGNER1000",
                "EF34242D2324",
                "CN=Test Root CA"});
		assertTrue(TestUtils.grepTempOut("Client Removed"));
		
		assertSuccessfulExecution(new String[] {"listauthorizedclients",
		"TIMESTAMPSIGNER1000"});
        assertFalse(TestUtils.grepTempOut("ef34242d2324, CN=Test Root CA"));
		
		
		// Dump
		assertSuccessfulExecution(new String[] {"dumpproperties",
				"TIMESTAMPSIGNER1000",
                signserverhome + "/tmp/testdump.properties"});		
		assertTrue(TestUtils.grepTempOut("Properties successfully dumped into file"));
		
		
		Properties props = new Properties();
		props.load(new FileInputStream(signserverhome + "/tmp/testdump.properties"));
		assertNotNull(props.get("WORKER1000.AUTHTYPE"));
		
		// Test the timestamp client
		try {
			TestUtils.flushTempOut();
			TimeStampClient.main(new String[] {
					"http://localhost:8080/signserver/tsa?signerId=" +TESTTSID,
					"-instr", 
					"TEST",
					"-outrep",
					signserverhome + "/tmp/timestamptest.data"});	
			
			FileInputStream fis = new FileInputStream(signserverhome + "/tmp/timestamptest.data");
			TimeStampResponse tsr = new TimeStampResponse(fis);
			assertTrue(tsr != null);
			String archiveId = tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16);
			assertNotNull(archiveId);
			
			assertSuccessfulExecution(new String[] {"archive", 
					                  "findfromarchiveid",
					                  TESTTSID,
					                  archiveId,
					                  signserverhome + "/tmp"});
			File datafile = new File(signserverhome + "/tmp/" +archiveId);
			assertTrue(datafile.exists());
			datafile.delete();
			assertSuccessfulExecution(new String[] {"archive", 
	                  "findfromrequestip",
	                  TESTTSID,
	                  "127.0.0.1",
	                  signserverhome + "/tmp"});
             datafile = new File(signserverhome + "/tmp/" +archiveId);
             assertTrue(datafile.exists());
             			
		}catch(ExitException e) {
			TestUtils.printTempErr();
			TestUtils.printTempOut();
			assertTrue(false);
		}
		
		TestingSecurityManager.remove();
	}
	
	public void testRemoveTimeStamp(){
		// Remove and restore
		assertSuccessfulExecution(new String[] {"setproperties",
				signserverhome +"/src/test/test_rem_timestamp_configuration.properties"});		
		assertTrue(TestUtils.grepTempOut("Removing the property NAME  for worker 1000"));
		
		assertSuccessfulExecution(new String[] {"getconfig",
                TESTTSID});	
         assertFalse(TestUtils.grepTempOut("NAME=timestampSigner1000"));
         
  		assertSuccessfulExecution(new String[] {"removeproperty",
                TESTTSID,
                "TESTKEY"});
		
		assertSuccessfulExecution(new String[] {"reload",
				TESTTSID});
		assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));
         
		TestingSecurityManager.remove();
	}
	
	private void assertSuccessfulExecution(String[] args){
		try {
			TestUtils.flushTempOut();
			signserver.main(args);			
		}catch(ExitException e) {
			TestUtils.printTempErr();
			TestUtils.printTempOut();
			assertTrue(false);
		}		
	}
	
	private void assertFailedExecution(String[] args){
		try {
			TestUtils.flushTempOut();
			signserver.main(args);
			assertTrue(false);
		}catch(ExitException e) {
		}		
	}

}
