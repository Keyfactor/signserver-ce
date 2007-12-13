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

import java.io.FileInputStream;
import java.util.Properties;

import junit.framework.TestCase;

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
 * @version $Id: TestMailSignerCLI.java,v 1.2 2007-12-13 12:49:55 herrvendil Exp $
 */

public class TestMailSignerCLI extends TestCase {

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
        CommonAdminInterface.BUILDMODE = "MAILSIGNER";
	}
	
	public void testBasicSetup() {

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
                TESTID,
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
	
	public void testSetupDummyMailSigner() {
			assertSuccessfulExecution(new String[] {"setproperties",
					signserverhome +"/src/test/test_add_dummymailsigner_configuration.properties"});		
			assertTrue(TestUtils.grepTempOut("Setting the property NAME to dummyMailSigner1000 for worker 1000"));

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
			assertFalse(TestUtils.grepTempOut("TESTKEY"));

			assertSuccessfulExecution(new String[] {"reload",
					TESTTSID});
			assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));


			assertSuccessfulExecution(new String[] {"getstatus",
					"complete",
					TESTTSID});	
			assertTrue(TestUtils.grepTempOut("NAME=dummyMailSigner1000"));
			assertTrue(TestUtils.grepTempOut("TESTKEY"));

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
					"dummyMailSigner1000",
			"1234"});
			assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));
			assertSuccessfulExecution(new String[] {"activatecryptotoken",
					"DUMMYMAILSIGNER1000",
			"1234"});
			assertFailedExecution(new String[] {"activatecryptotoken",
					"DUMMYMAILSIGNER2000",
			"1234"});



			// Dump
			assertSuccessfulExecution(new String[] {"dumpproperties",
					"DUMMYMAILSIGNER1000",
					signserverhome + "/tmp/testdump.properties"});		
			assertTrue(TestUtils.grepTempOut("Properties successfully dumped into file"));


			Properties props = new Properties();
			try {
				props.load(new FileInputStream(signserverhome + "/tmp/testdump.properties"));
			} catch (Exception e) {
				fail(e.getMessage());
			}
			assertNotNull(props.get("WORKER1000.TESTKEY"));


			TestingSecurityManager.remove();
	}
	
	public void testRemoveDummyMailSigner(){

		// Remove and restore
		assertSuccessfulExecution(new String[] {"setproperties",
				signserverhome +"/src/test/test_rem_dummymailsigner_configuration.properties"});		
		assertTrue(TestUtils.grepTempOut("Removing the property NAME  for worker 1000"));
		
		assertSuccessfulExecution(new String[] {"getconfig",
                TESTTSID});	
         assertFalse(TestUtils.grepTempOut("NAME=dummyMailSigner1000"));
		
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
			TestUtils.printTempErr();
			TestUtils.printTempOut();
			assertTrue(false);
		}catch(ExitException e) {
		}		
	}

}
