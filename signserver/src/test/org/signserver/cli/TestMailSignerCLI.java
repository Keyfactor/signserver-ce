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

import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Class used to test the basic aspects of the SignServer CLI such
 * as get status, activate, set properties etc..
 * 
 * 
 * @author Philip Vendil 21 okt 2007
 *
 * @version $Id: TestMailSignerCLI.java,v 1.3 2007-12-29 10:44:26 herrvendil Exp $
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

		TestUtils.assertSuccessfulExecution(new String[] {"noarguments"});
		assertTrue(TestUtils.grepTempOut("Usage: signserver"));
		
				
		TestUtils.assertSuccessfulExecution(new String[] {"setproperty",
                "global",
                "WORKER" + TESTID + ".CLASSPATH",
                "org.signserver.server.signers.TimeStampSigner"});
		
		TestUtils.assertSuccessfulExecution(new String[] {"getconfig",
                "global"});	
		
		assertTrue(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));
		
		TestUtils.assertSuccessfulExecution(new String[] {"setproperty",
                TESTID,
                "TESTKEY",
                "TESTVALUE"});	
		
		TestUtils.assertSuccessfulExecution(new String[] {"getconfig",
        TESTID});
		
		assertTrue(TestUtils.grepTempOut("TESTKEY"));
		
		TestUtils.assertSuccessfulExecution(new String[] {"removeproperty",
                TESTID,
                "TESTKEY"});
		TestUtils.assertSuccessfulExecution(new String[] {"removeproperty",
                "global",
                "WORKER" + TESTID + ".CLASSPATH"});

		TestUtils.assertSuccessfulExecution(new String[] {"getconfig",
		        "global"});
		assertFalse(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));

		TestUtils.assertSuccessfulExecution(new String[] {"getconfig",
		        "" + TESTID});		
		assertFalse(TestUtils.grepTempOut("TESTKEY"));
		
		TestUtils.assertSuccessfulExecution(new String[] {"getconfig", 
				"-host",
				"localhost",
		        "" + TESTID});

		TestingSecurityManager.remove();
	}
	
	public void testSetupDummyMailSigner() {
			TestUtils.assertSuccessfulExecution(new String[] {"setproperties",
					signserverhome +"/src/test/test_add_dummymailsigner_configuration.properties"});		
			assertTrue(TestUtils.grepTempOut("Setting the property NAME to dummyMailSigner1000 for worker 1000"));

			TestUtils.assertSuccessfulExecution(new String[] {"getstatus",
					"complete",
					TESTTSID});	

			TestUtils.assertSuccessfulExecution(new String[] {"setproperty",
					TESTTSID,
					"TESTKEY",
			"TESTVALUE"});	

			TestUtils.assertSuccessfulExecution(new String[] {"getstatus",
					"complete",
					TESTTSID});	
			assertFalse(TestUtils.grepTempOut("TESTKEY"));

			TestUtils.assertSuccessfulExecution(new String[] {"reload",
					TESTTSID});
			assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));


			TestUtils.assertSuccessfulExecution(new String[] {"getstatus",
					"complete",
					TESTTSID});	
			assertTrue(TestUtils.grepTempOut("NAME=dummyMailSigner1000"));
			assertTrue(TestUtils.grepTempOut("TESTKEY"));

			// Test token operations
			TestUtils.assertFailedExecution(new String[] {"activatesigntoken",
					TESTTSID,
			"9876"});
			TestUtils.assertSuccessfulExecution(new String[] {"activatesigntoken",
					TESTTSID,
			"1234"});
			assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));


			TestUtils.assertSuccessfulExecution(new String[] {"deactivatesigntoken",
					TESTTSID});
			assertTrue(TestUtils.grepTempOut("Deactivation of worker was successful"));


			// Test operations by name
			TestUtils.assertSuccessfulExecution(new String[] {"activatecryptotoken",
					"dummyMailSigner1000",
			"1234"});
			assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));
			TestUtils.assertSuccessfulExecution(new String[] {"activatecryptotoken",
					"DUMMYMAILSIGNER1000",
			"1234"});
			TestUtils.assertFailedExecution(new String[] {"activatecryptotoken",
					"DUMMYMAILSIGNER2000",
			"1234"});
			
			
			TestUtils.assertSuccessfulExecution(new String[] {"addauthorizeduser",
					"test1",
					"pwd1"});	
			TestUtils.assertSuccessfulExecution(new String[] {"listauthorizedusers"});
			assertTrue(TestUtils.grepTempOut("TEST1"));
			
			TestUtils.assertSuccessfulExecution(new String[] {"removeauthorizeduser",
					"test1"});	
			TestUtils.assertSuccessfulExecution(new String[] {"listauthorizedusers"});
			assertFalse(TestUtils.grepTempOut("TEST1"));
			
			// Dump
			TestUtils.assertSuccessfulExecution(new String[] {"dumpproperties",
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
		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
				"dummyMailSigner1000"});		
		assertTrue(TestUtils.grepTempOut("Property 'NAME' removed"));
		
		TestUtils.assertSuccessfulExecution(new String[] {"getconfig",
                TESTTSID});	
         assertFalse(TestUtils.grepTempOut("NAME=dummyMailSigner1000"));
		
 		TestUtils.assertSuccessfulExecution(new String[] {"removeproperty",
                TESTTSID,
                "TESTKEY"});
         
		TestUtils.assertSuccessfulExecution(new String[] {"reload",
				TESTTSID});
		assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));
         

		TestingSecurityManager.remove();
	}
	




}
