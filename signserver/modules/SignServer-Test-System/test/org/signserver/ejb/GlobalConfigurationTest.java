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

package org.signserver.ejb;

import junit.framework.TestCase;

import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceLocator;

public class GlobalConfigurationTest extends TestCase {

	private static IGlobalConfigurationSession.IRemote  globalConfigSession;
	
	private static String signserverhome;
	
	protected void setUp() throws Exception {
		super.setUp();
			    
		globalConfigSession = ServiceLocator.getInstance().lookupRemote(
                    IGlobalConfigurationSession.IRemote.class);

		signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);
	}

	/*
	 * Test method for 'org.signserver.common.GlobalConfigurationFileParser.getBaseProperty(String)'
	 */
	public void test01SetProperty() throws Exception {				
		GlobalConfiguration gc = globalConfigSession.getGlobalConfiguration();
		
		globalConfigSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST", "TESTVALUE");
		globalConfigSession.setProperty(GlobalConfiguration.SCOPE_NODE, "TEST2", "TESTVALUE");
		gc = globalConfigSession.getGlobalConfiguration();
		assertTrue(gc != null);
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST").equals("TESTVALUE"));
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TEST") == null);       


		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TEST2").equals("TESTVALUE"));
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST2") == null);

		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "WORKER1.CLASSPATH") == null);

		globalConfigSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST");
		gc = globalConfigSession.getGlobalConfiguration();
	}


}
