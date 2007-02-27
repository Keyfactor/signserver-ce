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

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;

import junit.framework.TestCase;

import org.signserver.common.GlobalConfiguration;

public class TestGlobalConfiguration extends TestCase {

	private static IGlobalConfigurationSession globalConfigSession = null;
	
	protected void setUp() throws Exception {
		super.setUp();
			    
		globalConfigSession = getHome().create();
	}
	
    /**
     * Get the initial naming context
     */
    protected Context getInitialContext() throws Exception {
    	Hashtable props = new Hashtable();
    	props.put(
    		Context.INITIAL_CONTEXT_FACTORY,
    		"org.jnp.interfaces.NamingContextFactory");
    	props.put(
    		Context.URL_PKG_PREFIXES,
    		"org.jboss.naming:org.jnp.interfaces");
    	props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
    	Context ctx = new InitialContext(props);
    	return ctx;
    }

    /**
     * Get the home interface
     */
    protected org.signserver.ejb.IGlobalConfigurationSessionHome getHome() throws Exception {
    	Context ctx = this.getInitialContext();
    	Object o = ctx.lookup("GlobalConfigurationSession");
    	org.signserver.ejb.IGlobalConfigurationSessionHome intf = (org.signserver.ejb.IGlobalConfigurationSessionHome) PortableRemoteObject
    		.narrow(o, org.signserver.ejb.IGlobalConfigurationSessionHome.class);
    	return intf;
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
