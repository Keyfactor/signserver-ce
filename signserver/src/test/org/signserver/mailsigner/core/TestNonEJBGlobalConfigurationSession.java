package org.signserver.mailsigner.core;

import org.signserver.common.GlobalConfiguration;
import org.signserver.mailsigner.mailsigners.DummyMailSigner;
import org.signserver.server.PropertyFileStore;

import junit.framework.TestCase;

public class TestNonEJBGlobalConfigurationSession extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
		
		// Special trick to set up the backend properties from a specified
		// file.
		PropertyFileStore.getInstance("tmp/testproperties.properties");
	}

	public void testSetProperty() {
		NonEJBGlobalConfigurationSession gcs = NonEJBGlobalConfigurationSession.getInstance();
		
		gcs.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1", "123456");
		
		GlobalConfiguration gc = gcs.getGlobalConfiguration();
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1").equals("123456"));
		gcs.reload();
		gc = gcs.getGlobalConfiguration();
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1").equals("123456"));
		
		
	}

	public void testRemoveProperty() {
		NonEJBGlobalConfigurationSession gcs = NonEJBGlobalConfigurationSession.getInstance();
		
		gcs.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1");
		
		GlobalConfiguration gc = gcs.getGlobalConfiguration();
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1"));
		gcs.reload();
		gc = gcs.getGlobalConfiguration();
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "GCTEST1"));
		
	}



	public void testGetWorkers() {		
		NonEJBGlobalConfigurationSession gcs = NonEJBGlobalConfigurationSession.getInstance();
		
		gcs.setProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + "99" + GlobalConfiguration.WORKERPROPERTY_CLASSPATH , DummyMailSigner.class.getName());
		gcs.setProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + "100" + GlobalConfiguration.WORKERPROPERTY_CLASSPATH , DummyMailSigner.class.getName());
		
		assertTrue(gcs.getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS).size() >= 2);
		assertTrue(gcs.getWorkers(GlobalConfiguration.WORKERTYPE_ALL).size() >= 2);
		assertTrue(""+gcs.getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES).size(), gcs.getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES).size() == 0);
	}



}
