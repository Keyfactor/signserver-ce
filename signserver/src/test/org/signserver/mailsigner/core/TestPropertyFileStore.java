package org.signserver.mailsigner.core;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;
import org.signserver.server.PropertyFileStore;

import junit.framework.TestCase;

public class TestPropertyFileStore extends TestCase {

	public void testSetGlobalProperty() {		
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		properties.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTKEY1", "VALUE");
		properties.setGlobalProperty(GlobalConfiguration.SCOPE_NODE, "TESTKEY2", "VALUE2");		
	}

	public void testGetGlobalConfiguration() {
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		GlobalConfiguration gc = properties.getGlobalConfiguration();
		
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTKEY1").equals("VALUE"));
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TESTKEY2").equals("VALUE2"));
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TESTKEY1"));
	}
	
	public void testRemoveGlobalProperty() {
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		properties.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTKEY1");
		properties.reload();
		GlobalConfiguration gc = properties.getGlobalConfiguration();
				
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TESTKEY2").equals("VALUE2"));
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTKEY1"));
	}

	public void testSetWorkerProperty() {
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		properties.setWorkerProperty(1, "W1TESTKEY1", "W1TESTVALUE1");
		properties.setWorkerProperty(1, "W1TESTKEY2", "W1TESTVALUE2");
		properties.setWorkerProperty(2, "W2TESTKEY1", "W2TESTVALUE1");
	}

	
	public void testGetWorkerProperties() {
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		WorkerConfig wc = properties.getWorkerProperties(1);
		
		assertTrue(wc.getProperties().keySet().size() == 2);
		assertTrue(wc.getProperties().getProperty("W1TESTKEY1").equals("W1TESTVALUE1"));
		assertTrue(wc.getProperties().getProperty("W1TESTKEY2").equals("W1TESTVALUE2"));
		assertNull(wc.getProperties().getProperty("W2TESTKEY1"));
		
	}
	
	public void testRemoveWorkerProperty() {
		PropertyFileStore properties = PropertyFileStore.getInstance("tmp/testproperties.properties");
		properties.removeWorkerProperty(1, "W1TESTKEY1");
		
		WorkerConfig wc = properties.getWorkerProperties(1);
		assertTrue(wc.getProperties().keySet().size() == 1);		
		assertTrue(wc.getProperties().getProperty("W1TESTKEY2").equals("W1TESTVALUE2"));
		assertNull(wc.getProperties().getProperty("W1TESTKEY1"));
	}


}
