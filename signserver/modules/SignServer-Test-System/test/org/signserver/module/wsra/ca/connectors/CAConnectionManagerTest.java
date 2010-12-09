package org.signserver.module.wsra.ca.connectors;

import java.util.Properties;

import junit.framework.TestCase;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.ca.connectors.dummy.DummyCAConnector;
import org.signserver.module.wsra.common.WSRAConstants;

public class CAConnectionManagerTest extends TestCase {

	private Properties workerProperties;

	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		
		workerProperties = new Properties();
		workerProperties.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+1+"." +WSRAConstants.SETTING_CACONNECTOR_CLASSPATH, DummyCAConnector.class.getName());
		workerProperties.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+1+"." +DummyCAConnector.ISSUER_PREFIX+1+DummyCAConnector.DN_SETTING, "CN=test1,OU=test2");
		workerProperties.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+1+"." +DummyCAConnector.ISSUER_PREFIX+4+DummyCAConnector.DN_SETTING, "CN=test2,OU=test2");
		workerProperties.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+10+"."+WSRAConstants.SETTING_CACONNECTOR_CLASSPATH, DummyCAConnector.class.getName());
		workerProperties.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+10+"." +DummyCAConnector.ISSUER_PREFIX+2+DummyCAConnector.DN_SETTING, "CN=test4,OU=test2");
		workerProperties.setProperty("TESTKEY", "TESTDATA");
		

	}

	public void test01GetConnectorProperties() {
		Properties props = CAConnectionManager.getConnectorProperties(1, workerProperties);
		
		assertTrue(props.getProperty(WSRAConstants.SETTING_CACONNECTOR_CLASSPATH), props.getProperty(WSRAConstants.SETTING_CACONNECTOR_CLASSPATH).equals(DummyCAConnector.class.getName()));
		assertTrue(props.getProperty(DummyCAConnector.ISSUER_PREFIX+1+DummyCAConnector.DN_SETTING).equals("CN=test1,OU=test2"));
		assertTrue(props.getProperty(DummyCAConnector.ISSUER_PREFIX+4+DummyCAConnector.DN_SETTING).equals("CN=test2,OU=test2"));
		
		props = CAConnectionManager.getConnectorProperties(10, workerProperties);
		assertTrue(props.getProperty(WSRAConstants.SETTING_CACONNECTOR_CLASSPATH).equals(DummyCAConnector.class.getName()));
		assertTrue(props.getProperty(DummyCAConnector.ISSUER_PREFIX+2+DummyCAConnector.DN_SETTING).equals("CN=test4,OU=test2"));
		
		props = CAConnectionManager.getConnectorProperties(3, workerProperties);
		assertNull(props);
	}
	
	public void test02GetCAConnector() throws IllegalRequestException, SignServerException {
		CAConnectionManager mgr = new CAConnectionManager(1,workerProperties,null);
		assertTrue(mgr.getCAConnector("CN=test1,OU=test2").getCACertificateChain("CN=test1,OU=test2").get(0).getSubject().equals("CN=test1,OU=test2"));
		
		try{
  		  mgr.getCAConnector("CN=testnotexists,OU=test2");
  		  assertTrue(false);
		}catch(IllegalRequestException e){}
	}



}
