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
package org.signserver.protocol.ws;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.namespace.QName;

import junit.framework.TestCase;
import org.apache.log4j.Logger;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.tsa.TimeStampSigner;
import org.signserver.protocol.ws.client.ISignServerWSClient;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.ProcessResponseWS;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.server.ICertificateManager;
import org.signserver.validationservice.server.ValidationTestUtils;

public class TestMainWebService extends TestCase {

    private static final Logger LOG = Logger.getLogger(TestMainWebService.class);
    
	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
	private static X509Certificate validCert1;
	private SignServerWS signServerWS;
	private String signserverhome;
	private int moduleVersion;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
                gCSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
		sSSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
		
		QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
		SignServerWSService signServerWSService = new SignServerWSService(new URL("http://localhost:8080/signserver/signserverws/signserverws?wsdl"),qname);
		signServerWS =  signServerWSService.getSignServerWSPort();
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}
	
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
	}
	
	public void test00SetupDatabase() throws Exception{
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/tsa.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/tsa.mar"});		
		assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
		
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.CLASSPATH", "org.signserver.module.tsa.TimeStampSigner");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.P12CryptoToken");


		sSSession.setWorkerProperty(9, "AUTHTYPE", "org.signserver.server.DummyAuthorizer");
		sSSession.setWorkerProperty(9, "TESTAUTHPROP", "DATA");
		sSSession.setWorkerProperty(9, "NAME", "TestTimeStamp");
		String signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);
		sSSession.setWorkerProperty(9,"KEYSTOREPATH",signserverhome +"/src/test/timestamp1.p12");
		//sSSession.setWorkerProperty(9, "KEYSTOREPASSWORD", "foo123");
		sSSession.setWorkerProperty(9,TimeStampSigner.DEFAULTTSAPOLICYOID,"1.0.1.2.33");
		sSSession.setWorkerProperty(9,TimeStampSigner.TSA,"CN=TimeStampTest1");
		sSSession.setWorkerProperty(9,SignServerConstants.MODULENAME,"TSA");
		sSSession.setWorkerProperty(9,SignServerConstants.MODULEVERSION,moduleVersion+"");

		sSSession.reloadConfiguration(9);	

		KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
		validCert1 = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		

		ArrayList<X509Certificate> validChain1 = new ArrayList<X509Certificate>();
		// Add in the wrong order
		validChain1.add(validRootCA1);
		validChain1.add(validSubCA1);

		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");

		sSSession.setWorkerProperty(16, "AUTHTYPE", "NOAUTH");
		sSSession.setWorkerProperty(16, "NAME", "ValTest");
		sSSession.setWorkerProperty(16, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
		sSSession.setWorkerProperty(16, "VAL1.TESTPROP", "TEST");
		sSSession.setWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));

		sSSession.reloadConfiguration(16);		
	}
	
	

	public void test01BasicWSStatuses() throws MalformedURLException, InvalidWorkerIdException_Exception, CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException{
		
	
		List<WorkerStatusWS> statuses = signServerWS.getStatus("9");
		assertTrue(statuses.size() == 1);
		assertTrue(statuses.get(0).getWorkerName().equals("9"));
		assertTrue(statuses.get(0).getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ERROR));
		assertTrue(statuses.get(0).getErrormessage() != null);
		sSSession.activateSigner(9, "foo123");
		statuses = signServerWS.getStatus("TestTimeStamp");
		assertTrue(statuses.size() == 1);
		assertTrue(statuses.get(0).getWorkerName().equals("TestTimeStamp"));
		assertTrue(statuses.get(0).getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ALLOK));
		assertTrue(statuses.get(0).getErrormessage() == null);
		
		statuses = signServerWS.getStatus(ISignServerWS.ALLWORKERS);
                final StringBuilder sb = new StringBuilder();
                for (WorkerStatusWS stat : statuses) {
                    sb.append(stat.getWorkerName());
                    sb.append(", ");
                }
                LOG.info("Got status for: " + sb.toString());
                assertTrue(statuses.size() >= 2);
                assertTrue("workerStatusesContains 9",
                        workerStatusesContains(statuses, "9"));
                assertTrue("workerStatusesContains 16",
                        workerStatusesContains(statuses, "16"));
		
		try{
		  signServerWS.getStatus("1991817");
		  assertTrue(false);
		}catch(InvalidWorkerIdException_Exception e){}
	}
	
	
	public void test02BasicWSProcess() throws Exception{
		
		TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest          timeStampRequest1 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes1 = timeStampRequest1.getEncoded();
        GenericSignRequest signRequest1 = new GenericSignRequest(12, requestBytes1);
        ProcessRequestWS req1 = new ProcessRequestWS(signRequest1);
        
		TimeStampRequest          timeStampRequest2 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes2 = timeStampRequest2.getEncoded();
        GenericSignRequest signRequest2 = new GenericSignRequest(13, requestBytes2);
        ProcessRequestWS req2 = new ProcessRequestWS(signRequest2);

		ArrayList<ProcessRequestWS> reqs = new ArrayList<ProcessRequestWS>();
		reqs.add(req1);
		reqs.add(req2);
        
		try{
		  signServerWS.process("9", WSClientUtil.convertProcessRequestWS(reqs));
		  assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
		
		sSSession.setWorkerProperty(9, "AUTHTYPE", "NOAUTH");
        sSSession.reloadConfiguration(9);               
        
        sSSession.deactivateSigner(9);
        try{
        	signServerWS.process("9", WSClientUtil.convertProcessRequestWS(reqs));
        	assertTrue(false);
        }catch(CryptoTokenOfflineException_Exception e){}
		
        sSSession.activateSigner(9, "foo123");
        
        List<ProcessResponseWS> resps = signServerWS.process("TestTimeStamp", WSClientUtil.convertProcessRequestWS(reqs));
	    assertTrue(resps.size() == 2);
	    assertTrue(resps.get(0).getRequestID()==12);
	    assertTrue(resps.get(1).getRequestID()==13);
		assertNotNull(resps.get(0).getWorkerCertificate());

		GenericSignResponse resp = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(WSClientUtil.convertProcessResponseWS(resps).get(0).getResponseData());
		
		TimeStampResponse timeStampResponse =  new TimeStampResponse(resp.getProcessedData());
		timeStampResponse.validate(timeStampRequest1);
	    
		try{
		  signServerWS.process("1991817", WSClientUtil.convertProcessRequestWS(reqs));
		  assertTrue(false);
		}catch(InvalidWorkerIdException_Exception e){}
		
		
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(validCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		
        req1 = new ProcessRequestWS(req);

		reqs = new ArrayList<ProcessRequestWS>();
		reqs.add(req1);
		
		resps = signServerWS.process("16", WSClientUtil.convertProcessRequestWS(reqs));
		assertTrue(resps.size() == 1);
		ValidateResponse res = (ValidateResponse) RequestAndResponseManager.parseProcessResponse(WSClientUtil.convertProcessResponseWS(resps).get(0).getResponseData());

		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
 		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
	}
	
	public void test03CallFirstNodeWithStatusOKClient() throws Exception{
		
		FaultCallback callback = new FaultCallback();
		
		TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest          timeStampRequest1 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes1 = timeStampRequest1.getEncoded();
        GenericSignRequest signRequest1 = new GenericSignRequest(12, requestBytes1);
        ProcessRequestWS req1 = new ProcessRequestWS(signRequest1);
        ArrayList<ProcessRequestWS> reqs = new ArrayList<ProcessRequestWS>();
		reqs.add(req1);
		
		// Perform a basic test
		
        SignServerWSClientFactory f = new SignServerWSClientFactory();
        String[] hosts = {"localhost"};
        ISignServerWSClient client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts , false, callback);
        List<org.signserver.protocol.ws.ProcessResponseWS> resps = client.process("9", reqs);
        assertTrue(resps != null);
        assertTrue(resps.size() == 1);
        assertTrue(!callback.isCallBackCalled());
        
        // Test with a host that is down
        /*
        String[] hosts2 = {"128.0.0.2"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts2 , false, callback);
        resps = client.process("9", reqs);
        assertTrue(resps == null);
        assertTrue(callback.isCallBackCalled());
        */
        // Test a with one host that is down and one up
        /*
        callback = new FaultCallback();
        String[] hosts3 = {"128.0.0.2","127.0.0.1"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts3 , false, callback);
        resps = client.process("9", reqs);
        assertTrue(resps.size() == 1);
        assertTrue(callback.isCallBackCalled());
        */
        // Test a lot of subsequent calls

        callback = new FaultCallback();
        String[] hosts4 = {"128.0.0.2","127.0.0.1","128.0.0.3"};        
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts4 , false, callback);
        for(int i=0;i<100;i++){
          Thread.sleep(100);
          resps = client.process("9", reqs);
          assertTrue(resps.size() == 1);
          assertTrue(callback.isCallBackCalled());
        }
        
        // Test timeout
        String[] hosts5 = {"128.0.0.1"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts5 , false, callback, 8080, 5);
        resps = client.process("9", reqs);
        assertTrue(resps == null);
        assertTrue(callback.isCallBackCalled());
        
        
	}
	
	
	public void test99TearDownDatabase() throws Exception{
		 TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
		 "9"});
		  
		  TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","TSA", "" + moduleVersion});
		  
		  
		  sSSession.reloadConfiguration(9);
		  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH");

		  sSSession.removeWorkerProperty(16, "AUTHTYPE");
		  sSSession.removeWorkerProperty(16, "VAL1.CLASSPATH");
		  sSSession.removeWorkerProperty(16, "VAL1.TESTPROP");
		  sSSession.removeWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN");

		  
		  sSSession.reloadConfiguration(16);	
	}

    /**
     * @param statuses List of worker statuses
     * @param workerName Name to search for
     * @return true if found in list
     */
    private static boolean workerStatusesContains(final List<WorkerStatusWS> statuses,
            final String workerName) {
        boolean ret = false;
        for (WorkerStatusWS stat : statuses) {
            if (workerName.equals(stat.getWorkerName())) {
                ret = true;
                break;
            }
        }
        return ret;
    }
    

}
