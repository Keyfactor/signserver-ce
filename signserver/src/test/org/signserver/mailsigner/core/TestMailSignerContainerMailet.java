package org.signserver.mailsigner.core;

import java.rmi.RemoteException;
import java.util.Properties;

import junit.framework.TestCase;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerStatus;
import org.signserver.common.SignServerUtil;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.PropertyFileStore;
import org.signserver.server.cryptotokens.ICryptoToken;

public class TestMailSignerContainerMailet extends TestCase {

	private static MailSignerContainerMailet mc = null;

	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		PropertyFileStore.getInstance("tmp/testproperties.properties");
		mc = new MailSignerContainerMailet();
	}

	public void test00SetupDatabase() throws Exception{
		   
		  mc.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CLASSPATH", "org.signserver.mailsigner.mailsigners.DummyMailSigner");
		  mc.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CRYPTOTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
				  		  
          mc.setWorkerProperty(3, "NAME", "testWorker");
		  mc.reloadConfiguration(3);	
	} 
	
	public void testActivateSigner() throws RemoteException, CryptoTokenOfflineException, InvalidWorkerIdException {
		try{
		  mc.activateCryptoToken(3, "9876");
		  fail();
		}catch(CryptoTokenAuthenticationFailureException e){}
	}

	public void testDeactivateSigner() throws RemoteException, CryptoTokenOfflineException, InvalidWorkerIdException {
		assertTrue(mc.deactivateCryptoToken(3));
	}

	public void testDestroyKey() throws RemoteException, InvalidWorkerIdException {
		assertTrue(mc.destroyKey(3, ICryptoToken.PURPOSE_SIGN));
	}

	public void testGenCertificateRequest() throws RemoteException, CryptoTokenOfflineException, InvalidWorkerIdException {
		assertNull(mc.genCertificateRequest(3, null));
	}

	public void testGetSignerId() throws RemoteException {
		   int id = mc.getWorkerId("testWorker");
		   assertTrue(""+ id , id == 3);
	}

	public void testGetStatus() throws RemoteException, InvalidWorkerIdException {
		   assertTrue(((MailSignerStatus) mc.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_ACTIVE ||
				   ((MailSignerStatus)mc.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_OFFLINE);
	}

	public void testReloadConfiguration() throws RemoteException {
		mc.reloadConfiguration(0);
	}



	public void testGetCurrentSignerConfig() throws RemoteException, InvalidWorkerIdException {
		mc.removeWorkerProperty(3, "TESTKEY");
		WorkerStatus ws = mc.getStatus(3);
		assertNull(ws.getActiveSignerConfig().getProperties().getProperty("TESTKEY"));
		
		mc.setWorkerProperty(3, "TESTKEY", "TESTVAL");
		
		WorkerConfig wc = mc.getCurrentWorkerConfig(3);
		MailSignerConfig msc = new MailSignerConfig(wc);
		assertTrue(msc.getWorkerConfig().getProperties().getProperty("TESTKEY").equals("TESTVAL"));
		
		ws = mc.getStatus(3);
		assertNull(ws.getActiveSignerConfig().getProperties().getProperty("TESTKEY"));
		
		mc.reloadConfiguration(3);
		
		ws = mc.getStatus(3);
		assertNotNull(ws.getActiveSignerConfig().getProperties().getProperty("TESTKEY"));
		mc.removeWorkerProperty(3, "TESTKEY");
	}
	


	public void testSetWorkerProperty() {
		mc.setWorkerProperty(3,"test", "Hello World");
		
		Properties props = mc.getCurrentWorkerConfig(3).getProperties();
		assertTrue(props.getProperty("TEST").equals("Hello World"));
	}
	
	public void testRemoveWorkerProperty() {
		mc.removeWorkerProperty(3,"test");
		
		Properties props = mc.getCurrentWorkerConfig(3).getProperties();
		assertNull(props.getProperty("test"));
	}


	
	public void test99TearDownDatabase() throws Exception{
		  mc.removeWorkerProperty(3, "NAME");
		  mc.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CLASSPATH");
		  mc.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.SIGNERTOKEN.CLASSPATH");
		  mc.reloadConfiguration(3);
	}
	/*
	   private static byte[] testcert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
	            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky"
	            + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
	            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB"
	            + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
	            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ"
	            + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
	            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw"
	            + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
	            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj"
	            + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
	            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0"
	            + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
	            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4"
	            + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
	            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ"
	            + "QUOBOvc=").getBytes());
	   
		private boolean arrayEquals(byte[] signreq2, byte[] signres2) {
			boolean retval = true;
			
			if(signreq2.length != signres2.length){
				return false;
			}
			
			for(int i=0;i<signreq2.length;i++){
				if(signreq2[i] != signres2[i]){
					return false;
				}
			}
			return retval;
		}*/
}
