package org.signserver.mailsigner.module.common;

import java.security.cert.X509Certificate;
import java.util.HashMap;

import junit.framework.TestCase;

import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerStatus;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;

public class TestNotificationParamGen extends TestCase {

	private final static String expireCertData = "MIIBJTCB0KADAgECAghj1RfsJ/Y4ITANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQD"+
			"DARURVNUMB4XDTA4MTAwMzA1NTcwMloXDTA4MTAwNDA2MDcwMlowDzENMAsGA1UE"+
			"AwwEVEVTVDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCDUs+MhwSWJN9+M9Zzsfm2"+
			"eGM07EYx3e64jk/l97QifUnbHaGhAPQrp14FIws8SMser1ZnABm69nrpb5BnrnXL"+
			"AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADQQAgcOrNIWow"+
			"Gep4jSsVHPwgngufFTDdUcrXGtFHB956hozeHUB2zJ4cRl8ikqrFXpStsXn/eQwM"+
			"nD0qrVFD76z7";
	
	private static X509Certificate expireCert = null;
	
	protected void setUp() throws Exception {
		super.setUp();		
		SignServerUtil.installBCProvider();		
		expireCert = (X509Certificate)CertTools.getCertfromByteArray(Base64.decode(expireCertData.getBytes()));	
	}
	
	public void testSubstitutions(){
		WorkerConfig wc = new WorkerConfig();
		wc.setProperty(ProcessableConfig.NAME,"TESTNAME");
		MailSignerConfig msc = new MailSignerConfig(wc);
		NotificationParamGen gen = new NotificationParamGen(new MailSignerStatus(1,MailSignerStatus.STATUS_OFFLINE, msc,expireCert));
		
		assertTrue(gen.getParams() != null);
		HashMap<String,String> params = gen.getParams();
		assertTrue(params.get("cert.CERTSUBJECTDN").equals("CN=TEST"));
		assertTrue(params.get("cert.CERTISSUERDN").equals("CN=TEST"));
		assertTrue(params.get("cert.CERTSERIAL").equals("63d517ec27f63821"));
		assertTrue(params.get("cert.EXPIREDATE").contains("08"));
		assertTrue(params.get("WORKERID").equals("1"));
		assertTrue(params.get("WORKERNAME").equals("TESTNAME"));
		assertTrue(params.get("NL")!= null);
		assertTrue(params.get("HOSTNAME")!= null);
		assertTrue(params.get("DATE")!= null);
		
		String result = NotificationParamGen.interpolate(params, "test ${WORKERID} ${WORKERNAME} asdf");
		assertTrue(result.contains("1"));
		assertTrue(result.contains("TESTNAME"));
		
	}
	

}
