package org.signserver.mailsigner.module.common;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.mail.Message.RecipientType;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ServiceConfig;
import org.signserver.common.SignServerConstants;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.mailsigner.core.SMIMEHelper;
import org.signserver.mailsigner.mailsigners.BaseMailSignerTester;
import org.signserver.mailsigner.module.simplemailsigner.SimpleMailSigner;
import org.signserver.server.cryptotokens.SoftCryptoToken;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

public class TestCertificateExpireTimedService extends BaseMailSignerTester {

	private static final int SERVICEID = 7777;
	private int moduleVersion;
	private String signserverhome;
	private KeyPair keys;
	
	protected void setUp() throws Exception {
		super.setUp();
		
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "MAILSIGNER";
		
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/simplemailsigner.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/simplemailsigner.mar", ""});		
	    assertTrue(TestUtils.grepTempOut("Loading module SIMPLEMAILSIGNER"));
	    assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
	    
		// Set SimpleMailSigner properties
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.REQUIRESMTPAUTH, "TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.FROMADDRESS, "mailsigner@someorg.org");		
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERADDRESS, "mailsigner@someorg.org");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER, "TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER, "TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SignServerConstants.MODULENAME, "SIMPLEMAILSIGNER");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SignServerConstants.MODULEVERSION, ""+moduleVersion);
		
		iMailSignerRMI.reloadConfiguration(0);
		// Set crypto token properties	
		Base64SignerCertReqData reqData = (Base64SignerCertReqData) iMailSignerRMI.genCertificateRequest(getWorkerId(), new PKCS10CertReqInfo("SHA1WithRSA","CN=EXPIRETEST",null));
		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
		assertNotNull(pkcs10);
		keys = KeyTools.genKeys("512", "RSA");
		X509Certificate expiringCert11Days = CertTools.genSelfCert("CN=Expiring11Days", 11, null, keys.getPrivate(), pkcs10.getPublicKey(), "SHA1WithRSA", false);
		
		iMailSignerRMI.uploadSignerCertificate(getWorkerId(), expiringCert11Days);
		
		// Set time service properties
		iMailSignerRMI.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + SERVICEID + GlobalConfiguration.WORKERPROPERTY_CLASSPATH, CertificateExpireTimedService.class.getName());
		iMailSignerRMI.setWorkerProperty(SERVICEID, ServiceConfig.INTERVAL, "1");
		iMailSignerRMI.setWorkerProperty(SERVICEID, ServiceConfig.ACTIVE, "TRUE");
		iMailSignerRMI.setWorkerProperty(SERVICEID, SignServerConstants.MODULENAME, "SIMPLEMAILSIGNER");
		iMailSignerRMI.setWorkerProperty(SERVICEID, SignServerConstants.MODULEVERSION, ""+moduleVersion);
				
		iMailSignerRMI.reloadConfiguration(0);
	}
	
	public void test01Work() throws Exception {
		clearTestInbox();	
		Thread.sleep(3000);		
		MimeMessage mail = readTestInbox();
		assertNotNull(mail);
		assertTrue(mail.getSubject().equals("WARNING: Mail Processor with id : 5533 is about to expire."));		
		assertTrue(((String) mail.getContent()).startsWith("A mail processor at host"));
		assertTrue(mail.getFrom()[0].toString().startsWith("certexpire"));
		assertNotNull(mail.getRecipients(RecipientType.TO)[0].toString());
		
		clearTestInbox();	
		Thread.sleep(2000);		
		mail = readTestInbox();
		assertNull(mail);
		
		GlobalConfiguration gc =iMailSignerRMI.getGlobalConfiguration();
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_EXPIREMAILSENT_POSTFIX).equals("TRUE"));
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_REMINDERMAILSENT_POSTFIX));

		Base64SignerCertReqData reqData = (Base64SignerCertReqData) iMailSignerRMI.genCertificateRequest(getWorkerId(), new PKCS10CertReqInfo("SHA1WithRSA","CN=EXPIRETEST",null));
		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
		assertNotNull(pkcs10);
		X509Certificate expiringCert8Days = CertTools.genSelfCert("CN=Expiring8Days", 8, null, keys.getPrivate(), pkcs10.getPublicKey(), "SHA1WithRSA", false);
		
		iMailSignerRMI.uploadSignerCertificate(getWorkerId(), expiringCert8Days);
		iMailSignerRMI.reloadConfiguration(getWorkerId());
		
		clearTestInbox();	
		Thread.sleep(2000);		
		mail = readTestInbox();
		assertNotNull(mail);
		assertTrue(mail.getSubject(),mail.getSubject().equals("REMINDER: Mail Processor with id : 5533 is about to expire."));		
		assertTrue(((String) mail.getContent()).startsWith("This is a reminder that a mail processor at host"));
		assertTrue(mail.getFrom()[0].toString().startsWith("certexpire"));
		assertNotNull(mail.getRecipients(RecipientType.TO)[0].toString());

		clearTestInbox();	
		Thread.sleep(2000);		
		mail = readTestInbox();
		assertNull(mail);
		
		gc =iMailSignerRMI.getGlobalConfiguration();
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_EXPIREMAILSENT_POSTFIX).equals("TRUE"));
		assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_REMINDERMAILSENT_POSTFIX).equals("TRUE"));

		reqData = (Base64SignerCertReqData) iMailSignerRMI.genCertificateRequest(getWorkerId(), new PKCS10CertReqInfo("SHA1WithRSA","CN=EXPIRETEST",null));
		pkcs10 = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
		assertNotNull(pkcs10);
		X509Certificate expiringCert35Days = CertTools.genSelfCert("CN=Expiring8Days", 35, null, keys.getPrivate(), pkcs10.getPublicKey(), "SHA1WithRSA", false);
		
		iMailSignerRMI.uploadSignerCertificate(getWorkerId(), expiringCert35Days);
		iMailSignerRMI.reloadConfiguration(getWorkerId());
		
		clearTestInbox();	
		Thread.sleep(2000);		
		mail = readTestInbox();
		assertNull(mail);
		
		gc =iMailSignerRMI.getGlobalConfiguration();
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_EXPIREMAILSENT_POSTFIX));
		assertNull(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_REMINDERMAILSENT_POSTFIX));
		
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		// Set SimpleMailSigner properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REQUIRESMTPAUTH);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.FROMADDRESS);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERADDRESS);	
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SMIMEHelper.EXPLAINATION_TEXT);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.FROMNAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERNAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTOADDRESS);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTONAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USEREBUILDFROM);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHANGEREPLYTO);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.OPTIN);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USESUBJECTTAGS);
		
		
		
		// crypto token properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SoftCryptoToken.PROPERTY_KEYDATA);		

		iMailSignerRMI.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, CertificateExpireTimedService.GLOBVAR_CERTEXPIRESERVICE_PREFIX + getWorkerId() + CertificateExpireTimedService.GLOBVAR_EXPIREDATE_POSTFIX);
		
		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
		"" + getWorkerId()});
		
		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
				"" + SERVICEID});
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","SIMPLEMAILSIGNER", "" + moduleVersion});		
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
		
		iMailSignerRMI.reloadConfiguration(0);
		
		TestingSecurityManager.remove();
	}



	@Override
	protected String getCryptoTokenClasspath() {
		return SoftCryptoToken.class.getName();		
	}

	@Override
	protected String getMailSignerClassPath() {
		return SimpleMailSigner.class.getName();
	}

	@Override
	protected String getSMTPAuthUser() {		
		return "dummy1";
	}

	@Override
	protected int getWorkerId() {
		return 5533;
	}

}
