package org.signserver.validationservice.server;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;

public class ValidationServiceWorkerTest extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;

	private static X509Certificate validRootCA1;
	private static X509Certificate validSubCA1;
	private static X509Certificate validCert1;
	private static X509Certificate revokedCert1;
	private static X509Certificate expiredCert1;
	private static X509Certificate noYetValidCert1;
	private static X509Certificate badSigCert1;
	private static X509Certificate expiredRootCA1;
	private static X509Certificate certByExpiredRoot;
	private static X509Certificate notYetValidCA;
	private static X509Certificate certByNotYetValidSub;
	private static X509Certificate revocedRootCA1;
	private static X509Certificate certByRevocedRoot;
	private static X509Certificate validSubCA2;
	private static X509Certificate validSubSubCA2;
	private static X509Certificate validSubSubSubCA2;
	private static X509Certificate validSubSubSubSubCA2;
	private static X509Certificate certSignedByLongChain;
	private static X509Certificate identificationCert1;
	private static X509Certificate esigCert1;
	private static X509Certificate badKeyUsageCert1;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
                gCSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
		sSSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);

	}
	
	public void test00SetupDatabase() throws Exception{

		
		  KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		  validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
		  
		  KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		  validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
		  
		  KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
		  validCert1 = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  revokedCert1 = ValidationTestUtils.genCert("CN=revokedCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  expiredCert1  = ValidationTestUtils.genCert("CN=expiredCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() - 1000000), false);
          noYetValidCert1 = ValidationTestUtils.genCert("CN=noYetValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(System.currentTimeMillis() + 1000000), new Date(System.currentTimeMillis() + 2000000), false);
		  badSigCert1 = ValidationTestUtils.genCert("CN=badSigCert1", "CN=ValidSubCA1", validRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
          
		  identificationCert1 = ValidationTestUtils.genCert("CN=identificationCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment);
		  esigCert1 = ValidationTestUtils.genCert("CN=esigCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.nonRepudiation);
		  badKeyUsageCert1 = ValidationTestUtils.genCert("CN=badKeyUsageCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false,X509KeyUsage.dataEncipherment + X509KeyUsage.cRLSign);
		  
		  KeyPair expiredRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		  expiredRootCA1 = ValidationTestUtils.genCert("CN=expiredRootCA1", "CN=expiredRootCA1", expiredRootCA1Keys.getPrivate(), expiredRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() - 1000000), true);
		  
		  certByExpiredRoot = ValidationTestUtils.genCert("CN=certByExpiredRoot", "CN=expiredRootCA1", expiredRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  
		  KeyPair notYetValidSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		  notYetValidCA = ValidationTestUtils.genCert("CN=notYetValidCA", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), notYetValidSubCA1Keys.getPublic(), new Date(System.currentTimeMillis() + 1000000), new Date(System.currentTimeMillis() + 2000000), true);
		  
		  certByNotYetValidSub = ValidationTestUtils.genCert("CN=certByNotYetValidSub", "CN=notYetValidCA", notYetValidSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  
		  KeyPair revocedRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		  revocedRootCA1 = ValidationTestUtils.genCert("CN=revocedRootCA1", "CN=revocedRootCA1", revocedRootCA1Keys.getPrivate(), revocedRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
		  certByRevocedRoot = ValidationTestUtils.genCert("CN=certByRevocedRoot", "CN=revocedRootCA1", revocedRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  
		  
		  KeyPair validSubCA2Keys = KeyTools.genKeys("1024", "RSA");
		  validSubCA2 = ValidationTestUtils.genCert("CN=ValidSubCA2", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);		  
		  KeyPair validSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
		  validSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubCA2", "CN=ValidSubCA2", validSubCA2Keys.getPrivate(), validSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
		  KeyPair validSubSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
		  validSubSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubSubCA2", "CN=ValidSubSubCA2", validSubSubCA2Keys.getPrivate(), validSubSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);		  
		  KeyPair validSubSubSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
		  validSubSubSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubSubSubCA2", "CN=ValidSubSubSubCA2", validSubSubSubCA2Keys.getPrivate(), validSubSubSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);		  

		  certSignedByLongChain = ValidationTestUtils.genCert("CN=certSignedByLongChain", "CN=ValidSubSubSubSubCA2", validSubSubSubSubCA2Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
		  
		  ArrayList<X509Certificate> validChain1 = new ArrayList<X509Certificate>();
		  // Add in the wrong order
		  validChain1.add(validRootCA1);
		  validChain1.add(validSubCA1);
		  
		  ArrayList<X509Certificate> expiredRootChain = new ArrayList<X509Certificate>();
		  expiredRootChain.add(expiredRootCA1);

		  ArrayList<X509Certificate> notYetValidSubChain = new ArrayList<X509Certificate>();		 
		  notYetValidSubChain.add(notYetValidCA);
		  notYetValidSubChain.add(validRootCA1);

		  ArrayList<X509Certificate> revocedRootCA1Chain = new ArrayList<X509Certificate>();
		  revocedRootCA1Chain.add(revocedRootCA1);
		  
		  ArrayList<X509Certificate> longChain = new ArrayList<X509Certificate>();
		  longChain.add(validSubCA2);
		  longChain.add(validSubSubSubCA2);
		  longChain.add(validRootCA1);
		  longChain.add(validSubSubSubSubCA2);
		  longChain.add(validSubSubCA2);
		  
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
		  
		  
		  sSSession.setWorkerProperty(15, "AUTHTYPE", "NOAUTH");
		  sSSession.setWorkerProperty(15, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
		  sSSession.setWorkerProperty(15, "VAL1.TESTPROP", "TEST");
		  sSSession.setWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));
		  sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(expiredRootChain));
		  sSSession.setWorkerProperty(15, "VAL1.ISSUER4.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(notYetValidSubChain));
		  sSSession.setWorkerProperty(15, "VAL2.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
		  sSSession.setWorkerProperty(15, "VAL2.TESTPROP", "TEST");
		  sSSession.setWorkerProperty(15, "VAL2.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(revocedRootCA1Chain));
		  sSSession.setWorkerProperty(15, "VAL2.ISSUER250.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(longChain));
		  
		  sSSession.reloadConfiguration(15);	
		  
		  
		  
		  
	}
	
	public void test01BasicValidation() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(validCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
 		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
	}
	
	public void test02RevokedCertificate() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(revokedCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.REVOKED));
		assertTrue(val.getStatusMessage() != null);
		assertTrue(val.getRevokationReason() == 3);
		assertTrue(val.getRevokedDate() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
	}
	
	public void test03ExpiredCertificate() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(expiredCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.EXPIRED));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));		
	}

	public void test04NotYetValidCertificate() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(noYetValidCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.NOTYETVALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));		
	}
	
	public void test05BadSignatureCertificate() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(badSigCert1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.DONTVERIFY));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));		
	}
	
	public void test06signedByExpiredRootCertificate() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certByExpiredRoot), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.CAEXPIRED));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=expiredRootCA1"));
				
	}

	public void test07signedByNotYetValidSubCA() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certByNotYetValidSub), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.CANOTYETVALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=notYetValidCA"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
				
	}
	
	public void test08signedByNotYetValidSubCA() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certByNotYetValidSub), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.CANOTYETVALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=notYetValidCA"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
				
	}
	
	public void test09signedByRevocedRootCA() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certByRevocedRoot), null);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.CAREVOKED));
		assertTrue(val.getStatusMessage() != null);
		assertTrue(val.getRevokedDate() != null);
		assertTrue(val.getRevokationReason() == 3);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=revocedRootCA1"));		
				
	}
	
	public void test10LongChainValidation() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certSignedByLongChain), null);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubSubSubSubCA2"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidSubSubSubCA2"));
		assertTrue(cAChain.get(2).getSubject().equals("CN=ValidSubSubCA2"));
		assertTrue(cAChain.get(3).getSubject().equals("CN=ValidSubCA2"));
		assertTrue(cAChain.get(4).getSubject().equals("CN=ValidRootCA1"));
		
	}
	
	public void test11CertPurpose() throws Exception{
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(identificationCert1), ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(identificationCert1), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.BADCERTPURPOSE));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(esigCert1), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(res.getValidCertificatePurposes() != null);
		assertTrue(res.getValidCertificatePurposes().equals(ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(esigCert1), ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.BADCERTPURPOSE));
		assertTrue(res.getValidCertificatePurposes() == null);
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(badKeyUsageCert1), ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.BADCERTPURPOSE));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(badKeyUsageCert1), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.BADCERTPURPOSE));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(validCert1), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.BADCERTPURPOSE));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(identificationCert1), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE + "," + ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(res.getValidCertificatePurposes().equals(ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION));
		
	}
	
	
	
	public void test12CertificateCache() throws Exception{
		sSSession.setWorkerProperty(15, "VAL1.WAITTIME", "1000");
		sSSession.setWorkerProperty(15, "CACHEDISSUERS", "CN=ValidSubCA1;CN=revocedRootCA1");
		sSSession.reloadConfiguration(15);
		
		
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(validCert1), null);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		Validation val2 = res.getValidation();
		assertTrue(val2 != null);
		assertTrue(val2.getStatus().equals(Validation.Status.VALID));
		assertTrue(val2.getStatusMessage() != null);
		assertTrue(val.getValidationDate().equals(val2.getValidationDate()));
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubCA1"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidRootCA1"));
		
		req = new ValidateRequest(ICertificateManager.genICertificate(certSignedByLongChain), null);
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubSubSubSubCA2"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidSubSubSubCA2"));
		assertTrue(cAChain.get(2).getSubject().equals("CN=ValidSubSubCA2"));
		assertTrue(cAChain.get(3).getSubject().equals("CN=ValidSubCA2"));
		assertTrue(cAChain.get(4).getSubject().equals("CN=ValidRootCA1"));
		
		res = (ValidateResponse) sSSession.process(15, req, new RequestContext());
		
		val2 = res.getValidation();
		assertTrue(val2 != null);
		assertTrue(val2.getStatus().equals(Validation.Status.VALID));
		assertTrue(val2.getStatusMessage() != null);
		assertTrue(!val.getValidationDate().equals(val2.getValidationDate()));
		cAChain = val2.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=ValidSubSubSubSubCA2"));
		assertTrue(cAChain.get(1).getSubject().equals("CN=ValidSubSubSubCA2"));
		assertTrue(cAChain.get(2).getSubject().equals("CN=ValidSubSubCA2"));
		assertTrue(cAChain.get(3).getSubject().equals("CN=ValidSubCA2"));
		assertTrue(cAChain.get(4).getSubject().equals("CN=ValidRootCA1"));
		
	}

	public void test99RemoveDatabase() throws Exception{
				  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH");

		  sSSession.removeWorkerProperty(15, "AUTHTYPE");
		  sSSession.removeWorkerProperty(15, "VAL1.CLASSPATH");
		  sSSession.removeWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN");
		  sSSession.removeWorkerProperty(15, "VAL1.ISSUER2.CERTCHAIN");
		  sSSession.removeWorkerProperty(15, "VAL1.ISSUER4.CERTCHAIN");
		  sSSession.removeWorkerProperty(15, "VAL2.CLASSPATH");
		  sSSession.removeWorkerProperty(15, "VAL2.TESTPROP");
		  sSSession.removeWorkerProperty(15, "VAL2.ISSUER1.CERTCHAIN");
		  sSSession.removeWorkerProperty(15, "VAL2.ISSUER250.CERTCHAIN");		
		  sSSession.removeWorkerProperty(15, "VAL1.WAITTIME");
		  sSSession.removeWorkerProperty(15, "CACHEDISSUERS");

		  
		  sSSession.reloadConfiguration(15);		   
	}
}
