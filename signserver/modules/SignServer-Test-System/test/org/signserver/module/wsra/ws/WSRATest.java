package org.signserver.module.wsra.ws;

import java.io.File;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.xml.namespace.QName;
import javax.xml.ws.WebServiceContext;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.ProductMappingBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.ca.OrganizationRequestDataChecker;
import org.signserver.module.wsra.ca.PKCS10CertRequestData;
import org.signserver.module.wsra.ca.UserCertRequestData;
import org.signserver.module.wsra.ca.connectors.dummy.DummyCAConnector;
import org.signserver.module.wsra.ca.connectors.dummy.DummyCAData;
import org.signserver.module.wsra.common.AuthorizationDeniedException;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;
import org.signserver.module.wsra.common.WSRAConstants.UserStatus;
import org.signserver.module.wsra.common.authtypes.CertSNAuthType;
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.authtypes.SNinDNAuthType;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.SMTPTokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.UserGeneratedTokenProfile;
import org.signserver.module.wsra.core.CommonManagerT;
import org.signserver.module.wsra.core.DataBankManager;
import org.signserver.module.wsra.core.OrganizationManager;
import org.signserver.module.wsra.core.ProductManager;
import org.signserver.module.wsra.core.ProductMapper;
import org.signserver.module.wsra.core.TokenManager;
import org.signserver.module.wsra.core.TransactionManager;
import org.signserver.module.wsra.core.UserManager;
import org.signserver.module.wsra.ws.gen.WSRAService;
import org.signserver.protocol.validationservice.ws.ValidationResponse;
import org.signserver.protocol.ws.Certificate;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;


public class WSRATest extends CommonManagerT {
	
	private static UserManager um = null;
	private static OrganizationManager om = null;
	private static Integer orgId; 
	private static RequestContext raadmin1ctx = new RequestContext();
	private static RequestContext user2ctx = new RequestContext();
	private static RequestContext sactx = new RequestContext();
	private static RequestContext smtpctx = new RequestContext();
	private static RequestContext smtpadmctx = new RequestContext();
	private static RequestContext userctx = new RequestContext();
	
	private static X509Certificate cert1 = null;
	private static X509Certificate cert2 = null;
	private static X509Certificate cert3 = null;
	private static X509Certificate cert4 = null;
	private static X509Certificate cert5 = null;
	private static X509Certificate cert6 = null;
	
	private static String issuerDN = "CN=testCA1";
	
	private Set<Class<?>> availableTokenProfileClasses = new HashSet<Class<?>>();
	private Set<Class<?>> availableAuthTypeClasses = new HashSet<Class<?>>();
	private static ProductManager pm;
	private static TransactionManager trm;
	private static DataBankManager dbm;
	private static KeyPair keys;	
	private static int workerId;
	private static WorkerConfig wc;
	
	private static IWorkerSession.IRemote sSSession = null;
	private static String signserverhome;
	private static org.signserver.module.wsra.ws.gen.WSRA wsraPort;
	
	private static final int WORKERID = 7732;
	private static int moduleVersion;
	
	private static String superadmincertdata = "MIIBMTCB3KADAgECAggZGf8XFLeg1zANBgkqhkiG9w0BAQUFADAVMRMwEQYDVQQD" +
			"DApzdXBlcmFkbWluMB4XDTA4MTExMDEzMTIxM1oXDTA4MTExMTEzMjIxM1owFTET" +
			"MBEGA1UEAwwKc3VwZXJhZG1pbjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCerJvu" +
			"zZrpk0Im6c1iF8AEAXz5Duf8V776s1FC1gb0N9pIeF2L+rWpgmHX0uNx5RivSbhn" +
			"4ttR0VCCEeTzTZutAgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEF" +
			"BQADQQAzxNb1+MxlEPpgVGTMuigDAxsBSoIiA1nZVUymjz694CUaawUq/CCWSOrZ" +
			"pRup82x2ifROIahgpFIZry6TAMCK";

	protected void setUp() throws Exception {
		super.setUp();
		
	    File cAFile = new File(DummyCAData.getStoreFileName(issuerDN));
	    if(cAFile.exists()){
	    	cAFile.delete();
	    }

		availableTokenProfileClasses.add(JKSTokenProfile.class);
		
		availableAuthTypeClasses.add(CertSNAuthType.class);
		availableAuthTypeClasses.add(CertSubjectAuthType.class);
		availableAuthTypeClasses.add(SNinDNAuthType.class);
		SignServerUtil.installBCProvider();		
		if(um == null){
			TokenManager tm = new TokenManager(workerEntityManager,getAvailableTokenProfiles());
			um = new UserManager(workerEntityManager,availableAuthTypeClasses,tm);
			pm = new ProductManager(workerEntityManager);
			trm = new TransactionManager(workerEntityManager,"node1");
			dbm = new DataBankManager(workerEntityManager);
			
			keys = KeyTools.genKeys("512", "RSA");
			cert1 = CertTools.genSelfCert("CN=test1", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			cert2 = CertTools.genSelfCert("CN=test2", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			cert3 = CertTools.genSelfCert("CN=superadmin", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			cert4 = CertTools.genSelfCert("CN=smtpserver", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			cert5 = CertTools.genSelfCert("CN=regularuser", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			cert6 = CertTools.genSelfCert("CN=smtpadmin", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
			
			raadmin1ctx.put(RequestContext.CLIENT_CERTIFICATE, cert1);
			user2ctx.put(RequestContext.CLIENT_CERTIFICATE, cert2);
			sactx.put(RequestContext.CLIENT_CERTIFICATE, cert3);
			smtpctx.put(RequestContext.CLIENT_CERTIFICATE, cert4);
			userctx.put(RequestContext.CLIENT_CERTIFICATE, cert5);
			smtpadmctx.put(RequestContext.CLIENT_CERTIFICATE, cert6);
			
			om = new OrganizationManager(workerEntityManager,um,pm);	
			
			HashSet<String> allowedIssuers = new HashSet<String>();
			allowedIssuers.add(issuerDN);
			allowedIssuers.add("CN=testCA2");
			HashSet<String> allowedCProfiles = new HashSet<String>();
			allowedCProfiles.add("cProfile1");
			
			HashSet<String> allowedTProfiles = new HashSet<String>();
			allowedTProfiles.add(UserGeneratedTokenProfile.PROFILEID);
			allowedTProfiles.add(JKSTokenProfile.PROFILEID);
			allowedTProfiles.add(SMTPTokenProfile.PROFILEID);
			
			OrganizationDataBean org = new OrganizationDataBean(OrganizationType.CUSTOMER,"testOrg","Test Org",
					                                            allowedIssuers,allowedCProfiles, allowedTProfiles);
			tb();om.editOrganization(org);tc();
			OrganizationDataBean orgWithId = om.findOrganization("testOrg");		
			orgId = orgWithId.getId();

			HashSet<String> roles1 = new HashSet<String>();
			roles1.add(Roles.RAADMIN);			
			UserDataBean ud = new UserDataBean("test1","Test 1",roles1,orgId);
			
			ArrayList<UserAliasDataBean> aliases = new ArrayList<UserAliasDataBean>();
			aliases.add(new UserAliasDataBean("type1","somealias1"));
			
			ud.setAliases(aliases);
			
			tb();um.editUser(ud);tc();
			
			ud = um.findUser("test1", orgId);
			CertSubjectAuthType at = new CertSubjectAuthType();
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(raadmin1ctx),ud.getId()));tc();
			
			HashSet<String> roles2 = new HashSet<String>();
			roles2.add(Roles.USER);
			ud = new UserDataBean("test2","Test 2",roles2,orgId);
			
						
			tb();um.editUser(ud);tc();
			
			ud = um.findUser("test2", orgId);
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(user2ctx),ud.getId()));tc();
			
			HashSet<String> roles3 = new HashSet<String>();
			roles3.add(Roles.SUPERADMIN);
			ud = new UserDataBean("superadmin","Super Admin",roles3,orgId);
			
						
			tb();um.editUser(ud);tc();
		
			
			ud = um.findUser("superadmin", orgId);
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(sactx),ud.getId()));tc();
				
			HashSet<String> roles4 = new HashSet<String>();
			roles4.add(Roles.SMTPSERVER);
			ud = new UserDataBean("smtpserver","SMTP Server",roles4,orgId);
			tb();um.editUser(ud);tc();
			
			ud = um.findUser("smtpserver", orgId);
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(smtpctx),ud.getId()));tc();
			
			HashSet<String> roles5 = new HashSet<String>();
			roles5.add(Roles.SMTPADMIN);
			ud = new UserDataBean("smtpadmin","SMTP Admin",roles5,orgId);
			tb();um.editUser(ud);tc();
			
			ud = um.findUser("smtpadmin", orgId);
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(smtpadmctx),ud.getId()));tc();
				
			
			HashSet<String> roles6 = new HashSet<String>();
			roles6.add(Roles.USER);
			ud = new UserDataBean("regularuser","Regular User",roles6,orgId);
			tb();um.editUser(ud);tc();
			
			ud = um.findUser("regularuser", orgId);
			tb();um.editAuthData(new AuthDataBean(at.getAuthType(),at.getMatchValue(userctx),ud.getId()));tc();
				
			
			workerId = 1;
			wc = new WorkerConfig();
			wc.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+1+ "." + WSRAConstants.SETTING_CACONNECTOR_CLASSPATH, DummyCAConnector.class.getName());
			wc.setProperty(WSRAConstants.SETTING_CACONNECTOR_PREFIX+1+ "." + DummyCAConnector.ISSUER_PREFIX+1+DummyCAConnector.DN_SETTING,"CN=testCA1");
			wc.setProperty(WSRAConstants.SETTING_REQUESTDATACHECKER_CLASSPATH,OrganizationRequestDataChecker.class.getName());
			wc.setProperty(WSRAConstants.SETTING_DEBITWSCALLS,"TRUE");			
			
			ProductDataBean productData = new ProductDataBean("Artnr1","Product 1","Some product");
			tb();pm.editProduct(productData);tc();
			
			ProductMappingBean pmb = new ProductMappingBean("MAPPING1",WSRAConstants.DEBITEVENT_GENCERT,null,null,"Artnr1");
			List<ProductMappingBean> pmaps = new ArrayList<ProductMappingBean>();
			pmaps.add(pmb);
			ProductMapper pMapper = new ProductMapper(dbm);
			tb();pMapper.setProductMappings(pmaps);tc();
						
		}
		
		sSSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
		signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
	}
	public void test01AuthorizedRoles() throws Exception{				

		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
		
		ArrayList<String> reqRoles = new ArrayList<String>();
		reqRoles.add("TEST");
		wSRA.listUsers(reqRoles);
		
        wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
		try{
		  wSRA.listUsers(null);
		  assertTrue(false);
		}catch(AuthorizationDeniedException e){}
		
		RequestContext rc = new RequestContext();
        wSRA = genWSRA(workerId, workerEntityManager, wc, rc, null);
		try{
		  wSRA.listUsers(null);
		  assertTrue(false);
		}catch(AuthorizationDeniedException e){}
		
		// Test superadmin
        wSRA = genWSRA(workerId, workerEntityManager, wc, sactx, null);				
		wSRA.listUsers(reqRoles);
		
	}
	
	public void test02LightListUsers() throws Exception{
		
		
		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, sactx, null);
		
		ArrayList<String> reqRoles = new ArrayList<String>();
		reqRoles.add(Roles.SUPERADMIN);
		assertTrue(wSRA.listUsers(reqRoles).size()==1);
		reqRoles = new ArrayList<String>();
		reqRoles.add(Roles.RAADMIN);
		reqRoles.add(Roles.USER);
		assertTrue(wSRA.listUsers(reqRoles).size()==3);
		
		assertTrue(wSRA.listUsers(null).size()==6);
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
		reqRoles = new ArrayList<String>();
		reqRoles.add(Roles.SUPERADMIN);
		reqRoles.add(Roles.RAADMIN);
		reqRoles.add(Roles.USER);
		assertTrue(wSRA.listUsers(reqRoles).size()==3);
	}
	
	public void test03LightEditUsers() throws Exception{
		Set<String> roles = new HashSet<String>();
		roles.add(Roles.SUPERADMIN);
		UserDataBean ud =  new UserDataBean("someuser","Super Admin",roles,orgId);
		
		try{
			WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
			tb();wSRA.editUsers(ud);tc();
			assertTrue(false);
		}catch(AuthorizationDeniedException e){
			tr();
		}
		
		try{
			WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			tb();wSRA.editUsers(ud);tc();
			assertTrue(false);
		}catch(AuthorizationDeniedException e){
			tr();
		}
		
		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, sactx, null);
		tb();wSRA.editUsers(ud);tc();

		roles = new HashSet<String>();
		roles.add(Roles.USER);
		ud =  new UserDataBean("someotheruser","Super Admin",roles,orgId);
		
		try{
			wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			tb();wSRA.editUsers(ud);tc();
			assertTrue(false);
		}catch(AuthorizationDeniedException e){
			tr();
		}
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
		tb();wSRA.editUsers(ud);tc();
		
	}
	
	public void test04LightFindUsers() throws Exception{

		try{
			WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			wSRA.findUserByUsername("test1");
			assertTrue(false);
		}catch(AuthorizationDeniedException e){}
		
		try{
			WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			wSRA.findUsersByAlias(WSRAConstants.MATCHTYPE_EQUALS, "type1", "somealias1");
			assertTrue(false);
		}catch(AuthorizationDeniedException e){}
		
		
		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
		UserDataBean ud = wSRA.findUserByUsername("test1");
		assertNotNull(ud);
		assertTrue(ud.getUserName().equals("test1"));
				
		ud = wSRA.findUserByUsername("nouser");
		assertNull(ud);
		
		List<UserDataBean> res = wSRA.findUsersByAlias(WSRAConstants.MATCHTYPE_EQUALS, "type1", "somealias1");
		assertTrue(res.size() == 1);
		assertTrue(res.get(0).getUserName().equals("test1"));
		
		res = wSRA.findUsersByAlias(WSRAConstants.MATCHTYPE_CONTAINS, "type1", "some");
		assertTrue(res.size() == 1);
		assertTrue(res.get(0).getUserName().equals("test1"));
		
		res = wSRA.findUsersByAlias(WSRAConstants.MATCHTYPE_CONTAINS, "type4", "some");
		assertTrue(res.size() == 0);

	}
	
	public void test05LightManageCertificates() throws Exception{

		PKCS10CertRequestData pkcs10 = new PKCS10CertRequestData("cProfile1","RFC822Name=test@test.se",
				                                                 "SHA1WithRSA","CN=test1",issuerDN,null,keys.getPublic(),
				                                                 keys.getPrivate(),"BC");
		
//		try
                {
			WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			tb();wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();
			assertTrue(false);
		}
//                        catch(AuthorizationDeniedException e){
//			tr();
//		}
		
		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
		pkcs10 = new PKCS10CertRequestData("cProfile1","RFC822Name=test@test.se",
                "SHA1WithRSA","CN=test1,O=blaj",issuerDN,null,keys.getPublic(),
                keys.getPrivate(),"BC");
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
		pkcs10 = new PKCS10CertRequestData("cProfile1","RFC822Name=test@test.se",
                "SHA1WithRSA","CN=test1,O=Test Org",issuerDN,null,keys.getPublic(),
                keys.getPrivate(),"BC");
		tb();Certificate cert = wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();		
		assertNotNull(cert);
		X509Certificate realCert = (X509Certificate) cert.getCertificate();
		assertTrue(realCert.getIssuerDN().toString().equals(issuerDN));
		
		pkcs10 = new PKCS10CertRequestData("cProfile1","RFC822Name=test@test.se",
                "SHA1WithRSA","CN=test1,O=Test Org","CN=noexistissuer",null,keys.getPublic(),
                keys.getPrivate(),"BC");
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test1",  pkcs10, null);tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
		pkcs10 = new PKCS10CertRequestData("cProfile2","RFC822Name=test@test.se",
                "SHA1WithRSA","CN=test1,O=Test Org",issuerDN,null,keys.getPublic(),
                keys.getPrivate(),"BC");
		
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test1", pkcs10, null);tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
		UserDataBean udb = wSRA.findUserByUsername("test1");
		assertNotNull(udb);
		assertTrue(udb.getTokens().size()==1);
		TokenDataBean tdb = udb.getTokens().iterator().next();
		assertTrue(tdb.getCertificates().size() == 1);
		assertTrue(tdb.getSerialNumber().equals(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "test1"));
		
		pkcs10 = new PKCS10CertRequestData("cProfile1","RFC822Name=test@test.se",
                "SHA1WithRSA","CN=test2,O=Test Org",issuerDN, null,keys.getPublic(),
                keys.getPrivate(),"BC");
		
		tb();cert = wSRA.generateCertificateFromPKCS10("test1", pkcs10, "12345");tc();
		assertNotNull(cert);
		realCert = (X509Certificate) cert.getCertificate();
		assertTrue(realCert.getSubjectDN().toString().equals("CN=test2,O=Test Org"));
		
		udb = wSRA.findUserByUsername("test1");
		assertNotNull(udb);
		assertTrue(udb.getTokens().size()==2);
		
//		try{
			tb();wSRA.generateCertificateFromPKCS10("test2", pkcs10, "12345");tc();
			assertTrue(false);
//		}catch(IllegalRequestException e){
//			tr();
//		}
		
		
//		try{
			wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
			wSRA.findUsersByAlias(WSRAConstants.MATCHTYPE_EQUALS, "type1", "somealias1");
			assertTrue(false);
//		}catch(AuthorizationDeniedException e){}
		
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, raadmin1ctx, null);
		UserDataBean ud = wSRA.findUserByUsername("test1");
		assertNotNull(ud);
		assertTrue(ud.getUserName().equals("test1"));
		assertTrue(ud.getTokens().size() ==2);
		Iterator<TokenDataBean> iter = ud.getTokens().iterator();
		while(iter.hasNext()){
			TokenDataBean tdb2 = iter.next();
			if(tdb2.getSerialNumber().equals("12345")){
				assertTrue(tdb2.getProfile().equals(UserGeneratedTokenProfile.PROFILEID));
				assertTrue(tdb2.getCertificates().size() == 1);
				CertificateDataBean cdb = tdb2.getCertificates().iterator().next();
				assertTrue(cdb.getSubjectDN().equals("CN=test2,O=Test Org"));
			}
			if(tdb2.getSerialNumber().equals(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "test1")){
				assertTrue(tdb2.getProfile().equals(UserGeneratedTokenProfile.PROFILEID));
				assertTrue(tdb2.getCertificates().size() == 1);
				CertificateDataBean cdb = tdb2.getCertificates().iterator().next();
				Certificate c = new Certificate();
				c.setCertificateBase64(new String(Base64.encode(cdb.getCertificateData())));
				ValidationResponse vr = wSRA.checkCertStatus(c);
				assertTrue(vr.getStatus().equals(Validation.Status.VALID));
				assertTrue(vr.getRevocationDate() == null);
				assertTrue(vr.getRevocationReason() == -1);
				assertTrue(cdb.getSubjectDN().equals("CN=test1,O=Test Org"));
			}
		}
		
		List<TransactionDataBean> transaction = trm.listTransactions(new Date(System.currentTimeMillis() - 10000), new Date(System.currentTimeMillis() + 10000), 0);
		assertTrue(transaction.size() > 0);
		
		// findToken
		TokenDataBean tdb2 = wSRA.getTokenData("12345", false);		
		if(tdb2.getSerialNumber().equals("12345")){
			assertTrue(tdb2.getProfile().equals(UserGeneratedTokenProfile.PROFILEID));
			assertTrue(tdb2.getSensitiveData() == null);
			assertTrue(tdb2.getCertificates().size() == 1);
			CertificateDataBean cdb = tdb2.getCertificates().iterator().next();
			assertTrue(cdb.getSubjectDN().equals("CN=test2,O=Test Org"));
			wSRA.revokeCertificate(new Certificate(cdb.getCertificate()), WSRAConstants.REVOKATION_REASON_CACOMPROMISE);
			ValidationResponse vr = wSRA.checkCertStatus(new Certificate(cdb.getCertificate()));
			assertTrue(vr.getStatus().equals(Validation.Status.REVOKED));
			assertTrue(vr.getRevocationDate() != null);
			assertTrue(vr.getRevocationReason() == WSRAConstants.REVOKATION_REASON_CACOMPROMISE);			
		}
		
		assertTrue(wSRA.existsToken(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "test1"));
		assertFalse(wSRA.existsToken(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "testsdfasdf"));
		tdb = wSRA.getTokenData(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "test1", false);
		List<CertificateDataBean> certs = new ArrayList<CertificateDataBean>();
		certs.addAll(tdb.getCertificates());
		
		wSRA.revokeToken(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "test1", WSRAConstants.REVOKATION_REASON_CACOMPROMISE);
		for(CertificateDataBean cert2 : tdb.getCertificates()){
			ValidationResponse vr = wSRA.checkCertStatus(new Certificate(cert2.getCertificate()));
			assertTrue(vr.getStatus().equals(Validation.Status.REVOKED));
		}
		
		
		
		// Generate Token
		List<UserCertRequestData> requests = new ArrayList<UserCertRequestData>();		
		requests.add(new UserCertRequestData("alias1","cProfile1",null,"CN=test1,OU=1,O=Test Org",issuerDN,"RSA","512"));
		requests.add(new UserCertRequestData("alias2","cProfile1",null,"CN=test1,OU=2,O=Test Org",issuerDN,"RSA","512"));
		tb();tdb =wSRA.generateSoftToken("test1", "foo123", requests, JKSTokenProfile.PROFILEID, null, false);tc();
		assertNotNull(tdb);
		assertNotNull(tdb.getSerialNumber());
		String tokenSN = tdb.getSerialNumber();
		assertNotNull(tdb.getSensitiveData());
		assertTrue(tdb.getProfile().equals(JKSTokenProfile.PROFILEID));
		assertTrue(tdb.getCertificates().size() == 2);
		for(CertificateDataBean cdb : tdb.getCertificates()){
			assertTrue(cdb.getSubjectDN().equals("CN=test1,OU=1,O=Test Org") || cdb.getSubjectDN().equals("CN=test1,OU=2,O=Test Org"));
		}
		JKSTokenProfile jksProf = new JKSTokenProfile();
		jksProf.init(tdb.getSensitiveData());
		KeyStore ks = jksProf.getKeyStore();
		String ksPwd = jksProf.getKeyStorePwd();
		assertTrue(ksPwd.equals("foo123"));
		assertTrue(ks.containsAlias("alias1"));
		assertTrue(ks.containsAlias("alias2"));
		assertTrue(CertTools.getIssuerDN(((X509Certificate) ks.getCertificate("alias1"))).equals(issuerDN));
		
		try{			
			tb();wSRA.generateSoftToken("test1", "foo123", requests, JKSTokenProfile.PROFILEID, tokenSN, false);tc();
			assertTrue(false);
		}catch(IllegalRequestException e){
			tr();
		}
		
		tb();wSRA.generateSoftToken("test1", "foo123", requests, JKSTokenProfile.PROFILEID, tokenSN, true);tc();
		
		try{
			List<UserCertRequestData> requests2 = new ArrayList<UserCertRequestData>();		
			requests2.add(new UserCertRequestData("alias1","cProfile1",null,"CN=test1,OU=1,O=Test Orgnono",issuerDN,"RSA","512"));
			tb();wSRA.generateSoftToken("test1", "foo123", requests2, JKSTokenProfile.PROFILEID, null, false);tc();
			assertTrue(false);
		}catch(IllegalRequestException e){
			tr();
		}
		try{
			List<UserCertRequestData> requests2 = new ArrayList<UserCertRequestData>();		
			requests2.add(new UserCertRequestData("alias1","cProfilenono",null,"CN=test1,OU=1,O=Test Org",issuerDN,"RSA","512"));
			tb();wSRA.generateSoftToken("test1", "foo123", requests2, JKSTokenProfile.PROFILEID, null, false);tc();
			assertTrue(false);
		}catch(IllegalRequestException e){
			tr();
		}
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, userctx, null);
		try{
			List<UserCertRequestData> requests2 = new ArrayList<UserCertRequestData>();		
			requests2.add(new UserCertRequestData("alias1","cProfile1",null,"CN=test1,OU=1,O=Test Org",issuerDN,"RSA","512"));
			tb();wSRA.generateSoftToken("test1", "foo123", requests2, JKSTokenProfile.PROFILEID, null, false);tc();
			assertTrue(false);
		}catch(AuthorizationDeniedException e){
			tr();
		}
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, smtpctx, null);
		try{
			List<UserCertRequestData> requests2 = new ArrayList<UserCertRequestData>();		
			requests2.add(new UserCertRequestData("alias1","cProfile1",null,"CN=test1,OU=1,O=Test Org",issuerDN,"RSA","512"));
			tb();wSRA.generateSoftToken("test1", "foo123", requests2, JKSTokenProfile.PROFILEID, null, false);tc();
			assertTrue(false);
		}catch(IllegalRequestException e){
			tr();
		}
		
		
		tb();tdb = wSRA.generateSoftToken("test2", "foo123", requests, SMTPTokenProfile.PROFILEID, null, false);tc();
		assertNotNull(tdb);
		assertNotNull(tdb.getSerialNumber());		
		assertNotNull(tdb.getSensitiveData());
		assertTrue(tdb.getProfile().equals(SMTPTokenProfile.PROFILEID));
		assertTrue(tdb.getCertificates().size() == 2);
		for(CertificateDataBean cdb : tdb.getCertificates()){
			assertTrue(cdb.getSubjectDN().equals("CN=test1,OU=1,O=Test Org") || cdb.getSubjectDN().equals("CN=test1,OU=2,O=Test Org"));
		}
		
		jksProf.init(tdb.getSensitiveData());
		ks = jksProf.getKeyStore();
		ksPwd = jksProf.getKeyStorePwd();
		assertTrue(ksPwd.equals("foo123"));
		assertTrue(ks.containsAlias("alias1"));
		assertTrue(ks.containsAlias("alias2"));
		assertTrue(CertTools.getIssuerDN(((X509Certificate) ks.getCertificate("alias1"))).equals(issuerDN));
		
		tdb = wSRA.getTokenData(tdb.getSerialNumber(), true);
		assertNotNull(tdb.getSensitiveData());
		jksProf.init(tdb.getSensitiveData());
		ks = jksProf.getKeyStore();
		ksPwd = jksProf.getKeyStorePwd();
		assertTrue(ksPwd.equals("foo123"));
		assertTrue(ks.containsAlias("alias1"));
		assertTrue(ks.containsAlias("alias2"));
		assertTrue(CertTools.getIssuerDN(((X509Certificate) ks.getCertificate("alias1"))).equals(issuerDN));
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, userctx, null);
		try{
		  wSRA.getTokenData(tdb.getSerialNumber(), false);
		}catch(IllegalRequestException e){}
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, user2ctx, null);
		try{
		  wSRA.getTokenData(tdb.getSerialNumber(), true);
		}catch(IllegalRequestException e){}
		
		tokenSN = tdb.getSerialNumber();
		tdb = wSRA.getTokenData(tdb.getSerialNumber(), false);
		assertNotNull(tdb);
		assertTrue(tdb.getSerialNumber().equals(tokenSN));
		assertTrue(tdb.getCertificates().size() > 0);
		assertTrue(tdb.getProfile().equals(SMTPTokenProfile.PROFILEID));
		assertNull(tdb.getSensitiveData());
		
		// Revoke User		
		try{
		  tb();wSRA.revokeUser("test1", WSRAConstants.REVOKATION_REASON_AACOMPROMISE, UserStatus.DISABLED);tc();		  
		}catch(AuthorizationDeniedException e){
			tr();
		}
		
		wSRA = genWSRA(workerId, workerEntityManager, wc, sactx, null);
		tb();wSRA.revokeUser("test1", WSRAConstants.REVOKATION_REASON_AACOMPROMISE, UserStatus.DISABLED);tc();
		ud = wSRA.findUserByUsername("test1");
		for(TokenDataBean t : ud.getTokens()){
			for(CertificateDataBean c : t.getCertificates()){
				ValidationResponse vr = wSRA.checkCertStatus(new Certificate(c.getCertificate()));
				assertTrue(vr.getStatus() == Status.REVOKED);
			}
		}
	}
	
	public void test06LightGetCallerUserData() throws Exception{
		
		
		WSRA wSRA = genWSRA(workerId, workerEntityManager, wc, sactx, null);

		tb();UserDataBean udb = wSRA.getCallerUserData();tc();
		assertNotNull(udb);
		assertTrue(udb.getUserName(), udb.getUserName().equals("superadmin"));
	}
	
	public void test100SetupDatabase() throws Exception {
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/dummyws.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/wsra.mar", "junittest"});		
	    assertTrue(TestUtils.grepTempOut("Loading module WSRA"));
	    assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

	    sSSession.setWorkerProperty(WORKERID, "TESTCERT", superadmincertdata);
	    sSSession.setWorkerProperty(WORKERID, WSRAConstants.SETTING_TESTDATA, signserverhome + "/src/test/testwsradata.xml");
	    sSSession.reloadConfiguration(WORKERID);
	    
	    File cAFile = new File(DummyCAData.getStoreFileName(issuerDN));
	    if(cAFile.exists()){
	    	cAFile.delete();
	    }
	    	    
	    Thread.sleep(5000);

	}
	
	public void test101WSListUsers() throws Exception {
		ArrayList<String> reqRoles = new ArrayList<String>();
		reqRoles.add(Roles.RAADMIN);
		reqRoles.add(Roles.USER);
		assertTrue(getWSRA().listUsers(reqRoles).size()>1);
	}
	
	public void test102WSEditUsers() throws Exception{
		
		org.signserver.module.wsra.ws.gen.UserDataBean.Roles roles = new org.signserver.module.wsra.ws.gen.UserDataBean.Roles();
		roles.getRole().add(Roles.USER);		
		org.signserver.module.wsra.ws.gen.UserDataBean ud = new org.signserver.module.wsra.ws.gen.UserDataBean();
		ud.setUserName("someuser");
		ud.setDisplayName("Some User");
		ud.setRoles(roles);
		ud.setStatus(UserStatus.READYFORGENERATION.toString());
		
		getWSRA().editUsers(ud);
		
		org.signserver.module.wsra.ws.gen.UserDataBean ud2 =  getWSRA().findUserByUsername("someuser");
		assertNotNull(ud2);
		assertTrue(ud2.getUserName().equals("someuser"));
		
	}
	
	public void test103WSFindUsers() throws Exception{

				
		org.signserver.module.wsra.ws.gen.UserDataBean ud =  getWSRA().findUserByUsername("test1");
		assertNotNull(ud);
		assertTrue(ud.getUserName().equals("test1"));
				
		ud = getWSRA().findUserByUsername("nouser");
		assertNull(ud);
		
		List<org.signserver.module.wsra.ws.gen.UserDataBean> res = getWSRA().findUsersByAlias(WSRAConstants.MATCHTYPE_EQUALS, "type1", "somealias1");
		assertTrue(res.size() == 1);
		assertTrue(res.get(0).getUserName().equals("test1"));

	}
	
	public void test104WSManageCertificates() throws Exception{
		keys = KeyTools.genKeys("512", "RSA");
		PKCS10CertificationRequest p10 = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("CN=test1,O=Test Org"),
                keys.getPublic(),null,
                keys.getPrivate(),"BC");
		
		Random rand = new Random();
		String tokenSerial = ""+ (rand.nextInt() %100000);
		String userName = "test"+ (rand.nextInt() %100000);
		
		
		org.signserver.module.wsra.ws.gen.UserDataBean.Roles roles = new org.signserver.module.wsra.ws.gen.UserDataBean.Roles();
		roles.getRole().add(Roles.USER);		
		org.signserver.module.wsra.ws.gen.UserDataBean ud = new org.signserver.module.wsra.ws.gen.UserDataBean();
		ud.setUserName(userName);
		ud.setDisplayName(userName);
		ud.setRoles(roles);
		ud.setStatus(UserStatus.READYFORGENERATION.toString());
		
		getWSRA().editUsers(ud);
		
		
		
		org.signserver.module.wsra.ws.gen.Pkcs10CertRequestData pkcs10 = new org.signserver.module.wsra.ws.gen.Pkcs10CertRequestData();
		pkcs10.setCertificateProfile("cProfile1");
		pkcs10.setIssuerDN("CN=testCA1");
		pkcs10.setSubjectAltName("RFC822Name=test@test.se");
		pkcs10.setPkcs10Data(p10.getDEREncoded());
		
		org.signserver.module.wsra.ws.gen.Certificate cert = getWSRA().generateCertificateFromPKCS10(userName, pkcs10, null);	
		assertNotNull(cert);
        assertNotNull(cert.getCertificateBase64());

        org.signserver.module.wsra.ws.gen.Certificate c = new org.signserver.module.wsra.ws.gen.Certificate();
		c.setCertificateBase64(cert.getCertificateBase64());
		org.signserver.module.wsra.ws.gen.ValidationResponse vr = getWSRA().checkCertStatus(c);
		assertTrue(vr.getStatus().toString().equals(Validation.Status.VALID.toString()));
		assertTrue(vr.getRevocationDate() == null);
		assertTrue(vr.getRevocationReason() == -1);
        
        ud =  getWSRA().findUserByUsername(userName);
		assertNotNull(ud);
		assertTrue(ud.getUserName().equals(userName));
		assertTrue(ud.getTokens().getToken().size()>0);
		org.signserver.module.wsra.ws.gen.TokenDataBean tdb = ud.getTokens().getToken().iterator().next();
		assertTrue(tdb.getCertificates().getCertificate().size() > 0);
		assertTrue(tdb.getSerialNumber().equals(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + userName));
				
		
		ud = getWSRA().findUserByUsername(userName);
		assertNotNull(ud);
		assertTrue(ud.getUserName().equals(userName));
		assertTrue(""+ud.getTokens().getToken().size(), ud.getTokens().getToken().size() > 0);
		Iterator<org.signserver.module.wsra.ws.gen.TokenDataBean> iter = ud.getTokens().getToken().iterator();
		while(iter.hasNext()){
			org.signserver.module.wsra.ws.gen.TokenDataBean tdb2 = iter.next();			
			if(tdb2.getSerialNumber().equals(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + userName)){
				assertTrue(tdb2.getProfile().equals(UserGeneratedTokenProfile.PROFILEID));
				assertTrue(""+tdb2.getCertificates().getCertificate().size(), tdb2.getCertificates().getCertificate().size() >= 1);
				org.signserver.module.wsra.ws.gen.CertificateDataBean cdb = tdb2.getCertificates().getCertificate().iterator().next();	
				assertNotNull(cdb);
			}
		}
		
		c = getWSRA().generateCertificateFromPKCS10(userName, pkcs10, tokenSerial);		
		getWSRA().revokeCertificate(c, WSRAConstants.REVOKATION_REASON_CACOMPROMISE);
		vr = getWSRA().checkCertStatus(c);
		assertTrue(vr.getStatus().toString().equals(Validation.Status.REVOKED.toString()));
		assertTrue(vr.getRevocationDate() != null);
		assertTrue(vr.getRevocationReason() == WSRAConstants.REVOKATION_REASON_CACOMPROMISE);
		
		// findToken
		org.signserver.module.wsra.ws.gen.TokenDataBean tdb2 = getWSRA().getTokenData(tokenSerial, false);		
		if(tdb2.getSerialNumber().equals(tokenSerial)){
			assertTrue(tdb2.getProfile().equals(UserGeneratedTokenProfile.PROFILEID));
			assertTrue(tdb2.getSensitiveData() == null);
			assertTrue(tdb2.getCertificates().getCertificate().size() > 0);
			org.signserver.module.wsra.ws.gen.CertificateDataBean cdb = tdb2.getCertificates().getCertificate().iterator().next();
			assertNotNull(cdb);			
		}
		
		
		
		assertTrue(getWSRA().existsToken(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + userName));
		assertFalse(getWSRA().existsToken(WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + "testsdfasdf"));
		tdb = getWSRA().getTokenData(tokenSerial, false);
		
				
		getWSRA().revokeToken(tokenSerial, WSRAConstants.REVOKATION_REASON_CACOMPROMISE);
		
		for(org.signserver.module.wsra.ws.gen.CertificateDataBean cert2 : tdb.getCertificates().getCertificate()){
			c = new org.signserver.module.wsra.ws.gen.Certificate();
			c.setCertificateBase64(new String(Base64.encode(cert2.getCertificateData())));
			vr = getWSRA().checkCertStatus(c);			
			assertTrue(vr.getStatus().toString().equals(Validation.Status.REVOKED.toString()));
		}
		
		
		
		// Generate Token
		List<org.signserver.module.wsra.ws.gen.UserCertRequestData> requests = new ArrayList<org.signserver.module.wsra.ws.gen.UserCertRequestData>();
		org.signserver.module.wsra.ws.gen.UserCertRequestData ucrd = new org.signserver.module.wsra.ws.gen.UserCertRequestData();
		ucrd.setCertificateProfile("cProfile1");
		ucrd.setName("alias1");
		ucrd.setSubjectAltName(null);
		ucrd.setSubjectDN("CN=test1,OU=1,O=Test Org");
		ucrd.setIssuerDN(issuerDN);
		ucrd.setKeyAlg("RSA");
		ucrd.setKeySpec("512");
		requests.add(ucrd);
		ucrd = new org.signserver.module.wsra.ws.gen.UserCertRequestData();
		ucrd.setCertificateProfile("cProfile1");
		ucrd.setName("alias2");
		ucrd.setSubjectAltName(null);
		ucrd.setSubjectDN("CN=test1,OU=2,O=Test Org");
		ucrd.setIssuerDN(issuerDN);
		ucrd.setKeyAlg("RSA");
		ucrd.setKeySpec("512");
		requests.add(ucrd);
		tdb =getWSRA().generateSoftToken(userName, "foo123", requests, JKSTokenProfile.PROFILEID, null, false);
		assertNotNull(tdb);
		assertNotNull(tdb.getSerialNumber());
		String tokenSN = tdb.getSerialNumber();
		assertNotNull(tokenSN);
		assertNotNull(tdb.getSensitiveData());
		assertTrue(tdb.getProfile().equals(JKSTokenProfile.PROFILEID));
		assertTrue(tdb.getCertificates().getCertificate().size() == 2);
		for(org.signserver.module.wsra.ws.gen.CertificateDataBean cdb : tdb.getCertificates().getCertificate()){
			assertTrue(cdb.getSubjectDN().equals("CN=test1,OU=1,O=Test Org") || cdb.getSubjectDN().equals("CN=test1,OU=2,O=Test Org"));
		}
		JKSTokenProfile jksProf = new JKSTokenProfile();
		jksProf.init(tdb.getSensitiveData());
		KeyStore ks = jksProf.getKeyStore();
		String ksPwd = jksProf.getKeyStorePwd();
		assertTrue(ksPwd.equals("foo123"));
		assertTrue(ks.containsAlias("alias1"));
		assertTrue(ks.containsAlias("alias2"));
		assertTrue(CertTools.getIssuerDN(((X509Certificate) ks.getCertificate("alias1"))).equals(issuerDN));
		
		getWSRA().revokeUser(userName, WSRAConstants.REVOKATION_REASON_AACOMPROMISE,org.signserver.module.wsra.ws.gen.UserStatus.DISABLED);
		ud = getWSRA().findUserByUsername(userName);
		for(org.signserver.module.wsra.ws.gen.TokenDataBean t : ud.getTokens().getToken()){
			for(org.signserver.module.wsra.ws.gen.CertificateDataBean cert3 : t.getCertificates().getCertificate()){
				org.signserver.module.wsra.ws.gen.Certificate c2 = new org.signserver.module.wsra.ws.gen.Certificate();
				c2.setCertificateBase64(new String(Base64.encode(cert3.getCertificateData())));
				vr = getWSRA().checkCertStatus(c2);
				assertTrue(vr.getStatus().toString().equals(Status.REVOKED.toString()));
			}
		}
	}
	
	public void test105WSGetCallerUserData() throws Exception {
		org.signserver.module.wsra.ws.gen.UserDataBean udb = getWSRA().getCallerUserData();
		assertNotNull(udb);
		assertTrue(udb.getUserName(),udb.getUserName().equals("superadmin"));
	}
	
	   public void test199RemoveDatabase() throws Exception {
			TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
			""+WORKERID});
			
			TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","WSRA", "" + moduleVersion});		
			assertTrue(TestUtils.grepTempOut("Removal of module successful."));
		    sSSession.reloadConfiguration(WORKERID);
	   }
	
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
	}
	
	
	
	
	private WSRA genWSRA(int workerId, EntityManager workerEM,
			WorkerConfig config, RequestContext requestContext,
			ICryptoToken cryptoToken) throws IllegalRequestException, IllegalAccessException, SecurityException, NoSuchFieldException{
		
		
		WebServiceContext wsContext = new WSRATestWSContext(workerId,workerEM,config,
				                                        requestContext,cryptoToken);
		WSRA retval = new WSRA(availableTokenProfileClasses,availableAuthTypeClasses,"node1");
		
	    Field f = WSRA.class.getSuperclass().getDeclaredField("wsContext");
	    f.setAccessible(true);
	    f.set(retval, wsContext);
	    f.setAccessible(false);
		
		return retval;
	}
	   
	   private org.signserver.module.wsra.ws.gen.WSRA getWSRA() throws MalformedURLException {
		   if(wsraPort == null){
		    QName qname = new QName("gen.ws.wsra.module.signserver.org", "WSRAService");
			WSRAService service = new WSRAService(new URL("http://localhost:8080/signserver/ws/wsra/wsra?wsdl"),qname);
			wsraPort =  service.getWSRAPort();
			assertNotNull(wsraPort);
		   }
		   return wsraPort;
	   }
	
}
