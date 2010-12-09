package org.signserver.module.wsra.ca.connectors.dummy;

import java.security.KeyPair;
import java.util.List;
import java.util.Properties;

import junit.framework.TestCase;

import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.ca.PKCS10CertRequestData;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.X509Certificate;
import org.signserver.validationservice.common.Validation.Status;

public class DummyCAConnectorTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
	}
	
	public void test01DummyCAConnector() throws Exception{
		
		
		Properties props = new Properties();
		
		props.setProperty(DummyCAConnector.ISSUER_PREFIX + "1" + DummyCAConnector.DN_SETTING, "CN=DummyCAConnectortest1,OU=test2");
		props.setProperty(DummyCAConnector.ISSUER_PREFIX + "2" + DummyCAConnector.DN_SETTING, "CN=DummyCAConnectortest3,OU=test3");
		props.setProperty(DummyCAConnector.ISSUER_PREFIX + "32" + DummyCAConnector.DN_SETTING, "CN=DummyCAConnectortest 65,OU=test2");
		
		DummyCAConnector caCon = new DummyCAConnector();
		caCon.init(1, 2, props, null);
		
		List<String> result = caCon.getSupportedIssuerDN();
		assertTrue(result.size()==3);
		assertTrue(result.contains("CN=DummyCAConnectortest1,OU=test2"));
		assertTrue(result.contains("CN=DummyCAConnectortest3,OU=test3"));
		assertTrue(result.contains("CN=DummyCAConnectortest 65,OU=test2"));
		
		List<ICertificate> caCerts = caCon.getCACertificateChain("CN=DummyCAConnectortest1,OU=test2");
		assertTrue(caCerts.size()==1);
		assertTrue(caCerts.get(0).getSubject().equals("CN=DummyCAConnectortest1,OU=test2"));
		
		caCerts = caCon.getCACertificateChain("CN=DummyCAConnectortest3,OU=test3");
		assertTrue(caCerts.size()==1);
		assertTrue(caCerts.get(0).getSubject().equals("CN=DummyCAConnectortest3,OU=test3"));
		
		caCerts = caCon.getCACertificateChain("CN=DummyCAConnectortest 65,OU=test2");
		assertTrue(caCerts.size()==1);
		assertTrue(caCerts.get(0).getSubject().equals("CN=DummyCAConnectortest 65,OU=test2"));
		
		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		PKCS10CertRequestData pkcs10Req= new PKCS10CertRequestData("test1","RFC822NAME=test@test.se","SHA1WithRSA","CN=test1","CN=DummyCAConnectortest3,OU=test3",null,keys.getPublic(),keys.getPrivate(),"BC");
		X509Certificate cert = (X509Certificate) caCon.requestCertificate(pkcs10Req);
		assertTrue(cert.getIssuer().equals("CN=DummyCAConnectortest3,OU=test3"));
		
		Validation v = caCon.getCertificateStatus(cert);
		assertTrue(v.getCertificate().getIssuer().equals("CN=DummyCAConnectortest3,OU=test3"));
		
		caCon.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_AFFILIATIONCHANGED);
		v = caCon.getCertificateStatus(cert);
		assertTrue(v.getCertificate().getIssuer().equals("CN=DummyCAConnectortest3,OU=test3"));
		assertTrue(v.getStatus().equals(Status.REVOKED));
		
	}

}
