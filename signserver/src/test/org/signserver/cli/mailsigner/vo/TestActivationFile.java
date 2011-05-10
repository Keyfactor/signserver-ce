package org.signserver.cli.mailsigner.vo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.mailsigner.vo.RegistrationFile.KeyStoreType;
import org.signserver.cli.mailsigner.vo.RegistrationFile.RegistrationType;
import org.signserver.common.SignServerUtil;

import junit.framework.TestCase;

public class TestActivationFile extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testActivationFile() throws Exception{
		SignServerUtil.installBCProvider();
		KeyPair keys = KeyTools.genKeys("512", "RSA");
		PKCS10CertificationRequest p10 = new PKCS10CertificationRequest("SHA1WithRSA",CertTools.stringToBcX509Name("CN=test"),keys.getPublic(),null,keys.getPrivate());
		
		RegistrationFile rf = new RegistrationFile(RegistrationType.REGISTRATION,KeyStoreType.MAINTAINEDSIGNENC,"test@test.com",p10);
		
		X509Certificate cert1 = CertTools.genSelfCert("CN=test1", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
		X509Certificate cert2 = CertTools.genSelfCert("CN=test2", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
		ArrayList<Certificate> certChain = new ArrayList<Certificate>();
		certChain.add(cert1);
		certChain.add(cert2);
		
		ActivationFile af = new ActivationFile(rf,certChain);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(af);
		
		ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		ObjectInputStream ois = new ObjectInputStream(bais);
		ActivationFile af2 = (ActivationFile) ois.readObject();
		
		assertNotNull(af2);
		RegistrationFile rf2 = af2.getOrginalRegistrationFile();
		assertTrue(rf2.getAuthenticationPkcs10().getCertificationRequestInfo().getSubject().toString().equals("CN=test"));
		assertTrue(rf2.getKeyStoreType() == KeyStoreType.MAINTAINEDSIGNENC);
		assertTrue(rf2.getRegistrationType() == RegistrationType.REGISTRATION);
		
		assertTrue(af2.getAuthCertificateChain().size()==2);
		assertTrue(((X509Certificate) af2.getAuthCertificateChain().get(0)).getSubjectDN().toString().equals("CN=test1"));
		assertTrue(((X509Certificate) af2.getAuthCertificateChain().get(1)).getSubjectDN().toString().equals("CN=test2"));

	}
}
