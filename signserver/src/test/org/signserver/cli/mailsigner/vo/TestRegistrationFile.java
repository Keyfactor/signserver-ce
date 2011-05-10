package org.signserver.cli.mailsigner.vo;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;

import junit.framework.TestCase;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.mailsigner.vo.RegistrationFile.KeyStoreType;
import org.signserver.cli.mailsigner.vo.RegistrationFile.RegistrationType;
import org.signserver.common.SignServerUtil;

public class TestRegistrationFile extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testRegistrationFile() throws Exception{
		SignServerUtil.installBCProvider();
		// TODO KeyPair keys = KeyTools.genKeys("512", "RSA");
		KeyPair keys = KeyTools.genKeys("2048", "RSA");
		PKCS10CertificationRequest p10 = new PKCS10CertificationRequest("SHA1WithRSA",CertTools.stringToBcX509Name("CN=test1.test.com"),keys.getPublic(),null,keys.getPrivate());
		
		RegistrationFile rf = new RegistrationFile(RegistrationType.RENEWAL,KeyStoreType.MAINTAINEDSIGNENC,"test@test.com", p10);
		
		//ByteArrayOutputStream baos = new ByteArrayOutputStream();
		FileOutputStream fos = new FileOutputStream("c:\\testreq1.rf");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(rf);
		/*
		ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		ObjectInputStream ois = new ObjectInputStream(bais);
		RegistrationFile rf2 = (RegistrationFile) ois.readObject();
		
		assertNotNull(rf2);
		assertTrue(rf2.getAuthenticationPkcs10().getCertificationRequestInfo().getSubject().toString().equals("CN=test"));
		assertTrue(rf2.getKeyStoreType() == KeyStoreType.MAINTAINEDSIGNENC);
		assertTrue(rf2.getRegistrationType() == RegistrationType.REGISTRATION);
		assertTrue(rf2.getFromEmailAddress().equals("test@test.com"));
		*/
	}

}
