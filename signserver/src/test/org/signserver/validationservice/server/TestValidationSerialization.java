package org.signserver.validationservice.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import junit.framework.TestCase;

import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.SignServerUtil;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

public class TestValidationSerialization extends TestCase {



	private static X509Certificate validRootCA1;
	private static X509Certificate validSubCA1;
	private static X509Certificate validCert1;

	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();

	}
	
	public void test01ValidationSerialization() throws Exception{
		
		  KeyPair keys = KeyTools.genKeys("1024", "RSA");
		  validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", keys.getPrivate(), keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
		  
		  validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", keys.getPrivate(), keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		  validCert1 = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", keys.getPrivate(), keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
  
		  ArrayList<ICertificate> caChain = new ArrayList<ICertificate>();		  
		  caChain.add(ICertificateManager.genICertificate(validSubCA1));
		  caChain.add(ICertificateManager.genICertificate(validRootCA1));
		  Validation val = new Validation(ICertificateManager.genICertificate(validCert1),caChain,Validation.Status.BADCERTPURPOSE,null);
		  
		  ByteArrayOutputStream baos = new ByteArrayOutputStream();
		  DataOutputStream out = new DataOutputStream(baos);
		  val.serialize(out);
		  
		  byte[] data = baos.toByteArray();
		  
		  DataInputStream ois = new DataInputStream(new ByteArrayInputStream(data));
		  
		  Validation val2 = new Validation();
		  val2.parse(ois);
		  assertTrue(val2.getStatus() == Status.BADCERTPURPOSE);
		  assertTrue(Math.abs(System.currentTimeMillis() -  val2.getValidationDate().getTime()) < 1000); 
		  assertTrue(val2.getStatusMessage() == null);
		  assertTrue(val2.getRevokationReason() == -1);
		  assertTrue(val2.getRevokedDate() == null);
		  assertTrue(val2.getCertificate().getSubject().equals("CN=ValidCert1"));
		  assertTrue(val2.getCAChain().get(0).getSubject().equals("CN=ValidSubCA1"));
		  assertTrue(val2.getCAChain().get(1).getSubject().equals("CN=ValidRootCA1"));
		  
          val = new Validation(ICertificateManager.genICertificate(validCert1),caChain,Validation.Status.VALID,"test",new Date(1000),10);
		  
		  baos = new ByteArrayOutputStream();
		  out = new DataOutputStream(baos);
		  val.serialize(out);
		  
		  data = baos.toByteArray();
		  
		  ois = new DataInputStream(new ByteArrayInputStream(data));
		  
		  val2 = new Validation();
		  val2.parse(ois);
		  assertTrue(val2.getStatus() == Status.VALID);
		  assertTrue(Math.abs(System.currentTimeMillis() -  val2.getValidationDate().getTime()) < 1000); 
		  assertTrue(val2.getStatusMessage().equals("test"));
		  assertTrue(val2.getRevokationReason() == 10);
		  assertTrue(val2.getRevokedDate().getTime() == 1000);
		  assertTrue(val2.getCertificate().getSubject().equals("CN=ValidCert1"));
		  assertTrue(val2.getCAChain().get(0).getSubject().equals("CN=ValidSubCA1"));
		  assertTrue(val2.getCAChain().get(1).getSubject().equals("CN=ValidRootCA1"));
		  
	}
	
	
}
