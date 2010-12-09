package org.signserver.common.clusterclassloader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;

public class ClusterClassLoaderUtilsTest extends TestCase {

	private static String signserverhome;
	
	protected void setUp() throws Exception {
		super.setUp();
		signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);
		SignServerUtil.installBCProvider();
	}
	
	public void testClassNameFromResourcePath(){
		assertTrue(ClusterClassLoaderUtils.getClassNameFromResourcePath("org/signserver/test/Test.class").equals("org.signserver.test.Test"));
		assertNull(ClusterClassLoaderUtils.getClassNameFromResourcePath("org/signserver/test/Test.jsp"));
	}
	
	public void testResourcePathFromClassName(){
		assertTrue(ClusterClassLoaderUtils.getResourcePathFromClassName("org.signserver.test.Test").equals("org/signserver/test/Test.class"));		
	}
	
	public void getInternalObjectName(){
		assertTrue(ClusterClassLoaderUtils.getInternalObjectName(org.signserver.common.clusterclassloader.ClusterClassLoaderUtils.class.getName()).equals("org/signserver/common/clusterclassloader/ClusterClassLoaderUtils"));		
	}
	
	public void getInternalObjectWithL(){
		assertTrue(ClusterClassLoaderUtils.getInternalObjectNameWithL(org.signserver.common.clusterclassloader.ClusterClassLoaderUtils.class.getName()).equals("Lorg/signserver/common/clusterclassloader/ClusterClassLoaderUtils;"));		
	}
	
	public void testRemovePath(){
		assertTrue(ClusterClassLoaderUtils.removePath("org/signserver/test/Test.class"), ClusterClassLoaderUtils.removePath("org/signserver/test/Test.class").equals("Test.class"));
	}
	
	public void testFindVersionTag(){
		assertTrue(ClusterClassLoaderUtils.findVersionTag("v1234.org.someorg.Test").equals("v1234."));
		assertTrue(ClusterClassLoaderUtils.findVersionTag("v1234/org/someorg/Test").equals("v1234/"));
		assertNull(ClusterClassLoaderUtils.findVersionTag("org/v1234/someorg/Test"));
		assertNull(ClusterClassLoaderUtils.findVersionTag("org.v1234.someorg.Test"));
		assertNull(ClusterClassLoaderUtils.findVersionTag("v1234d.someorg.Test"));
	}
	
	public void testStripClassPostfixTag(){		
		assertTrue(ClusterClassLoaderUtils.stripClassPostfix("v1234/org/someorg/Test.class").equals("v1234/org/someorg/Test"));
		assertTrue(ClusterClassLoaderUtils.stripClassPostfix("v1234/org/someorg/Test").equals("v1234/org/someorg/Test"));
	}
	
	public void testPackageFromResourceName(){
		assertTrue(ClusterClassLoaderUtils.getPackageFromResourceName("v1234/org/someorg/Test.class").equals("v1234.org.someorg"));
		assertTrue(ClusterClassLoaderUtils.getPackageFromResourceName("v1234/org/someorg/").equals("v1234.org.someorg"));
		assertTrue(ClusterClassLoaderUtils.getPackageFromResourceName("/org/someorg/Test.properties").equals("org.someorg"));
	}
	
	public void testGenerateCMSMessageFromResource() throws Exception{
		
		// Test unsigned
		byte[] testData = "testData".getBytes();
		byte[] signedData = ClusterClassLoaderUtils.generateCMSMessageFromResource(testData, null, null, "BC");
		assertNotNull(signedData);
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(signedData));
		assertFalse(dis.readBoolean());
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while(dis.available() != 0){
			baos.write(dis.read());
		}
		
		assertTrue(new String(baos.toByteArray()).equals("testData"));
		
		byte[] rawData = ClusterClassLoaderUtils.verifyResourceData(signedData, null);
		assertTrue(new String(rawData).equals("testData"));

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(signserverhome +"/src/test/TESTCODESIGN.jks"), "foo123".toCharArray());		
		
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(signserverhome +"/src/test/codesigntruststore.jks"), "foo123".toCharArray());
		
		
		signedData = ClusterClassLoaderUtils.generateCMSMessageFromResource(testData, (X509Certificate) ks.getCertificate("TESTCODESIGN"),(PrivateKey) ks.getKey("TESTCODESIGN", "foo123".toCharArray()), "BC");
		
		rawData = ClusterClassLoaderUtils.verifyResourceData(signedData, trustStore);
		assertTrue(new String(rawData).equals("testData"));
		
		testData = "testData".getBytes();
		signedData = ClusterClassLoaderUtils.generateCMSMessageFromResource(testData, null, null, "BC");
		try{
		  ClusterClassLoaderUtils.verifyResourceData(signedData, ks);
		  assertTrue(false);
		}catch(SignServerException e1){			
		}
		
		// Test to sign with certificate without code signing
		try{
			ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(signserverhome +"/src/test/TESTNOCODESIGN.jks"), "foo123".toCharArray());

			signedData = ClusterClassLoaderUtils.generateCMSMessageFromResource(testData, (X509Certificate) ks.getCertificate("testnocodesign"),(PrivateKey) ks.getKey("testnocodesign", "foo123".toCharArray()), "BC");

			rawData = ClusterClassLoaderUtils.verifyResourceData(signedData, trustStore);
			assertTrue(false);
		}catch(SignatureException e){}
		
		// Test to verify without trust
		try{
			ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(signserverhome +"/src/test/TESTCODESIGN.jks"), "foo123".toCharArray());		
			trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream(signserverhome +"/src/test/codesignnottruststore.jks"), "foo123".toCharArray());
			signedData = ClusterClassLoaderUtils.generateCMSMessageFromResource(testData, (X509Certificate) ks.getCertificate("TESTCODESIGN"),(PrivateKey) ks.getKey("TESTCODESIGN", "foo123".toCharArray()), "BC");

			rawData = ClusterClassLoaderUtils.verifyResourceData(signedData, trustStore);
			assertTrue(false);
		}catch(SignatureException e){}
		
	}

}
